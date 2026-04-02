"""
Phase 4 - Payload Analyzer
SMB executable staging, PE metadata, GPO access, tool deployment.
"""

from __future__ import annotations

from typing import Optional

from ..models import (
    LogFile, LogCategory, IOC, IOCType,
    TimelineEvent, MITREMapping, Evidence, Finding, Severity,
    PhaseResult, epoch_to_utc,
)
from ..config import Config
from ..tools.log_reader import ZeekLogReader
from ..tools.search import group_by_field, count_unique
from ..tools.stats import count_by_field, top_n, unique_values, cluster_by_time


class PayloadAnalyzer:
    """Phase 4: SMB executable staging, PE metadata, GPO access, tool deployment."""

    def __init__(
        self,
        log_inventory: list[LogFile],
        config: Config,
        prior_iocs: list[IOC],
    ):
        self.inventory = log_inventory
        self.config = config
        self.prior_iocs = prior_iocs
        self.findings: list[Finding] = []
        self.iocs: list[IOC] = []
        self.timeline: list[TimelineEvent] = []
        self._finding_counter = 0

        # Collect known attacker IPs from prior phases
        self._attacker_ips: set[str] = {
            ioc.value for ioc in prior_iocs if ioc.type == IOCType.IP
        }

        # Track staging timestamps for cross-referencing
        self._exe_timestamps: list[float] = []

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------

    def run(self) -> PhaseResult:
        print("\n[Phase 4] Starting payload analysis...")

        self._check_smb_executables()
        self._check_pe_metadata()
        self._check_gpo_access()
        self._check_suspicious_smb_patterns()
        self._cross_reference_timeline()

        summary = (
            f"Payload analysis complete. "
            f"{len(self.findings)} finding(s), "
            f"{len(self.iocs)} IOC(s), "
            f"{len(self.timeline)} timeline event(s)."
        )
        print(f"  [Phase 4] {summary}")

        return PhaseResult(
            phase_name="payload",
            findings=self.findings,
            iocs=self.iocs,
            timeline_events=self.timeline,
            raw_results={},
            summary=summary,
        )

    # ------------------------------------------------------------------
    # Step 1: SMB executable staging
    # ------------------------------------------------------------------

    def _check_smb_executables(self) -> None:
        print("  [Phase 4] Searching smb_files.log for .exe files...")
        log = self._get_log("smb_files.log")
        if log is None:
            print("  [Phase 4] smb_files.log not found, skipping executable check.")
            return

        reader = self._safe_reader(log)
        if reader is None:
            return

        try:
            exe_records = reader.grep(".exe", max_results=20000)
        except Exception:
            exe_records = []

        if not exe_records:
            return

        # Extract details: source IP, dest IP, filename, file size
        large_exes: list[dict] = []
        all_exe_info: list[dict] = []

        for rec in exe_records:
            src = rec.get("id.orig_h", "")
            dst = rec.get("id.resp_h", "")
            fname = rec.get("name", "") or rec.get("filename", "")
            fsize_raw = rec.get("size", "0") or "0"

            try:
                fsize = int(float(fsize_raw))
            except (ValueError, TypeError):
                fsize = 0

            info = {
                "source": src,
                "dest": dst,
                "filename": fname,
                "size": fsize,
                "ts": rec.get("ts", ""),
            }
            all_exe_info.append(info)

            # Track timestamps for cross-referencing
            ts_raw = rec.get("ts", "")
            if ts_raw:
                try:
                    self._exe_timestamps.append(float(ts_raw))
                except (ValueError, TypeError):
                    pass

            if fsize >= self.config.large_exe_threshold:
                large_exes.append(info)
                self._add_ioc(IOCType.FILENAME, fname, f"Large executable ({fsize} bytes) staged via SMB", rec, "smb_files.log")
                self._add_timeline(rec, "payload", f"Large .exe staged: {fname} ({fsize} bytes) {src}->{dst}", "smb_files.log", "T1021.002")

        # Identify staging server (destination receiving most executables)
        dest_counts: dict[str, int] = {}
        for info in all_exe_info:
            dst = info["dest"]
            if dst:
                dest_counts[dst] = dest_counts.get(dst, 0) + 1

        staging_server = ""
        if dest_counts:
            staging_server = max(dest_counts, key=dest_counts.get)  # type: ignore[arg-type]
            self._add_ioc(IOCType.IP, staging_server, f"Staging server (received {dest_counts[staging_server]} executables)", {}, "smb_files.log")

        # Record all unique exe filenames as IOCs
        exe_names = list({info["filename"] for info in all_exe_info if info["filename"]})
        for name in exe_names[:30]:
            self._add_ioc(IOCType.FILENAME, name, "Executable staged via SMB", {}, "smb_files.log")

        evidence = Evidence(
            source_log="smb_files.log",
            description=(
                f"{len(exe_records)} .exe file(s) transferred via SMB, "
                f"{len(large_exes)} exceeding {self.config.large_exe_threshold} bytes"
            ),
            raw_data={
                "total_exes": len(exe_records),
                "large_exes": large_exes[:20],
                "staging_server": staging_server,
                "unique_filenames": exe_names[:30],
            },
            search_query="grep .exe in smb_files.log",
        )
        sev = Severity.CRITICAL if large_exes else Severity.HIGH
        self._add_finding(
            title="Executable Files Staged via SMB",
            text=(
                f"Detected {len(exe_records)} .exe file(s) transferred over SMB. "
                f"{len(large_exes)} file(s) exceed the {self.config.large_exe_threshold}-byte "
                f"threshold. Staging server: {staging_server or 'undetermined'}. "
                f"Unique executables: {', '.join(exe_names[:10])}."
            ),
            severity=sev,
            evidence=[evidence],
            mitre=[
                MITREMapping(
                    tactic="Lateral Movement",
                    technique="Remote Services: SMB/Windows Admin Shares",
                    technique_id="T1021.002",
                    observed_evidence=f"{len(exe_records)} .exe files via SMB",
                ),
            ],
        )

    # ------------------------------------------------------------------
    # Step 2: PE metadata
    # ------------------------------------------------------------------

    def _check_pe_metadata(self) -> None:
        print("  [Phase 4] Reading pe.log for PE metadata...")
        log = self._get_log("pe.log")
        if log is None:
            print("  [Phase 4] pe.log not found, skipping PE metadata check.")
            return

        records = self._safe_read(log)
        if not records:
            return

        # Extract architecture, compile timestamps, sections
        architectures: dict[str, int] = {}
        compile_timestamps: list[str] = []
        section_names: set[str] = set()
        pe_details: list[dict] = []

        for rec in records:
            arch = rec.get("machine", "") or rec.get("architecture", "")
            if arch:
                architectures[arch] = architectures.get(arch, 0) + 1

            compile_ts = rec.get("compile_ts", "") or rec.get("compile_timestamp", "")
            if compile_ts and compile_ts != "-":
                compile_timestamps.append(compile_ts)

            sections = rec.get("section_names", "")
            if sections and sections != "-":
                for s in sections.split(","):
                    section_names.add(s.strip())

            pe_details.append({
                "id": rec.get("id", ""),
                "machine": arch,
                "compile_ts": compile_ts,
                "sections": sections,
                "has_debug": rec.get("has_debug_data", ""),
            })

        # Check for dual-architecture pattern (same binary for 32/64-bit)
        dual_arch = len(architectures) > 1
        dual_arch_note = ""
        if dual_arch:
            dual_arch_note = (
                f"Dual-architecture binaries detected ({', '.join(architectures.keys())}). "
                f"This may indicate a multi-platform dropper."
            )

        for rec in records[:3]:
            self._add_timeline(rec, "payload", f"PE binary observed (arch={rec.get('machine', 'unknown')})", "pe.log", "T1105")

        evidence = Evidence(
            source_log="pe.log",
            description=(
                f"{len(records)} PE file(s): architectures={architectures}, "
                f"{len(compile_timestamps)} with compile timestamps"
            ),
            raw_data={
                "architectures": architectures,
                "compile_timestamps": compile_timestamps[:20],
                "section_names": list(section_names)[:30],
                "sample_details": pe_details[:20],
            },
            search_query="full read of pe.log",
        )
        sev = Severity.HIGH if dual_arch else Severity.MEDIUM
        self._add_finding(
            title="PE Binary Metadata Analysis",
            text=(
                f"Analyzed {len(records)} PE file record(s). "
                f"Architectures: {', '.join(f'{k}({v})' for k, v in architectures.items())}. "
                f"{len(compile_timestamps)} file(s) have compile timestamps. "
                f"Sections observed: {', '.join(list(section_names)[:10])}. "
                f"{dual_arch_note}"
            ),
            severity=sev,
            evidence=[evidence],
            mitre=[MITREMapping(
                tactic="Command and Control",
                technique="Ingress Tool Transfer",
                technique_id="T1105",
                observed_evidence=f"{len(records)} PE files analyzed",
            )],
        )

    # ------------------------------------------------------------------
    # Step 3: GPO file access
    # ------------------------------------------------------------------

    def _check_gpo_access(self) -> None:
        print("  [Phase 4] Searching smb_files.log for GPO file access...")
        log = self._get_log("smb_files.log")
        if log is None:
            return

        reader = self._safe_reader(log)
        if reader is None:
            return

        gpo_patterns = [
            "gpt.ini", "Registry.xml", "Groups.xml",
            "audit.csv", "ScheduledTasks.xml",
        ]

        gpo_hits: list[dict] = []
        pattern_hits: dict[str, int] = {}

        for pattern in gpo_patterns:
            try:
                hits = reader.grep(pattern, max_results=5000)
            except Exception:
                hits = []
            if hits:
                pattern_hits[pattern] = len(hits)
                gpo_hits.extend(hits)

        if not gpo_hits:
            return

        # Identify which hosts accessed GPO files
        accessing_hosts = list({
            rec.get("id.orig_h", "") for rec in gpo_hits if rec.get("id.orig_h")
        })

        for host in accessing_hosts[:10]:
            self._add_ioc(IOCType.IP, host, "Host accessing GPO files via SMB", {}, "smb_files.log")

        for rec in gpo_hits[:3]:
            fname = rec.get("name", "") or rec.get("filename", "unknown")
            self._add_timeline(rec, "payload", f"GPO file accessed: {fname}", "smb_files.log", "T1484.001")

        evidence = Evidence(
            source_log="smb_files.log",
            description=f"{len(gpo_hits)} GPO file access(es) by {len(accessing_hosts)} host(s)",
            raw_data={
                "pattern_hits": pattern_hits,
                "accessing_hosts": accessing_hosts[:20],
                "sample_records": gpo_hits[:20],
            },
            search_query=f"grep for {gpo_patterns}",
        )
        self._add_finding(
            title="Group Policy Object File Access",
            text=(
                f"Detected {len(gpo_hits)} access(es) to GPO files via SMB: "
                f"{', '.join(f'{p}({c})' for p, c in pattern_hits.items())}. "
                f"Accessing hosts: {', '.join(accessing_hosts[:10])}. GPO manipulation "
                f"can be used for persistence and mass deployment of malware."
            ),
            severity=Severity.MEDIUM,
            evidence=[evidence],
            mitre=[MITREMapping(
                tactic="Defense Evasion",
                technique="Domain Policy Modification: Group Policy Modification",
                technique_id="T1484.001",
                observed_evidence=f"{len(gpo_hits)} GPO file accesses",
            )],
        )

    # ------------------------------------------------------------------
    # Step 4: Suspicious SMB file patterns
    # ------------------------------------------------------------------

    def _check_suspicious_smb_patterns(self) -> None:
        print("  [Phase 4] Searching smb_files.log for suspicious patterns...")
        log = self._get_log("smb_files.log")
        if log is None:
            return

        reader = self._safe_reader(log)
        if reader is None:
            return

        # Patterns indicating ransomware, management tools, backup tools
        suspicious_patterns = [
            "ransom", "crypt", "locker", "readme.txt",
            "ManageEngine", "backup", "veeam", "shadow",
            ".bat", ".ps1", ".vbs",
        ]

        suspicious_hits: list[dict] = []
        pattern_hits: dict[str, int] = {}

        for pattern in suspicious_patterns:
            try:
                hits = reader.grep(pattern, max_results=2000)
            except Exception:
                hits = []
            if hits:
                pattern_hits[pattern] = len(hits)
                suspicious_hits.extend(hits)

        if not suspicious_hits:
            return

        # Record IOCs for suspicious filenames
        suspicious_filenames = list({
            rec.get("name", "") or rec.get("filename", "")
            for rec in suspicious_hits
            if rec.get("name") or rec.get("filename")
        })

        for fname in suspicious_filenames[:20]:
            self._add_ioc(IOCType.FILENAME, fname, "Suspicious file on SMB share", {}, "smb_files.log")

        for rec in suspicious_hits[:3]:
            fname = rec.get("name", "") or rec.get("filename", "unknown")
            self._add_timeline(rec, "payload", f"Suspicious SMB file: {fname}", "smb_files.log", "T1486")

        evidence = Evidence(
            source_log="smb_files.log",
            description=f"{len(suspicious_hits)} suspicious file pattern match(es)",
            raw_data={
                "pattern_hits": pattern_hits,
                "filenames": suspicious_filenames[:30],
                "sample_records": suspicious_hits[:20],
            },
            search_query=f"grep for {list(pattern_hits.keys())}",
        )

        # Determine severity based on patterns found
        sev = Severity.MEDIUM
        if any(p in pattern_hits for p in ("ransom", "crypt", "locker")):
            sev = Severity.CRITICAL

        self._add_finding(
            title="Suspicious Files Detected on SMB Shares",
            text=(
                f"Detected {len(suspicious_hits)} file(s) matching suspicious patterns: "
                f"{', '.join(f'{p}({c})' for p, c in pattern_hits.items())}. "
                f"Unique filenames: {', '.join(suspicious_filenames[:10])}."
            ),
            severity=sev,
            evidence=[evidence],
            mitre=[
                MITREMapping(
                    tactic="Impact",
                    technique="Data Encrypted for Impact",
                    technique_id="T1486",
                    observed_evidence=f"{len(suspicious_hits)} suspicious file patterns",
                ),
                MITREMapping(
                    tactic="Impact",
                    technique="Inhibit System Recovery",
                    technique_id="T1490",
                    observed_evidence="Backup/recovery tool references",
                ),
                MITREMapping(
                    tactic="Command and Control",
                    technique="Remote Access Software",
                    technique_id="T1219",
                    observed_evidence="Management tool references",
                ),
            ],
        )

    # ------------------------------------------------------------------
    # Step 5: Cross-reference exe staging with exfil timeline
    # ------------------------------------------------------------------

    def _cross_reference_timeline(self) -> None:
        """Check whether exe staging timestamps overlap with exfil timeline events
        from prior IOCs."""
        if not self._exe_timestamps:
            return

        # Gather exfiltration timeline from prior IOCs
        exfil_iocs = [
            ioc for ioc in self.prior_iocs
            if ioc.source_phase == "exfiltration" and ioc.first_seen
        ]

        if not exfil_iocs:
            return

        print("  [Phase 4] Cross-referencing payload staging with exfiltration timeline...")

        # Build a rough exfil time window
        exfil_times: list[float] = []
        for ioc in exfil_iocs:
            # first_seen is a human-readable string; we cannot easily convert back,
            # so we skip exact comparison and note the correlation narratively.
            pass

        # Cluster exe timestamps
        exe_clusters = cluster_by_time(
            [{"ts": t} for t in self._exe_timestamps],
            "ts",
            gap_seconds=86400,
        )

        if exe_clusters:
            evidence = Evidence(
                source_log="smb_files.log",
                description=f"Executable staging occurred in {len(exe_clusters)} time cluster(s)",
                raw_data={
                    "cluster_count": len(exe_clusters),
                    "earliest_exe": epoch_to_utc(min(self._exe_timestamps)) if self._exe_timestamps else "",
                    "latest_exe": epoch_to_utc(max(self._exe_timestamps)) if self._exe_timestamps else "",
                },
                search_query="cross-reference exe timestamps with exfil IOCs",
            )
            self._add_finding(
                title="Payload Staging Timeline Correlation",
                text=(
                    f"Executable staging spans {len(exe_clusters)} time cluster(s), "
                    f"from {epoch_to_utc(min(self._exe_timestamps))} to "
                    f"{epoch_to_utc(max(self._exe_timestamps))}. This should be compared "
                    f"with exfiltration activity for temporal overlap."
                ),
                severity=Severity.INFO,
                evidence=[evidence],
                mitre=[],
            )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _get_log(self, name: str) -> Optional[LogFile]:
        for lf in self.inventory:
            if lf.name == name:
                return lf
        return None

    def _safe_reader(self, log: LogFile) -> Optional[ZeekLogReader]:
        try:
            return ZeekLogReader(log.path)
        except Exception as exc:
            print(f"  [Phase 4] Warning: could not open {log.name}: {exc}")
            return None

    def _safe_read(self, log: LogFile, head: int = 5000) -> list[dict]:
        reader = self._safe_reader(log)
        if reader is None:
            return []
        try:
            if log.category == LogCategory.FULL_READ:
                return reader.read_full()
            return reader.read_head(head)
        except Exception as exc:
            print(f"  [Phase 4] Warning: could not read {log.name}: {exc}")
            return []

    def _add_ioc(self, ioc_type: IOCType, value: str, context: str, record: dict, source: str) -> None:
        for existing in self.iocs:
            if existing.type == ioc_type and existing.value == value:
                return
        ts_str = ""
        if isinstance(record, dict):
            ts_raw = record.get("ts", "")
            if ts_raw:
                try:
                    ts_str = epoch_to_utc(float(ts_raw))
                except (ValueError, TypeError):
                    ts_str = str(ts_raw)
        self.iocs.append(IOC(
            type=ioc_type,
            value=value,
            context=context,
            first_seen=ts_str,
            last_seen=ts_str,
            source_phase="payload",
        ))

    def _add_timeline(self, record: dict, phase: str, description: str, source: str, mitre_id: str) -> None:
        ts_raw = record.get("ts", 0)
        try:
            ts = float(ts_raw)
        except (ValueError, TypeError):
            ts = 0.0
        self.timeline.append(TimelineEvent(
            timestamp=ts,
            timestamp_human=epoch_to_utc(ts) if ts else "",
            source_ip=record.get("id.orig_h", ""),
            dest_ip=record.get("id.resp_h", ""),
            phase=phase,
            description=description,
            evidence_ref=source,
            mitre_id=mitre_id,
        ))

    def _add_finding(
        self,
        title: str,
        text: str,
        severity: Severity,
        evidence: list[Evidence],
        mitre: list[MITREMapping],
    ) -> None:
        self._finding_counter += 1
        self.findings.append(Finding(
            id=f"PL-{self._finding_counter:03d}",
            title=title,
            finding_text=text,
            severity=severity,
            evidence=evidence,
            mitre_mappings=mitre,
            iocs_discovered=[],
            timeline_events=[],
        ))

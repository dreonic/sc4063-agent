"""
Phase 3 - Exfiltration Analyzer
DNS lookups to exfil services, SSL sessions, IP recon tools, file transfer
tool staging.
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
from ..tools.search import is_external_ip, group_by_field, count_unique
from ..tools.stats import (
    count_by_field, top_n, unique_values, cluster_by_time, epoch_to_human,
)


class ExfiltrationAnalyzer:
    """Phase 3: DNS lookups to exfil services, SSL sessions, IP recon tools,
    file transfer tool staging."""

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

        # Resolved IPs for exfil domains (populated in step 1)
        self._exfil_resolved_ips: set[str] = set()
        # Querying hosts (populated in step 1)
        self._exfil_querying_hosts: set[str] = set()

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------

    def run(self) -> PhaseResult:
        print("\n[Phase 3] Starting exfiltration analysis...")

        self._check_dns_exfil()
        self._check_ssl_exfil()
        self._check_ip_recon()
        self._check_smb_transfer_tools()

        summary = (
            f"Exfiltration analysis complete. "
            f"{len(self.findings)} finding(s), "
            f"{len(self.iocs)} IOC(s), "
            f"{len(self.timeline)} timeline event(s)."
        )
        print(f"  [Phase 3] {summary}")

        return PhaseResult(
            phase_name="exfiltration",
            findings=self.findings,
            iocs=self.iocs,
            timeline_events=self.timeline,
            raw_results={},
            summary=summary,
        )

    # ------------------------------------------------------------------
    # Step 1: DNS lookups to exfil domains
    # ------------------------------------------------------------------

    def _check_dns_exfil(self) -> None:
        print("  [Phase 3] Searching dns.log for known exfil domains...")
        log = self._get_log("dns.log")
        if log is None:
            print("  [Phase 3] dns.log not found, skipping DNS exfil check.")
            return

        reader = self._safe_reader(log)
        if reader is None:
            return

        all_hits: list[dict] = []
        domain_hits: dict[str, list[dict]] = {}

        for domain in self.config.known_exfil_domains:
            try:
                hits = reader.grep(domain, max_results=5000)
            except Exception:
                hits = []
            if hits:
                domain_hits[domain] = hits
                all_hits.extend(hits)

        if not all_hits:
            return

        # Extract querying host IPs and resolved IPs
        for rec in all_hits:
            querier = rec.get("id.orig_h", "")
            if querier:
                self._exfil_querying_hosts.add(querier)

            # Zeek dns.log stores answers in "answers" field (comma-separated)
            answers = rec.get("answers", "")
            if answers and answers != "-":
                for ans in answers.split(","):
                    ans = ans.strip()
                    if ans and ans != "-":
                        self._exfil_resolved_ips.add(ans)

        # Record IOCs
        for domain, hits in domain_hits.items():
            self._add_ioc(IOCType.DOMAIN, domain, f"Known exfil domain ({len(hits)} DNS lookups)", hits[0], "dns.log")
            for rec in hits[:3]:
                self._add_timeline(rec, "exfiltration", f"DNS lookup for exfil domain: {domain}", "dns.log", "T1567.002")

        for resolved_ip in list(self._exfil_resolved_ips)[:20]:
            self._add_ioc(IOCType.IP, resolved_ip, "Resolved IP for known exfil domain", {}, "dns.log")

        evidence = Evidence(
            source_log="dns.log",
            description=(
                f"{len(all_hits)} DNS lookup(s) for {len(domain_hits)} exfil domain(s) "
                f"from {len(self._exfil_querying_hosts)} host(s)"
            ),
            raw_data={
                "domains": {d: len(h) for d, h in domain_hits.items()},
                "querying_hosts": list(self._exfil_querying_hosts)[:20],
                "resolved_ips": list(self._exfil_resolved_ips)[:20],
            },
            search_query=f"grep for {list(domain_hits.keys())}",
        )
        self._add_finding(
            title="DNS Lookups to Known Exfiltration Domains",
            text=(
                f"Detected {len(all_hits)} DNS lookup(s) for known exfiltration domains: "
                f"{', '.join(domain_hits.keys())}. "
                f"Querying hosts: {', '.join(list(self._exfil_querying_hosts)[:10])}."
            ),
            severity=Severity.HIGH,
            evidence=[evidence],
            mitre=[MITREMapping(
                tactic="Exfiltration",
                technique="Exfiltration Over Web Service: Exfiltration to Cloud Storage",
                technique_id="T1567.002",
                observed_evidence=f"{len(all_hits)} DNS lookups to exfil domains",
            )],
        )

    # ------------------------------------------------------------------
    # Step 2: SSL sessions to exfil destinations
    # ------------------------------------------------------------------

    def _check_ssl_exfil(self) -> None:
        print("  [Phase 3] Searching ssl.log for connections to exfil destinations...")
        log = self._get_log("ssl.log")
        if log is None:
            print("  [Phase 3] ssl.log not found, skipping SSL exfil check.")
            return

        reader = self._safe_reader(log)
        if reader is None:
            return

        exfil_ssl: list[dict] = []

        # Search by SNI for known exfil domains
        for domain in self.config.known_exfil_domains:
            try:
                hits = reader.grep(domain, max_results=5000)
                exfil_ssl.extend(hits)
            except Exception:
                continue

        # Search by destination IP (resolved IPs from DNS step)
        for resolved_ip in list(self._exfil_resolved_ips)[:50]:
            try:
                hits = reader.grep(resolved_ip, max_results=1000)
                exfil_ssl.extend(hits)
            except Exception:
                continue

        if not exfil_ssl:
            return

        # Deduplicate by uid if available
        seen_uids: set[str] = set()
        deduped: list[dict] = []
        for rec in exfil_ssl:
            uid = rec.get("uid", "")
            if uid and uid in seen_uids:
                continue
            if uid:
                seen_uids.add(uid)
            deduped.append(rec)

        exfil_ssl = deduped

        # Cluster sessions by time (24-hour gap)
        clusters = cluster_by_time(exfil_ssl, "ts", gap_seconds=86400)

        # Extract TLS details
        tls_versions = sorted(list(unique_values(exfil_ssl, "version")))
        sni_values = sorted(list(unique_values(exfil_ssl, "server_name")))

        for rec in exfil_ssl[:5]:
            sni = rec.get("server_name", "unknown")
            self._add_timeline(rec, "exfiltration", f"SSL session to exfil target: {sni}", "ssl.log", "T1573.002")

        evidence = Evidence(
            source_log="ssl.log",
            description=(
                f"{len(exfil_ssl)} SSL session(s) to exfil destinations in "
                f"{len(clusters)} time cluster(s)"
            ),
            raw_data={
                "session_count": len(exfil_ssl),
                "clusters": len(clusters),
                "tls_versions": tls_versions[:10],
                "sni_values": sni_values[:20],
                "sample_records": exfil_ssl[:10],
            },
            search_query="grep for exfil domains + resolved IPs in ssl.log",
        )
        self._add_finding(
            title="Encrypted Sessions to Exfiltration Services",
            text=(
                f"Detected {len(exfil_ssl)} SSL/TLS session(s) to known exfiltration "
                f"destinations, grouped into {len(clusters)} time cluster(s). "
                f"SNI values: {', '.join(sni_values[:10])}. "
                f"TLS versions: {', '.join(tls_versions[:5])}."
            ),
            severity=Severity.HIGH,
            evidence=[evidence],
            mitre=[MITREMapping(
                tactic="Command and Control",
                technique="Encrypted Channel: Asymmetric Cryptography",
                technique_id="T1573.002",
                observed_evidence=f"{len(exfil_ssl)} SSL sessions to exfil targets",
            )],
        )

    # ------------------------------------------------------------------
    # Step 3: IP recon service lookups
    # ------------------------------------------------------------------

    def _check_ip_recon(self) -> None:
        print("  [Phase 3] Searching http.log for IP recon service access...")
        log = self._get_log("http.log")
        if log is None:
            print("  [Phase 3] http.log not found, skipping IP recon check.")
            return

        reader = self._safe_reader(log)
        if reader is None:
            return

        recon_hits: list[dict] = []
        service_hits: dict[str, list[dict]] = {}

        for service in self.config.known_recon_services:
            try:
                hits = reader.grep(service, max_results=2000)
            except Exception:
                hits = []
            if hits:
                service_hits[service] = hits
                recon_hits.extend(hits)

        if not recon_hits:
            return

        # Extract querying hosts and cluster into "waves"
        source_hosts = sorted(list(unique_values(recon_hits, "id.orig_h")))
        user_agents = sorted(list(unique_values(recon_hits, "user_agent")))
        waves = cluster_by_time(recon_hits, "ts", gap_seconds=86400)

        for host in source_hosts[:10]:
            self._add_ioc(IOCType.IP, host, "Host performing IP reconnaissance", {}, "http.log")

        for rec in recon_hits[:3]:
            service_name = rec.get("host", "unknown")
            self._add_timeline(rec, "exfiltration", f"IP recon lookup: {service_name}", "http.log", "T1016")

        evidence = Evidence(
            source_log="http.log",
            description=(
                f"{len(recon_hits)} IP recon request(s) to {len(service_hits)} service(s) "
                f"in {len(waves)} wave(s)"
            ),
            raw_data={
                "services": {s: len(h) for s, h in service_hits.items()},
                "source_hosts": source_hosts[:20],
                "user_agents": user_agents[:10],
                "wave_count": len(waves),
            },
            search_query=f"grep for {list(service_hits.keys())}",
        )
        self._add_finding(
            title="IP Reconnaissance Service Lookups",
            text=(
                f"Detected {len(recon_hits)} request(s) to IP reconnaissance services "
                f"({', '.join(service_hits.keys())}). {len(source_hosts)} host(s) performed "
                f"lookups in {len(waves)} distinct wave(s). User-Agents: "
                f"{', '.join(user_agents[:5])}."
            ),
            severity=Severity.MEDIUM,
            evidence=[evidence],
            mitre=[MITREMapping(
                tactic="Discovery",
                technique="System Network Configuration Discovery",
                technique_id="T1016",
                observed_evidence=f"{len(recon_hits)} IP recon lookups",
            )],
        )

    # ------------------------------------------------------------------
    # Step 4: File transfer tool artifacts in SMB
    # ------------------------------------------------------------------

    def _check_smb_transfer_tools(self) -> None:
        print("  [Phase 3] Searching smb_files.log for file transfer tools...")
        log = self._get_log("smb_files.log")
        if log is None:
            print("  [Phase 3] smb_files.log not found, skipping transfer-tool check.")
            return

        reader = self._safe_reader(log)
        if reader is None:
            return

        tool_hits: list[dict] = []
        tool_match: dict[str, list[dict]] = {}

        for tool in self.config.known_transfer_tools:
            try:
                hits = reader.grep(tool, max_results=2000)
            except Exception:
                hits = []
            if hits:
                tool_match[tool] = hits
                tool_hits.extend(hits)

        if not tool_hits:
            return

        for tool_name, hits in tool_match.items():
            self._add_ioc(IOCType.FILENAME, tool_name, f"File transfer tool found in SMB ({len(hits)} occurrences)", hits[0], "smb_files.log")
            for rec in hits[:2]:
                self._add_timeline(rec, "exfiltration", f"Transfer tool on SMB: {tool_name}", "smb_files.log", "T1039")

        evidence = Evidence(
            source_log="smb_files.log",
            description=(
                f"{len(tool_hits)} SMB file record(s) matching {len(tool_match)} transfer tool(s)"
            ),
            raw_data={
                "tools": {t: len(h) for t, h in tool_match.items()},
                "sample_records": tool_hits[:20],
            },
            search_query=f"grep for {list(tool_match.keys())}",
        )
        self._add_finding(
            title="File Transfer Tools Staged via SMB",
            text=(
                f"Found {len(tool_hits)} SMB file record(s) referencing known file transfer "
                f"tools: {', '.join(tool_match.keys())}. These tools are commonly used "
                f"for data exfiltration."
            ),
            severity=Severity.HIGH,
            evidence=[evidence],
            mitre=[MITREMapping(
                tactic="Collection",
                technique="Data from Network Shared Drive",
                technique_id="T1039",
                observed_evidence=f"{len(tool_hits)} transfer tool references in SMB files",
            )],
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
            print(f"  [Phase 3] Warning: could not open {log.name}: {exc}")
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
            print(f"  [Phase 3] Warning: could not read {log.name}: {exc}")
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
            source_phase="exfiltration",
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
            id=f"EX-{self._finding_counter:03d}",
            title=title,
            finding_text=text,
            severity=severity,
            evidence=evidence,
            mitre_mappings=mitre,
            iocs_discovered=[],
            timeline_events=[],
        ))

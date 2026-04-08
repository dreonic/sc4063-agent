"""
Phase 1 - Initial Access Analyzer
Detect external RDP, C2 tunnels, protocol anomalies.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from ..models import (
    LogFile, LogCategory, NetworkHost, IOC, IOCType,
    TimelineEvent, MITREMapping, Evidence, Finding, Severity,
    PhaseResult, epoch_to_utc,
)
from ..config import Config
from ..tools.log_reader import ZeekLogReader
from ..tools.search import is_external_ip, find_external_ips
from ..tools.stats import top_n, time_range, unique_values, count_by_field


class InitialAccessAnalyzer:
    """Phase 1: Detect external RDP, C2 tunnels, protocol anomalies."""

    def __init__(
        self,
        log_inventory: list[LogFile],
        config: Config,
        network_hosts: list[NetworkHost],
    ):
        self.inventory = log_inventory
        self.config = config
        self.network_hosts = network_hosts
        self.findings: list[Finding] = []
        self.iocs: list[IOC] = []
        self.timeline: list[TimelineEvent] = []
        self._finding_counter = 0

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------

    def run(self) -> PhaseResult:
        print("\n[Phase 1] Starting initial-access analysis...")

        self._check_dpd()
        self._check_http()
        self._check_rdp()
        self._identify_patient_zero()

        summary = (
            f"Initial-access analysis complete. "
            f"{len(self.findings)} finding(s), "
            f"{len(self.iocs)} IOC(s), "
            f"{len(self.timeline)} timeline event(s)."
        )
        print(f"  [Phase 1] {summary}")

        return PhaseResult(
            phase_name="initial_access",
            findings=self.findings,
            iocs=self.iocs,
            timeline_events=self.timeline,
            raw_results={},
            summary=summary,
        )

    # ------------------------------------------------------------------
    # Sub-steps
    # ------------------------------------------------------------------

    def _check_dpd(self) -> None:
        """Step 1: Read dpd.log for protocol anomalies on remote-access ports."""
        print("  [Phase 1] Searching dpd.log for protocol anomalies...")
        log = self._get_log("dpd.log")
        if log is None:
            print("  [Phase 1] dpd.log not found, skipping.")
            return

        records = self._safe_read(log)
        if not records:
            return

        anomalies = []
        for rec in records:
            resp_port = rec.get("id.resp_p", "")
            try:
                port = int(resp_port)
            except (ValueError, TypeError):
                continue

            if port in self.config.remote_access_ports:
                anomalies.append(rec)
                src = rec.get("id.orig_h", "")
                if src and is_external_ip(src, self.config.internal_subnets):
                    self._add_ioc(IOCType.IP, src, "External IP with protocol anomaly on remote-access port", rec, "dpd.log")

        if anomalies:
            evidence = Evidence(
                source_log="dpd.log",
                description=f"{len(anomalies)} protocol anomaly record(s) on remote-access ports",
                raw_data=anomalies[:20],
                search_query="remote_access_ports filter",
            )
            self._add_finding(
                title="Protocol Anomalies on Remote Access Ports",
                text=(
                    f"Detected {len(anomalies)} DPD record(s) involving remote-access "
                    f"ports. This may indicate protocol tunneling or tool misuse."
                ),
                severity=Severity.MEDIUM,
                evidence=[evidence],
                mitre=[MITREMapping(
                    tactic="Initial Access",
                    technique="External Remote Services",
                    technique_id="T1133",
                    observed_evidence=f"{len(anomalies)} anomalous records on remote-access ports",
                )],
            )

    def _check_http(self) -> None:
        """Step 2: Search http.log for tunnels, suspicious UAs, WinRM, external access."""
        print("  [Phase 1] Searching http.log for tunnels and suspicious activity...")
        log = self._get_log("http.log")
        if log is None:
            print("  [Phase 1] http.log not found, skipping.")
            return

        reader = self._safe_reader(log)
        if reader is None:
            return

        # --- 2a. HTTP CONNECT tunnels ---
        self._check_http_connect(reader, log)

        # --- 2b. External IPs accessing internal hosts ---
        self._check_http_external(reader, log)

        # --- 2c. Suspicious User-Agents ---
        self._check_http_user_agents(reader, log)

        # --- 2d. WinRM /wsman from external IPs ---
        self._check_http_winrm(reader, log)

    def _check_http_connect(self, reader: ZeekLogReader, log: LogFile) -> None:
        try:
            connect_records = reader.grep("CONNECT", max_results=5000)
        except Exception:
            connect_records = []

        tunnels = [r for r in connect_records if r.get("method", "").upper() == "CONNECT"]
        if not tunnels:
            return

        # IANA-reserved and documentation domains that can never be attacker-controlled
        _RESERVED_DOMAINS = {
            "example.com", "example.net", "example.org", "example.edu",
            "localhost", "invalid", "test", "local",
        }

        c2_domains: list[str] = []
        for rec in tunnels:
            host_header = rec.get("host", "") or rec.get("uri", "")
            src = rec.get("id.orig_h", "")
            ts = rec.get("ts", "")

            if host_header:
                domain = host_header.split(":")[0].lower()
                # Skip IANA-reserved domains — they cannot be registered by attackers
                # and appear in scanner probes, conformance tests, and misconfigured clients
                if not domain or domain in _RESERVED_DOMAINS:
                    continue
                if domain not in c2_domains:
                    c2_domains.append(domain)
                    self._add_ioc(IOCType.DOMAIN, domain, "C2 tunnel destination (HTTP CONNECT)", rec, "http.log")

            if src and is_external_ip(src, self.config.internal_subnets):
                self._add_ioc(IOCType.IP, src, "External IP using HTTP CONNECT tunnel", rec, "http.log")

            self._add_timeline(rec, "initial_access", f"HTTP CONNECT tunnel to {host_header}", "http.log", "T1572")

        evidence = Evidence(
            source_log="http.log",
            description=f"{len(tunnels)} HTTP CONNECT tunnel(s) detected",
            raw_data=tunnels[:20],
            search_query="grep CONNECT",
        )
        self._add_finding(
            title="HTTP CONNECT Tunneling Detected",
            text=(
                f"Found {len(tunnels)} HTTP CONNECT request(s), indicating protocol tunneling. "
                f"C2 domains observed: {', '.join(c2_domains[:10]) or 'none extracted'}."
            ),
            severity=Severity.HIGH,
            evidence=[evidence],
            mitre=[MITREMapping(
                tactic="Command and Control",
                technique="Protocol Tunneling",
                technique_id="T1572",
                observed_evidence=f"{len(tunnels)} HTTP CONNECT requests",
            )],
        )

    def _check_http_external(self, reader: ZeekLogReader, log: LogFile) -> None:
        """Identify external IPs accessing internal web services."""
        if log.category == LogCategory.FULL_READ:
            try:
                records = reader.read_full()
            except Exception:
                return
        else:
            try:
                records = reader.read_head(2000)
            except Exception:
                return

        external_hits = []
        for rec in records:
            src = rec.get("id.orig_h", "")
            if src and is_external_ip(src, self.config.internal_subnets):
                external_hits.append(rec)

        if not external_hits:
            return

        ext_ips = list({r.get("id.orig_h", "") for r in external_hits if r.get("id.orig_h")})
        for ip in ext_ips:
            self._add_ioc(IOCType.IP, ip, "External IP accessing internal HTTP services", {}, "http.log")

        evidence = Evidence(
            source_log="http.log",
            description=f"{len(external_hits)} HTTP request(s) from {len(ext_ips)} external IP(s)",
            raw_data=external_hits[:20],
            search_query="external IP filter on id.orig_h",
        )
        self._add_finding(
            title="External HTTP Access to Internal Hosts",
            text=(
                f"Detected {len(external_hits)} HTTP request(s) originating from "
                f"{len(ext_ips)} external IP(s) targeting internal services."
            ),
            severity=Severity.HIGH,
            evidence=[evidence],
            mitre=[MITREMapping(
                tactic="Initial Access",
                technique="Valid Accounts",
                technique_id="T1078",
                observed_evidence=f"{len(ext_ips)} external IPs",
            )],
        )

    def _check_http_user_agents(self, reader: ZeekLogReader, log: LogFile) -> None:
        """Search for suspicious User-Agent strings."""
        suspicious_hits: list[dict] = []
        for ua_pattern in self.config.suspicious_user_agents:
            try:
                hits = reader.grep(ua_pattern, max_results=500)
                suspicious_hits.extend(hits)
            except Exception:
                continue

        if not suspicious_hits:
            return

        ua_values = list({r.get("user_agent", "unknown") for r in suspicious_hits})
        evidence = Evidence(
            source_log="http.log",
            description=f"{len(suspicious_hits)} request(s) with suspicious User-Agent strings",
            raw_data=suspicious_hits[:20],
            search_query=f"grep for {self.config.suspicious_user_agents}",
        )
        self._add_finding(
            title="Suspicious HTTP User-Agents Detected",
            text=(
                f"Found {len(suspicious_hits)} HTTP request(s) using suspicious User-Agent "
                f"strings: {', '.join(ua_values[:10])}. These are commonly associated with "
                f"automated tooling or malware."
            ),
            severity=Severity.MEDIUM,
            evidence=[evidence],
            mitre=[MITREMapping(
                tactic="Command and Control",
                technique="Protocol Tunneling",
                technique_id="T1572",
                observed_evidence=f"Suspicious UAs: {', '.join(ua_values[:5])}",
            )],
        )

    def _check_http_winrm(self, reader: ZeekLogReader, log: LogFile) -> None:
        """Search for WinRM /wsman requests from external IPs."""
        try:
            wsman_records = reader.grep("/wsman", max_results=2000)
        except Exception:
            wsman_records = []

        external_wsman = []
        for rec in wsman_records:
            src = rec.get("id.orig_h", "")
            if src and is_external_ip(src, self.config.internal_subnets):
                external_wsman.append(rec)
                self._add_ioc(IOCType.IP, src, "External IP using WinRM", rec, "http.log")
                self._add_timeline(rec, "initial_access", f"External WinRM access from {src}", "http.log", "T1133")

        if not external_wsman:
            return

        evidence = Evidence(
            source_log="http.log",
            description=f"{len(external_wsman)} WinRM request(s) from external IP(s)",
            raw_data=external_wsman[:20],
            search_query="grep /wsman + external IP filter",
        )
        self._add_finding(
            title="External WinRM Access Detected",
            text=(
                f"Detected {len(external_wsman)} WinRM (/wsman) request(s) from external "
                f"IP(s). WinRM is a remote management protocol and external access is "
                f"highly suspicious."
            ),
            severity=Severity.CRITICAL,
            evidence=[evidence],
            mitre=[MITREMapping(
                tactic="Initial Access",
                technique="External Remote Services",
                technique_id="T1133",
                observed_evidence=f"{len(external_wsman)} external WinRM requests",
            )],
        )

    def _check_rdp(self) -> None:
        """Step 3: Search rdp.log for non-internal source IPs."""
        print("  [Phase 1] Searching rdp.log for external RDP connections...")
        log = self._get_log("rdp.log")
        if log is None:
            print("  [Phase 1] rdp.log not found, skipping.")
            return

        records = self._safe_read(log)
        if not records:
            return

        external_rdp = []
        for rec in records:
            src = rec.get("id.orig_h", "") or rec.get("cookie", "")
            orig = rec.get("id.orig_h", "")
            if orig and is_external_ip(orig, self.config.internal_subnets):
                external_rdp.append(rec)
                self._add_ioc(IOCType.IP, orig, "External IP initiating RDP", rec, "rdp.log")
                self._add_timeline(rec, "initial_access", f"External RDP from {orig}", "rdp.log", "T1133")

        if external_rdp:
            evidence = Evidence(
                source_log="rdp.log",
                description=f"{len(external_rdp)} RDP session(s) from external IP(s)",
                raw_data=external_rdp[:20],
                search_query="external IP filter on id.orig_h",
            )
            self._add_finding(
                title="External RDP Sessions Detected",
                text=(
                    f"Found {len(external_rdp)} RDP session(s) originating from external "
                    f"IP address(es). External RDP is a common initial-access vector."
                ),
                severity=Severity.CRITICAL,
                evidence=[evidence],
                mitre=[MITREMapping(
                    tactic="Initial Access",
                    technique="External Remote Services",
                    technique_id="T1133",
                    observed_evidence=f"{len(external_rdp)} external RDP sessions",
                )],
            )

    def _identify_patient_zero(self) -> None:
        """Step 5: Identify Patient Zero - the first internal host targeted by external attackers."""
        print("  [Phase 1] Identifying Patient Zero...")

        # Collect all timeline events targeting internal hosts from external sources
        internal_targets: dict[str, float] = {}  # ip -> earliest timestamp
        for evt in self.timeline:
            dest = evt.dest_ip
            if dest and not is_external_ip(dest, self.config.internal_subnets):
                ts = evt.timestamp
                if dest not in internal_targets or ts < internal_targets[dest]:
                    internal_targets[dest] = ts

        if not internal_targets:
            print("  [Phase 1] No Patient Zero identified (no external->internal events).")
            return

        # Patient Zero = internal host with the earliest external-facing event
        patient_zero_ip = min(internal_targets, key=internal_targets.get)  # type: ignore[arg-type]
        pz_ts = internal_targets[patient_zero_ip]

        self._add_ioc(
            IOCType.IP,
            patient_zero_ip,
            f"Patient Zero - first internal host targeted (earliest event {epoch_to_utc(pz_ts)})",
            {},
            "initial_access_correlation",
        )

        evidence = Evidence(
            source_log="multiple",
            description=f"Patient Zero identified as {patient_zero_ip} at {epoch_to_utc(pz_ts)}",
            raw_data={"patient_zero": patient_zero_ip, "first_seen": epoch_to_utc(pz_ts)},
            search_query="earliest external->internal event",
        )
        self._add_finding(
            title=f"Patient Zero Identified: {patient_zero_ip}",
            text=(
                f"The internal host {patient_zero_ip} was the first target of external "
                f"access, with the earliest event at {epoch_to_utc(pz_ts)}. Subsequent "
                f"lateral movement likely originates from this host."
            ),
            severity=Severity.CRITICAL,
            evidence=[evidence],
            mitre=[MITREMapping(
                tactic="Initial Access",
                technique="Valid Accounts",
                technique_id="T1078",
                observed_evidence=f"Patient Zero: {patient_zero_ip}",
            )],
        )
        print(f"  [Phase 1] Patient Zero: {patient_zero_ip}")

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
            print(f"  [Phase 1] Warning: could not open {log.name}: {exc}")
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
            print(f"  [Phase 1] Warning: could not read {log.name}: {exc}")
            return []

    def _add_ioc(self, ioc_type: IOCType, value: str, context: str, record: dict, source: str) -> None:
        # Avoid duplicates
        for existing in self.iocs:
            if existing.type == ioc_type and existing.value == value:
                return
        ts_str = ""
        ts_raw = record.get("ts", "") if isinstance(record, dict) else ""
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
            source_phase="initial_access",
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
            id=f"IA-{self._finding_counter:03d}",
            title=title,
            finding_text=text,
            severity=severity,
            evidence=evidence,
            mitre_mappings=mitre,
            iocs_discovered=[],
            timeline_events=[],
        ))

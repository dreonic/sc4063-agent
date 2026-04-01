"""
Phase 2 - Lateral Movement Analyzer
Credential spray, SAMR enum, Kerberos escalation, NTLM lateral movement,
SMB shares, SOCKS proxy chains, WinRM.
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
from ..tools.search import (
    is_external_ip, find_auth_failures, find_auth_successes,
    find_high_volume_sources, group_by_field, count_unique,
)
from ..tools.stats import count_by_field, top_n, unique_values, cluster_by_time


class LateralMovementAnalyzer:
    """Phase 2: Credential spray, SAMR enum, Kerberos escalation, NTLM lateral
    movement, SMB shares, SOCKS proxy, WinRM."""

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

        # Derive patient-zero IP from prior IOCs if present
        self.patient_zero: Optional[str] = None
        for ioc in prior_iocs:
            if "patient zero" in ioc.context.lower():
                self.patient_zero = ioc.value
                break

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------

    def run(self) -> PhaseResult:
        print("\n[Phase 2] Starting lateral-movement analysis...")

        self._check_credential_spray()
        self._check_lateral_ntlm()
        self._check_samr()
        self._check_kerberos()
        self._check_smb_shares()
        self._check_socks()
        self._check_winrm()

        summary = (
            f"Lateral-movement analysis complete. "
            f"{len(self.findings)} finding(s), "
            f"{len(self.iocs)} IOC(s), "
            f"{len(self.timeline)} timeline event(s)."
        )
        print(f"  [Phase 2] {summary}")

        return PhaseResult(
            phase_name="lateral_movement",
            findings=self.findings,
            iocs=self.iocs,
            timeline_events=self.timeline,
            raw_results={},
            summary=summary,
        )

    # ------------------------------------------------------------------
    # Step 1: Credential spray
    # ------------------------------------------------------------------

    def _check_credential_spray(self) -> None:
        print("  [Phase 2] Checking ntlm.log for credential spray...")
        log = self._get_log("ntlm.log")
        if log is None:
            print("  [Phase 2] ntlm.log not found, skipping credential spray check.")
            return

        reader = self._safe_reader(log)
        if reader is None:
            return

        # Get authentication failures
        if log.category == LogCategory.FULL_READ:
            try:
                records = reader.read_full()
            except Exception:
                return
        else:
            try:
                records = reader.grep("false", max_results=50000)
            except Exception:
                return

        failures = find_auth_failures(records)
        if not failures:
            return

        # Group failures by source IP
        by_source = group_by_field(failures, "id.orig_h")
        spray_sources: list[dict] = []

        for src_ip, recs in by_source.items():
            if len(recs) >= self.config.cred_spray_min_failures:
                target_count = count_unique(recs, "id.resp_h")
                accounts = sorted(list(unique_values(recs, "username")))
                spray_sources.append({
                    "ip": src_ip,
                    "failure_count": len(recs),
                    "target_count": target_count,
                    "accounts_tried": accounts[:20],
                })
                self._add_ioc(IOCType.IP, src_ip, f"Credential spray source ({len(recs)} failures)", recs[0], "ntlm.log")
                for acct in accounts[:10]:
                    self._add_ioc(IOCType.ACCOUNT, acct, f"Account targeted in credential spray from {src_ip}", recs[0], "ntlm.log")

        if not spray_sources:
            return

        evidence = Evidence(
            source_log="ntlm.log",
            description=f"{len(spray_sources)} source(s) performing credential spray",
            raw_data=spray_sources,
            search_query="auth failures grouped by source",
        )
        self._add_finding(
            title="Credential Spray Attack Detected",
            text=(
                f"Detected {len(spray_sources)} source IP(s) performing credential spray. "
                + "; ".join(
                    f"{s['ip']}: {s['failure_count']} failures against {s['target_count']} targets"
                    for s in spray_sources[:5]
                )
            ),
            severity=Severity.HIGH,
            evidence=[evidence],
            mitre=[MITREMapping(
                tactic="Credential Access",
                technique="Brute Force: Password Spraying",
                technique_id="T1110.003",
                observed_evidence=f"{sum(s['failure_count'] for s in spray_sources)} total failures",
            )],
        )

    # ------------------------------------------------------------------
    # Step 2: Lateral NTLM movement
    # ------------------------------------------------------------------

    def _check_lateral_ntlm(self) -> None:
        print("  [Phase 2] Checking ntlm.log for lateral movement...")
        log = self._get_log("ntlm.log")
        if log is None:
            return

        reader = self._safe_reader(log)
        if reader is None:
            return

        # Focus on successes — especially from patient zero
        if log.category == LogCategory.FULL_READ:
            try:
                records = reader.read_full()
            except Exception:
                return
        else:
            try:
                records = reader.grep("true", max_results=50000)
            except Exception:
                return

        successes = find_auth_successes(records)
        if not successes:
            return

        by_source = group_by_field(successes, "id.orig_h")
        lateral_sources: list[dict] = []

        for src_ip, recs in by_source.items():
            dest_count = count_unique(recs, "id.resp_h")
            if dest_count >= self.config.lateral_move_min_targets:
                accounts = sorted(list(unique_values(recs, "username")))
                lateral_sources.append({
                    "ip": src_ip,
                    "success_count": len(recs),
                    "unique_targets": dest_count,
                    "accounts_used": accounts[:20],
                    "is_patient_zero": src_ip == self.patient_zero,
                })
                label = "Patient Zero lateral movement" if src_ip == self.patient_zero else "Lateral movement source"
                self._add_ioc(IOCType.IP, src_ip, f"{label} ({dest_count} unique targets)", recs[0], "ntlm.log")
                for acct in accounts[:10]:
                    self._add_ioc(IOCType.ACCOUNT, acct, f"Account used for lateral movement from {src_ip}", recs[0], "ntlm.log")

                # Timeline events for the earliest and latest record
                if recs:
                    self._add_timeline(recs[0], "lateral_movement", f"Lateral NTLM auth from {src_ip} ({dest_count} targets)", "ntlm.log", "T1078.002")
                    if len(recs) > 1:
                        self._add_timeline(recs[-1], "lateral_movement", f"Last lateral NTLM auth from {src_ip}", "ntlm.log", "T1078.002")

        if not lateral_sources:
            return

        sev = Severity.CRITICAL if any(s["is_patient_zero"] for s in lateral_sources) else Severity.HIGH
        evidence = Evidence(
            source_log="ntlm.log",
            description=f"{len(lateral_sources)} source(s) performing lateral movement",
            raw_data=lateral_sources,
            search_query="auth successes grouped by source, unique dest >= threshold",
        )
        self._add_finding(
            title="NTLM Lateral Movement Detected",
            text=(
                f"Detected {len(lateral_sources)} host(s) authenticating to many internal "
                f"targets. "
                + "; ".join(
                    f"{s['ip']}{'(Patient Zero)' if s['is_patient_zero'] else ''}: "
                    f"{s['unique_targets']} targets, accounts={s['accounts_used'][:5]}"
                    for s in lateral_sources[:5]
                )
            ),
            severity=sev,
            evidence=[evidence],
            mitre=[
                MITREMapping(
                    tactic="Lateral Movement",
                    technique="Valid Accounts: Domain Accounts",
                    technique_id="T1078.002",
                    observed_evidence=f"{len(lateral_sources)} sources with wide NTLM auth",
                ),
            ],
        )

    # ------------------------------------------------------------------
    # Step 3: SAMR enumeration
    # ------------------------------------------------------------------

    def _check_samr(self) -> None:
        print("  [Phase 2] Checking dce_rpc.log for SAMR operations...")
        log = self._get_log("dce_rpc.log")
        if log is None:
            print("  [Phase 2] dce_rpc.log not found, skipping SAMR check.")
            return

        reader = self._safe_reader(log)
        if reader is None:
            return

        try:
            samr_records = reader.grep("samr", max_results=50000)
        except Exception:
            samr_records = []

        if not samr_records:
            return

        by_source = group_by_field(samr_records, "id.orig_h")
        enum_sources: list[dict] = []

        for src_ip, recs in by_source.items():
            if len(recs) >= self.config.samr_enum_min_ops:
                operations = sorted(list(unique_values(recs, "operation")))
                enum_sources.append({
                    "ip": src_ip,
                    "op_count": len(recs),
                    "operations": operations[:20],
                })
                self._add_ioc(IOCType.IP, src_ip, f"SAMR enumeration source ({len(recs)} ops)", recs[0], "dce_rpc.log")
                self._add_timeline(recs[0], "lateral_movement", f"SAMR enumeration from {src_ip} ({len(recs)} ops)", "dce_rpc.log", "T1087.002")

        # Check for account creation / group modification
        creation_records = [r for r in samr_records if any(
            op in (r.get("operation", "") or "")
            for op in ("SamrCreateUser", "SamrAddMember", "SamrSetInformationUser")
        )]

        if creation_records:
            evidence_creation = Evidence(
                source_log="dce_rpc.log",
                description=f"{len(creation_records)} SAMR account creation/modification operation(s)",
                raw_data=creation_records[:20],
                search_query="SamrCreateUser|SamrAddMember|SamrSetInformationUser",
            )
            self._add_finding(
                title="SAMR Account Creation / Group Modification",
                text=(
                    f"Detected {len(creation_records)} SAMR operation(s) related to account "
                    f"creation or group modification. This could indicate privilege escalation."
                ),
                severity=Severity.CRITICAL,
                evidence=[evidence_creation],
                mitre=[MITREMapping(
                    tactic="Persistence",
                    technique="Account Manipulation",
                    technique_id="T1098",
                    observed_evidence=f"{len(creation_records)} create/modify ops",
                )],
            )

        if not enum_sources:
            return

        evidence = Evidence(
            source_log="dce_rpc.log",
            description=f"{len(enum_sources)} source(s) performing SAMR enumeration",
            raw_data=enum_sources,
            search_query="grep samr, grouped by source",
        )
        self._add_finding(
            title="SAMR Enumeration Detected",
            text=(
                f"Detected {len(enum_sources)} host(s) performing extensive SAMR enumeration. "
                + "; ".join(
                    f"{s['ip']}: {s['op_count']} operations ({', '.join(s['operations'][:5])})"
                    for s in enum_sources[:5]
                )
            ),
            severity=Severity.HIGH,
            evidence=[evidence],
            mitre=[
                MITREMapping(
                    tactic="Discovery",
                    technique="Account Discovery: Domain Account",
                    technique_id="T1087.002",
                    observed_evidence=f"{sum(s['op_count'] for s in enum_sources)} SAMR ops",
                ),
                MITREMapping(
                    tactic="Discovery",
                    technique="Permission Groups Discovery: Domain Groups",
                    technique_id="T1069.002",
                    observed_evidence="SAMR group enumeration",
                ),
            ],
        )

    # ------------------------------------------------------------------
    # Step 4: Kerberos escalation
    # ------------------------------------------------------------------

    def _check_kerberos(self) -> None:
        print("  [Phase 2] Checking kerberos.log for escalation patterns...")
        log = self._get_log("kerberos.log")
        if log is None:
            print("  [Phase 2] kerberos.log not found, skipping Kerberos check.")
            return

        reader = self._safe_reader(log)
        if reader is None:
            return

        try:
            tgt_records = reader.grep("krbtgt", max_results=10000)
        except Exception:
            tgt_records = []

        if not tgt_records:
            return

        # Focus on TGT requests from patient zero or suspicious hosts
        suspicious_tgt: list[dict] = []
        suspicious_ips = {ioc.value for ioc in self.prior_iocs + self.iocs if ioc.type == IOCType.IP}

        for rec in tgt_records:
            src = rec.get("id.orig_h", "") or rec.get("client", "")
            if src in suspicious_ips or src == self.patient_zero:
                suspicious_tgt.append(rec)

        # Even if no suspicious IPs match, report all TGT requests for context
        target_records = suspicious_tgt if suspicious_tgt else tgt_records

        # Identify domain admin accounts (accounts requesting TGTs)
        admin_accounts = sorted(list(unique_values(target_records, "client")))

        for acct in admin_accounts[:10]:
            self._add_ioc(IOCType.ACCOUNT, acct, "Account requesting Kerberos TGT (potential domain admin)", {}, "kerberos.log")

        if target_records:
            self._add_timeline(target_records[0], "lateral_movement", f"Kerberos TGT request (krbtgt) - {len(target_records)} total", "kerberos.log", "T1558")

        evidence = Evidence(
            source_log="kerberos.log",
            description=f"{len(target_records)} Kerberos TGT request(s) involving known IOCs",
            raw_data=target_records[:20],
            search_query="grep krbtgt + IOC IP filter",
        )
        sev = Severity.HIGH if suspicious_tgt else Severity.MEDIUM
        self._add_finding(
            title="Kerberos TGT Activity from Suspicious Hosts",
            text=(
                f"Detected {len(target_records)} Kerberos TGT request(s). "
                f"Accounts involved: {', '.join(admin_accounts[:10])}. "
                f"{'Requests originated from known IOC IPs.' if suspicious_tgt else 'No direct IOC IP match, but TGT activity is noted for context.'}"
            ),
            severity=sev,
            evidence=[evidence],
            mitre=[MITREMapping(
                tactic="Credential Access",
                technique="Steal or Forge Kerberos Tickets",
                technique_id="T1558",
                observed_evidence=f"{len(target_records)} TGT requests",
            )],
        )

    # ------------------------------------------------------------------
    # Step 5: SMB admin shares
    # ------------------------------------------------------------------

    def _check_smb_shares(self) -> None:
        print("  [Phase 2] Checking smb_mapping.log for admin share access...")
        log = self._get_log("smb_mapping.log")
        if log is None:
            print("  [Phase 2] smb_mapping.log not found, skipping SMB share check.")
            return

        reader = self._safe_reader(log)
        if reader is None:
            return

        known_attacker_ips = {ioc.value for ioc in self.prior_iocs + self.iocs if ioc.type == IOCType.IP}

        admin_records: list[dict] = []
        for pattern in [r"ADMIN\$", r"C\$"]:
            try:
                hits = reader.grep(pattern, max_results=20000)
                admin_records.extend(hits)
            except Exception:
                continue

        if not admin_records:
            return

        # Filter to known attacker IPs if available, else report all
        if known_attacker_ips:
            attacker_hits = [r for r in admin_records if r.get("id.orig_h", "") in known_attacker_ips]
        else:
            attacker_hits = admin_records

        if not attacker_hits:
            return

        by_source = group_by_field(attacker_hits, "id.orig_h")
        share_summary: list[dict] = []
        for src_ip, recs in by_source.items():
            dest_count = count_unique(recs, "id.resp_h")
            share_summary.append({
                "ip": src_ip,
                "access_count": len(recs),
                "unique_targets": dest_count,
            })
            if len(recs) >= self.config.admin_share_min_accesses:
                self._add_timeline(recs[0], "lateral_movement", f"Admin share access from {src_ip} ({len(recs)} accesses)", "smb_mapping.log", "T1021.002")

        total_accesses = sum(s["access_count"] for s in share_summary)
        evidence = Evidence(
            source_log="smb_mapping.log",
            description=f"{total_accesses} ADMIN$/C$ access(es) from {len(share_summary)} source(s)",
            raw_data=share_summary,
            search_query=r"grep ADMIN\$ and C\$ + attacker IP filter",
        )
        self._add_finding(
            title="Administrative Share Access Detected",
            text=(
                f"Detected {total_accesses} access(es) to ADMIN$ or C$ shares from "
                f"{len(share_summary)} source IP(s). "
                + "; ".join(
                    f"{s['ip']}: {s['access_count']} accesses to {s['unique_targets']} targets"
                    for s in share_summary[:5]
                )
            ),
            severity=Severity.HIGH,
            evidence=[evidence],
            mitre=[MITREMapping(
                tactic="Lateral Movement",
                technique="Remote Services: SMB/Windows Admin Shares",
                technique_id="T1021.002",
                observed_evidence=f"{total_accesses} admin share accesses",
            )],
        )

    # ------------------------------------------------------------------
    # Step 6: SOCKS proxy chains
    # ------------------------------------------------------------------

    def _check_socks(self) -> None:
        print("  [Phase 2] Checking socks.log for proxy chains...")
        log = self._get_log("socks.log")
        if log is None:
            print("  [Phase 2] socks.log not found, skipping SOCKS check.")
            return

        records = self._safe_read(log)
        if not records:
            return

        # Group by source->dest pairs to identify multi-hop chains
        pair_map: dict[str, list[dict]] = {}
        for rec in records:
            src = rec.get("id.orig_h", "")
            dst = rec.get("id.resp_h", "")
            pair_key = f"{src}->{dst}"
            pair_map.setdefault(pair_key, []).append(rec)

        if not pair_map:
            return

        # Identify chains: if a destination in one pair is a source in another
        dest_ips = {rec.get("id.resp_h", "") for rec in records}
        src_ips = {rec.get("id.orig_h", "") for rec in records}
        chain_pivots = dest_ips & src_ips  # IPs that are both destinations and sources

        for pivot_ip in chain_pivots:
            self._add_ioc(IOCType.IP, pivot_ip, "SOCKS proxy chain pivot point", {}, "socks.log")

        for rec in records[:1]:
            self._add_timeline(rec, "lateral_movement", f"SOCKS proxy activity ({len(records)} records, {len(chain_pivots)} pivots)", "socks.log", "T1090.003")

        evidence = Evidence(
            source_log="socks.log",
            description=f"{len(records)} SOCKS record(s), {len(pair_map)} unique pairs, {len(chain_pivots)} pivot(s)",
            raw_data=list(pair_map.keys())[:30],
            search_query="full read + pair analysis",
        )
        self._add_finding(
            title="SOCKS Proxy Chains Detected",
            text=(
                f"Detected {len(records)} SOCKS record(s) across {len(pair_map)} unique "
                f"source->destination pairs. {len(chain_pivots)} host(s) act as proxy pivots "
                f"(both source and destination). This indicates multi-hop proxy chains for "
                f"traffic obfuscation."
            ),
            severity=Severity.HIGH,
            evidence=[evidence],
            mitre=[MITREMapping(
                tactic="Command and Control",
                technique="Proxy: Multi-hop Proxy",
                technique_id="T1090.003",
                observed_evidence=f"{len(chain_pivots)} pivot hosts in SOCKS chains",
            )],
        )

    # ------------------------------------------------------------------
    # Step 7: Internal WinRM
    # ------------------------------------------------------------------

    def _check_winrm(self) -> None:
        print("  [Phase 2] Checking http.log for internal WinRM usage...")
        log = self._get_log("http.log")
        if log is None:
            return

        reader = self._safe_reader(log)
        if reader is None:
            return

        try:
            wsman_records = reader.grep("/wsman", max_results=10000)
        except Exception:
            return

        # Filter to internal sources on WinRM ports
        internal_winrm: list[dict] = []
        for rec in wsman_records:
            src = rec.get("id.orig_h", "")
            port = rec.get("id.resp_p", "")
            method = rec.get("method", "")
            if not is_external_ip(src, self.config.internal_subnets):
                try:
                    p = int(port)
                except (ValueError, TypeError):
                    p = 0
                if p in (5985, 5986) or method.upper() == "POST":
                    internal_winrm.append(rec)

        if not internal_winrm:
            return

        by_source = group_by_field(internal_winrm, "id.orig_h")
        for src_ip, recs in by_source.items():
            dest_count = count_unique(recs, "id.resp_h")
            self._add_ioc(IOCType.IP, src_ip, f"Internal WinRM source ({dest_count} targets)", recs[0], "http.log")
            self._add_timeline(recs[0], "lateral_movement", f"Internal WinRM from {src_ip} to {dest_count} targets", "http.log", "T1021.006")

        evidence = Evidence(
            source_log="http.log",
            description=f"{len(internal_winrm)} internal WinRM request(s) from {len(by_source)} source(s)",
            raw_data=internal_winrm[:20],
            search_query="grep /wsman + internal source + port 5985/5986",
        )
        self._add_finding(
            title="Internal WinRM Lateral Movement",
            text=(
                f"Detected {len(internal_winrm)} WinRM request(s) from {len(by_source)} "
                f"internal source(s). WinRM enables remote PowerShell execution."
            ),
            severity=Severity.HIGH,
            evidence=[evidence],
            mitre=[
                MITREMapping(
                    tactic="Lateral Movement",
                    technique="Remote Services: Windows Remote Management",
                    technique_id="T1021.006",
                    observed_evidence=f"{len(internal_winrm)} internal WinRM requests",
                ),
                MITREMapping(
                    tactic="Execution",
                    technique="Command and Scripting Interpreter: PowerShell",
                    technique_id="T1059.001",
                    observed_evidence="WinRM enables remote PowerShell",
                ),
            ],
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
            print(f"  [Phase 2] Warning: could not open {log.name}: {exc}")
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
            print(f"  [Phase 2] Warning: could not read {log.name}: {exc}")
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
            source_phase="lateral_movement",
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
            id=f"LM-{self._finding_counter:03d}",
            title=title,
            finding_text=text,
            severity=severity,
            evidence=evidence,
            mitre_mappings=mitre,
            iocs_discovered=[],
            timeline_events=[],
        ))

"""
Phase 5 - Correlator
Cross-phase correlation: merge IOCs, build timeline, map MITRE, generate
network topology, produce the final ForensicReport.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from ..models import (
    IOC, IOCType, TimelineEvent, MITREMapping, Finding, Severity,
    PhaseResult, NetworkHost, Evidence, epoch_to_utc,
)


# ------------------------------------------------------------------
# ForensicReport data class (assembled by Correlator)
# ------------------------------------------------------------------

@dataclass
class ForensicReport:
    """Final assembled report across all phases."""
    findings: list[Finding]
    iocs: list[IOC]
    timeline: list[TimelineEvent]
    mitre_mappings: list[MITREMapping]
    network_hosts: list[NetworkHost]
    kill_chain_phases: list[str]
    recommendations: list[str]
    executive_summary: str


class Correlator:
    """Cross-phase correlation: merge IOCs, build timeline, map MITRE,
    generate network topology."""

    def __init__(
        self,
        phase_results: list[PhaseResult],
        network_hosts: list[NetworkHost],
    ):
        self.phase_results = phase_results
        self.network_hosts = network_hosts

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------

    def run(self) -> ForensicReport:
        print("\n[Correlator] Cross-phase correlation in progress...")

        # 1. Merge and deduplicate IOCs
        merged_iocs = self._merge_iocs()
        print(f"  [Correlator] Merged IOCs: {len(merged_iocs)}")

        # 2. Merge and sort timeline events
        merged_timeline = self._merge_timeline()
        print(f"  [Correlator] Merged timeline events: {len(merged_timeline)}")

        # 3. Merge and deduplicate MITRE mappings
        merged_mitre = self._merge_mitre()
        print(f"  [Correlator] Unique MITRE techniques: {len(merged_mitre)}")

        # 4. Determine kill chain progression
        kill_chain = self._determine_kill_chain(merged_timeline, merged_mitre)
        print(f"  [Correlator] Kill chain phases observed: {', '.join(kill_chain) if kill_chain else 'none'}")

        # 5. Collect all findings
        all_findings = self._collect_findings()
        print(f"  [Correlator] Total findings: {len(all_findings)}")

        # 6. Generate recommendations
        recommendations = self._generate_recommendations(all_findings, merged_iocs, merged_mitre)

        # 7. Build executive summary
        executive_summary = self._build_executive_summary(
            all_findings, merged_iocs, merged_timeline, kill_chain,
        )

        # 8. Enrich network hosts with IOC data
        self._enrich_network_hosts(merged_iocs)

        report = ForensicReport(
            findings=all_findings,
            iocs=merged_iocs,
            timeline=merged_timeline,
            mitre_mappings=merged_mitre,
            network_hosts=self.network_hosts,
            kill_chain_phases=kill_chain,
            recommendations=recommendations,
            executive_summary=executive_summary,
        )

        print(f"  [Correlator] Forensic report assembled.")
        return report

    # ------------------------------------------------------------------
    # Step 1: Merge IOCs
    # ------------------------------------------------------------------

    def _merge_iocs(self) -> list[IOC]:
        """Merge all IOCs from all phases, dedup by (type, value)."""
        seen: dict[tuple[IOCType, str], IOC] = {}

        for pr in self.phase_results:
            for ioc in pr.iocs:
                key = (ioc.type, ioc.value)
                if key in seen:
                    existing = seen[key]
                    # Update last_seen if the new IOC is later
                    if ioc.last_seen and (not existing.last_seen or ioc.last_seen > existing.last_seen):
                        seen[key] = IOC(
                            type=existing.type,
                            value=existing.value,
                            context=existing.context + " | " + ioc.context,
                            first_seen=existing.first_seen or ioc.first_seen,
                            last_seen=ioc.last_seen,
                            source_phase=existing.source_phase + "," + ioc.source_phase,
                        )
                else:
                    seen[key] = ioc

        return list(seen.values())

    # ------------------------------------------------------------------
    # Step 2: Merge timeline
    # ------------------------------------------------------------------

    def _merge_timeline(self) -> list[TimelineEvent]:
        """Merge all timeline events from all phases, sort chronologically."""
        events: list[TimelineEvent] = []
        for pr in self.phase_results:
            events.extend(pr.timeline_events)

        events.sort(key=lambda e: e.timestamp)
        return events

    # ------------------------------------------------------------------
    # Step 3: Merge MITRE mappings
    # ------------------------------------------------------------------

    def _merge_mitre(self) -> list[MITREMapping]:
        """Merge all MITRE mappings, dedup by technique_id."""
        seen: dict[str, MITREMapping] = {}

        for pr in self.phase_results:
            for finding in pr.findings:
                for mm in finding.mitre_mappings:
                    if mm.technique_id not in seen:
                        seen[mm.technique_id] = mm
                    else:
                        # Combine observed_evidence
                        existing = seen[mm.technique_id]
                        combined_evidence = existing.observed_evidence
                        if mm.observed_evidence and mm.observed_evidence not in combined_evidence:
                            combined_evidence += " | " + mm.observed_evidence
                        seen[mm.technique_id] = MITREMapping(
                            tactic=existing.tactic,
                            technique=existing.technique,
                            technique_id=existing.technique_id,
                            observed_evidence=combined_evidence,
                        )

        return list(seen.values())

    # ------------------------------------------------------------------
    # Step 4: Kill chain progression
    # ------------------------------------------------------------------

    def _determine_kill_chain(
        self,
        timeline: list[TimelineEvent],
        mitre: list[MITREMapping],
    ) -> list[str]:
        """Map observed activity to Lockheed Martin Cyber Kill Chain phases."""
        # Define mappings from MITRE tactics to kill-chain phases
        tactic_to_killchain: dict[str, str] = {
            "Reconnaissance": "Reconnaissance",
            "Resource Development": "Weaponization",
            "Initial Access": "Delivery",
            "Execution": "Exploitation",
            "Persistence": "Installation",
            "Privilege Escalation": "Installation",
            "Defense Evasion": "Installation",
            "Credential Access": "Exploitation",
            "Discovery": "Exploitation",
            "Lateral Movement": "Installation",
            "Collection": "Actions on Objectives",
            "Command and Control": "Command & Control",
            "Exfiltration": "Actions on Objectives",
            "Impact": "Actions on Objectives",
        }

        # Also infer from phase names in timeline
        phase_to_killchain: dict[str, str] = {
            "initial_access": "Delivery",
            "lateral_movement": "Installation",
            "exfiltration": "Actions on Objectives",
            "payload": "Exploitation",
        }

        observed_kc: set[str] = set()

        for mm in mitre:
            kc = tactic_to_killchain.get(mm.tactic)
            if kc:
                observed_kc.add(kc)

        for evt in timeline:
            kc = phase_to_killchain.get(evt.phase)
            if kc:
                observed_kc.add(kc)

        # Order the kill chain phases
        ordered = [
            "Reconnaissance",
            "Weaponization",
            "Delivery",
            "Exploitation",
            "Installation",
            "Command & Control",
            "Actions on Objectives",
        ]

        return [phase for phase in ordered if phase in observed_kc]

    # ------------------------------------------------------------------
    # Step 5: Collect findings
    # ------------------------------------------------------------------

    def _collect_findings(self) -> list[Finding]:
        """Collect all findings from all phases, sorted by severity."""
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        all_findings: list[Finding] = []
        for pr in self.phase_results:
            all_findings.extend(pr.findings)

        all_findings.sort(key=lambda f: severity_order.get(f.severity, 99))
        return all_findings

    # ------------------------------------------------------------------
    # Step 6: Recommendations
    # ------------------------------------------------------------------

    def _generate_recommendations(
        self,
        findings: list[Finding],
        iocs: list[IOC],
        mitre: list[MITREMapping],
    ) -> list[str]:
        """Generate actionable recommendations based on findings."""
        recommendations: list[str] = []

        # Severity-based recommendations
        crit_count = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        high_count = sum(1 for f in findings if f.severity == Severity.HIGH)

        if crit_count > 0:
            recommendations.append(
                f"IMMEDIATE: {crit_count} critical finding(s) require urgent incident response. "
                f"Isolate compromised hosts and begin containment procedures."
            )

        # IOC-based recommendations
        external_ips = [ioc for ioc in iocs if ioc.type == IOCType.IP and "external" in ioc.context.lower()]
        if external_ips:
            ip_list = ", ".join(ioc.value for ioc in external_ips[:10])
            recommendations.append(
                f"Block external attacker IP(s) at the perimeter firewall: {ip_list}."
            )

        exfil_domains = [ioc for ioc in iocs if ioc.type == IOCType.DOMAIN]
        if exfil_domains:
            domain_list = ", ".join(ioc.value for ioc in exfil_domains[:10])
            recommendations.append(
                f"Block exfiltration/C2 domains in DNS and proxy: {domain_list}."
            )

        compromised_accounts = [ioc for ioc in iocs if ioc.type == IOCType.ACCOUNT]
        if compromised_accounts:
            acct_list = ", ".join(ioc.value for ioc in compromised_accounts[:10])
            recommendations.append(
                f"Reset credentials for compromised accounts: {acct_list}."
            )

        # Technique-based recommendations
        technique_ids = {mm.technique_id for mm in mitre}

        if "T1110.003" in technique_ids:
            recommendations.append(
                "Implement account lockout policies and multi-factor authentication "
                "to prevent credential spraying attacks."
            )

        if "T1021.002" in technique_ids:
            recommendations.append(
                "Restrict SMB admin share access. Disable unnecessary ADMIN$ and C$ shares. "
                "Enforce least-privilege for domain accounts."
            )

        if "T1572" in technique_ids:
            recommendations.append(
                "Inspect and restrict HTTP CONNECT tunneling at the proxy. "
                "Deploy TLS inspection for outbound connections."
            )

        if "T1567.002" in technique_ids:
            recommendations.append(
                "Block or monitor access to cloud storage/file-sharing services. "
                "Implement DLP controls for sensitive data."
            )

        if "T1486" in technique_ids:
            recommendations.append(
                "Verify backup integrity. Ensure offline/immutable backups exist. "
                "Prepare ransomware response playbook."
            )

        if "T1558" in technique_ids:
            recommendations.append(
                "Rotate the KRBTGT account password twice. Review Kerberos delegation "
                "settings and monitor for abnormal TGT requests."
            )

        if not recommendations:
            recommendations.append(
                "Continue monitoring. No critical actions required based on current findings."
            )

        return recommendations

    # ------------------------------------------------------------------
    # Step 7: Executive summary
    # ------------------------------------------------------------------

    def _build_executive_summary(
        self,
        findings: list[Finding],
        iocs: list[IOC],
        timeline: list[TimelineEvent],
        kill_chain: list[str],
    ) -> str:
        """Build a concise executive summary paragraph."""
        severity_counts = {}
        for f in findings:
            severity_counts[f.severity.name] = severity_counts.get(f.severity.name, 0) + 1

        ioc_type_counts = {}
        for ioc in iocs:
            ioc_type_counts[ioc.type.name] = ioc_type_counts.get(ioc.type.name, 0) + 1

        time_range_str = ""
        if timeline:
            earliest = min(e.timestamp for e in timeline if e.timestamp > 0)
            latest = max(e.timestamp for e in timeline if e.timestamp > 0)
            if earliest and latest:
                time_range_str = f" spanning {epoch_to_utc(earliest)} to {epoch_to_utc(latest)}"

        sev_str = ", ".join(f"{count} {name}" for name, count in severity_counts.items())
        ioc_str = ", ".join(f"{count} {name}" for name, count in ioc_type_counts.items())

        summary = (
            f"Forensic analysis identified {len(findings)} finding(s) ({sev_str}) "
            f"and {len(iocs)} indicator(s) of compromise ({ioc_str}){time_range_str}. "
            f"The attack progressed through {len(kill_chain)} kill chain phase(s): "
            f"{', '.join(kill_chain)}. "
            f"{len(timeline)} discrete events were recorded in the timeline."
        )

        return summary

    # ------------------------------------------------------------------
    # Enrich network hosts
    # ------------------------------------------------------------------

    def _enrich_network_hosts(self, iocs: list[IOC]) -> None:
        """Update network host records with IOC context."""
        ip_iocs = {ioc.value: ioc for ioc in iocs if ioc.type == IOCType.IP}
        for host in self.network_hosts:
            if host.ip in ip_iocs:
                ioc = ip_iocs[host.ip]
                # Mark the host role based on IOC context
                if "patient zero" in ioc.context.lower():
                    host.role = "patient_zero"
                elif "staging server" in ioc.context.lower():
                    host.role = "staging_server"
                elif "lateral" in ioc.context.lower():
                    host.role = "compromised"

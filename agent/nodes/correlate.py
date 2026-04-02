"""Correlate node — merge findings, IOCs, timeline from the investigation."""
from __future__ import annotations

from ..models import (
    IOC, IOCType, TimelineEvent, MITREMapping, Finding, Severity,
    Evidence, NetworkHost, ForensicReport, epoch_to_utc,
)
from ..state import ForensicState


def _parse_severity(s: str) -> Severity:
    try:
        return Severity(s.lower())
    except (ValueError, KeyError):
        return Severity.MEDIUM


def _parse_ioc_type(t: str) -> IOCType:
    if not t or t.startswith("<"):
        return IOCType.IP
    try:
        return IOCType(t.lower())
    except ValueError:
        return IOCType.IP


def correlate_node(state: ForensicState) -> dict:
    """Merge and deduplicate findings, IOCs, timeline, and MITRE mappings."""
    print("[CORRELATE] Cross-referencing investigation results...")

    raw_findings = state.get("findings", [])
    raw_iocs = state.get("iocs", [])
    raw_timeline = state.get("timeline_events", [])

    # --- Deduplicate raw findings by ID ---
    seen_finding_ids: set[str] = set()
    deduped_findings: list[dict] = []
    for f in raw_findings:
        fid = f.get("id", "")
        if fid and fid in seen_finding_ids:
            continue
        seen_finding_ids.add(fid)
        deduped_findings.append(f)
    raw_findings = deduped_findings

    # --- Build Finding objects ---
    findings: list[Finding] = []
    mitre_mappings: list[MITREMapping] = []

    for f in raw_findings:
        mitre_maps = []
        if f.get("mitre_id"):
            mm = MITREMapping(
                tactic=f.get("mitre_tactic", ""),
                technique=f.get("mitre_technique", ""),
                technique_id=f.get("mitre_id", ""),
                observed_evidence=f.get("evidence_description", ""),
            )
            mitre_maps.append(mm)
            mitre_mappings.append(mm)

        evidence = []
        if f.get("evidence_log"):
            evidence.append(Evidence(
                source_log=f["evidence_log"],
                description=f.get("evidence_description", ""),
                search_query=f"line {f['evidence_line']}" if f.get("evidence_line") else "",
            ))

        findings.append(Finding(
            id=f.get("id", "?"),
            title=f.get("title", "Untitled"),
            finding_text=f.get("description", ""),
            severity=_parse_severity(f.get("severity", "medium")),
            evidence=evidence,
            mitre_mappings=mitre_maps,
        ))

    # Sort by severity
    severity_order = {
        Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2,
        Severity.LOW: 3, Severity.INFO: 4,
    }
    findings.sort(key=lambda f: severity_order.get(f.severity, 99))

    # --- Build IOC objects (dedup) ---
    seen_iocs: dict[tuple[str, str], dict] = {}
    for ioc in raw_iocs:
        key = (ioc.get("type", ""), ioc.get("value", ""))
        if key not in seen_iocs:
            seen_iocs[key] = ioc
    iocs = [
        IOC(
            type=_parse_ioc_type(d.get("type", "ip")),
            value=d.get("value", ""),
            context=d.get("context", ""),
            source_phase=d.get("source_phase", ""),
        )
        for d in seen_iocs.values()
    ]

    # --- Build timeline (dedup and sort) ---
    timeline: list[TimelineEvent] = []
    seen_tl_keys: set[tuple] = set()
    for evt in raw_timeline:
        ts_raw = evt.get("timestamp", "0")
        try:
            ts_float = float(ts_raw)
            ts_human = epoch_to_utc(ts_float)
        except (ValueError, TypeError):
            ts_float = 0.0
            ts_human = str(ts_raw)

        tl_key = (ts_raw, evt.get("source_ip", ""), evt.get("dest_ip", ""))
        if tl_key in seen_tl_keys:
            continue
        seen_tl_keys.add(tl_key)

        timeline.append(TimelineEvent(
            timestamp=ts_float,
            timestamp_human=ts_human,
            source_ip=evt.get("source_ip", ""),
            dest_ip=evt.get("dest_ip", ""),
            phase=evt.get("phase", ""),
            description=evt.get("description", ""),
            mitre_id=evt.get("mitre_id", ""),
        ))
    timeline.sort(key=lambda e: e.timestamp)

    # --- Deduplicate MITRE mappings ---
    seen_mitre: dict[str, MITREMapping] = {}
    for mm in mitre_mappings:
        if mm.technique_id and mm.technique_id not in seen_mitre:
            seen_mitre[mm.technique_id] = mm
    unique_mitre = list(seen_mitre.values())

    # --- Kill chain ---
    tactic_to_kc = {
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
    kc_phases = set()
    for mm in unique_mitre:
        kc = tactic_to_kc.get(mm.tactic)
        if kc:
            kc_phases.add(kc)
    kc_ordered = [
        p for p in [
            "Reconnaissance", "Weaponization", "Delivery", "Exploitation",
            "Installation", "Command & Control", "Actions on Objectives",
        ] if p in kc_phases
    ]

    # --- Executive summary (deterministic) ---
    sev_counts = {}
    for f in findings:
        sev_counts[f.severity.name] = sev_counts.get(f.severity.name, 0) + 1
    sev_str = ", ".join(f"{c} {n}" for n, c in sev_counts.items())

    summary = (
        f"Autonomous forensic analysis identified {len(findings)} finding(s) ({sev_str}) "
        f"and {len(iocs)} indicator(s) of compromise. "
        f"The attack progressed through {len(kc_ordered)} kill chain phase(s): "
        f"{', '.join(kc_ordered) if kc_ordered else 'none identified'}. "
        f"{len(timeline)} discrete events were recorded."
    )

    # --- Recommendations ---
    recommendations = []
    crit_count = sum(1 for f in findings if f.severity == Severity.CRITICAL)
    if crit_count:
        recommendations.append(
            f"IMMEDIATE: {crit_count} critical finding(s) require urgent incident response."
        )
    ext_ips = [i for i in iocs if i.type == IOCType.IP]
    if ext_ips:
        ips = ", ".join(i.value for i in ext_ips[:10])
        recommendations.append(f"Block attacker IP(s) at perimeter firewall: {ips}.")
    domains = [i for i in iocs if i.type == IOCType.DOMAIN]
    if domains:
        ds = ", ".join(i.value for i in domains[:10])
        recommendations.append(f"Block exfiltration/C2 domains: {ds}.")
    accounts = [i for i in iocs if i.type == IOCType.ACCOUNT]
    if accounts:
        accts = ", ".join(i.value for i in accounts[:10])
        recommendations.append(f"Reset credentials for: {accts}.")
    if not recommendations:
        recommendations.append("Continue monitoring. No critical actions required.")

    print(f"[CORRELATE] {len(findings)} findings, {len(iocs)} IOCs, "
          f"{len(timeline)} timeline events, {len(unique_mitre)} MITRE techniques")

    return {
        "kill_chain_phases": kc_ordered,
        "executive_summary": summary,
        "recommendations": recommendations,
        # These are stored as model objects in the state for the report node
        "_correlated_findings": findings,
        "_correlated_iocs": iocs,
        "_correlated_timeline": timeline,
        "_correlated_mitre": unique_mitre,
    }

"""LangChain @tool wrappers for analyzer-level (macro) tools.

Each macro tool runs a complete analysis phase using the existing analyzer
classes and returns a structured JSON summary of findings, IOCs, and
timeline events.
"""
from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from langchain_core.tools import tool

from ..config import Config
from ..models import LogFile, LogCategory, NetworkHost


MAX_FINDINGS_CHARS = 4000


def _serialize_phase_result(result) -> str:
    """Convert a PhaseResult to a JSON-friendly string, truncated to fit context."""
    data = {
        "phase": result.phase_name,
        "findings": [],
        "iocs": [],
        "timeline_events": [],
        "summary": result.summary or "",
    }

    for f in result.findings:
        finding_dict = {
            "id": f.id,
            "title": f.title,
            "finding_text": f.finding_text[:300],
            "severity": f.severity.value,
            "evidence_count": len(f.evidence),
            "mitre": [
                {"tactic": m.tactic, "technique_id": m.technique_id}
                for m in f.mitre_mappings
            ],
        }
        data["findings"].append(finding_dict)

    for ioc in result.iocs:
        data["iocs"].append({
            "type": ioc.type.value,
            "value": ioc.value,
            "context": ioc.context[:200],
            "source_phase": ioc.source_phase,
        })

    for evt in result.timeline_events[:50]:
        data["timeline_events"].append({
            "timestamp_human": evt.timestamp_human,
            "source_ip": evt.source_ip,
            "dest_ip": evt.dest_ip,
            "description": evt.description[:200],
            "mitre_id": evt.mitre_id,
        })

    out = json.dumps(data, indent=1, default=str)
    if len(out) > MAX_FINDINGS_CHARS:
        out = out[:MAX_FINDINGS_CHARS] + "\n[... truncated]"
    return out


def _build_inventory(log_dir: str, config: Config) -> list[LogFile]:
    """Build a log inventory from disk (lightweight — just lists files and parses headers)."""
    from ..tools.log_reader import ZeekLogReader

    log_path = Path(log_dir)
    inventory = []
    for lp in sorted(log_path.glob("*.log")):
        size = lp.stat().st_size
        if size < config.full_read_max:
            category = LogCategory.FULL_READ
        elif size < config.sample_grep_max:
            category = LogCategory.SAMPLE_GREP
        else:
            category = LogCategory.GREP_ONLY

        try:
            rdr = ZeekLogReader(lp)
            fields = rdr.fields
            types = rdr.types
            line_count = rdr.count_data_lines()
        except Exception:
            fields, types, line_count = [], [], 0

        inventory.append(LogFile(
            name=lp.name,
            path=lp,
            size=size,
            category=category,
            fields=fields,
            types=types,
            line_count=line_count,
        ))
    return inventory


def build_macro_tools(
    log_dir: str,
    internal_subnet: str,
    network_hosts_dicts: list[dict],
    state_ref: dict = None,
):
    """Return a list of LangChain tools for phase-level analysis."""
    config = Config()
    if internal_subnet:
        config.internal_subnets = [internal_subnet]

    # Reconstruct NetworkHost objects from state dicts
    hosts = [
        NetworkHost(
            ip=h.get("ip", ""),
            hostname=h.get("hostname", ""),
            role=h.get("role", ""),
            is_internal=h.get("is_internal", True),
            associated_accounts=h.get("associated_accounts", []),
        )
        for h in network_hosts_dicts
    ]

    def _dictify(result):
        findings = []
        for f in result.findings:
            mid, mtac = "", ""
            if f.mitre_mappings:
                mid = f.mitre_mappings[0].technique_id
                mtac = f.mitre_mappings[0].tactic
            elog, edesc = "", ""
            if f.evidence:
                elog = f.evidence[0].source_log
                edesc = f.evidence[0].description
            findings.append({
                "id": f.id or "A1",
                "title": f.title,
                "description": f.finding_text,
                "severity": f.severity.value if hasattr(f.severity, 'value') else str(f.severity),
                "evidence_log": elog,
                "evidence_description": edesc,
                "evidence_line": None,
                "mitre_tactic": mtac,
                "mitre_technique": "",
                "mitre_id": mid,
            })
        
        iocs = []
        for i in result.iocs:
            iocs.append({
                "type": i.type.value if hasattr(i.type, 'value') else str(i.type),
                "value": i.value,
                "context": i.context,
                "source_phase": i.source_phase,
            })
            
        timeline = []
        for t in result.timeline_events:
            timeline.append({
                "timestamp": t.timestamp_human,
                "description": t.description,
                "source_ip": t.source_ip,
                "dest_ip": t.dest_ip,
                "phase": result.phase_name,
                "mitre_id": t.mitre_id,
            })
            
        return findings, iocs, timeline

    @tool
    def run_initial_access_analysis() -> str:
        """Run a complete initial access analysis. Detects external RDP, C2 tunnels, HTTP CONNECT, protocol anomalies, suspicious user-agents, and identifies Patient Zero."""
        from ..analyzers.initial_access import InitialAccessAnalyzer
        inventory = _build_inventory(log_dir, config)
        analyzer = InitialAccessAnalyzer(inventory, config, hosts)
        result = analyzer.run()
        if state_ref is not None:
            fnd, ioc, tl = _dictify(result)
            state_ref["findings"].extend(fnd)
            state_ref["iocs"].extend(ioc)
            state_ref["timeline_events"].extend(tl)
        return f"Initial Access Analysis Complete:\n{_serialize_phase_result(result)}"

    @tool
    def run_lateral_movement_analysis() -> str:
        """Run a complete lateral movement analysis. Detects credential spray, NTLM lateral movement, SAMR enumeration, Kerberos anomalies, SMB share access, SOCKS chains, and internal WinRM."""
        from ..analyzers.lateral import LateralMovementAnalyzer
        inventory = _build_inventory(log_dir, config)
        analyzer = LateralMovementAnalyzer(inventory, config, [])
        result = analyzer.run()
        if state_ref is not None:
            fnd, ioc, tl = _dictify(result)
            state_ref["findings"].extend(fnd)
            state_ref["iocs"].extend(ioc)
            state_ref["timeline_events"].extend(tl)
        return f"Lateral Movement Analysis Complete:\n{_serialize_phase_result(result)}"

    @tool
    def run_exfiltration_analysis() -> str:
        """Run a complete exfiltration analysis. Detects DNS lookups to exfiltration services, SSL sessions to exfil destinations, IP reconnaissance service access, and file transfer tool usage."""
        from ..analyzers.exfiltration import ExfiltrationAnalyzer
        inventory = _build_inventory(log_dir, config)
        analyzer = ExfiltrationAnalyzer(inventory, config, [])
        result = analyzer.run()
        if state_ref is not None:
            fnd, ioc, tl = _dictify(result)
            state_ref["findings"].extend(fnd)
            state_ref["iocs"].extend(ioc)
            state_ref["timeline_events"].extend(tl)
        return f"Exfiltration Analysis Complete:\n{_serialize_phase_result(result)}"

    @tool
    def run_payload_analysis() -> str:
        """Run a complete payload analysis. Detects SMB-transferred executables, PE metadata, GPO access, and suspicious SMB file patterns."""
        from ..analyzers.payload import PayloadAnalyzer
        inventory = _build_inventory(log_dir, config)
        analyzer = PayloadAnalyzer(inventory, config, [])
        result = analyzer.run()
        if state_ref is not None:
            fnd, ioc, tl = _dictify(result)
            state_ref["findings"].extend(fnd)
            state_ref["iocs"].extend(ioc)
            state_ref["timeline_events"].extend(tl)
        return f"Payload Analysis Complete:\n{_serialize_phase_result(result)}"

    return [
        run_initial_access_analysis,
        run_lateral_movement_analysis,
        run_exfiltration_analysis,
        run_payload_analysis,
    ]

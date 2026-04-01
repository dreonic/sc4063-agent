"""State-mutation tools — the agent calls these to record findings, IOCs,
timeline events, and to signal investigation completion.

These tools include strict evidence validation guardrails. If the agent
cites a log file or line number that doesn't exist, the tool rejects
the call and returns an error forcing the agent to self-correct.
"""
from __future__ import annotations

import json
from typing import Any

from langchain_core.tools import tool

from ..guardrails.validators import (
    validate_evidence_log,
    validate_evidence_line,
    validate_severity,
    validate_mitre_id,
    validate_ioc,
)

# These get populated at construction time by build_state_tools()
_state_ref: dict[str, Any] = {}


def build_state_tools(state_ref: dict[str, Any]):
    """Build state-mutation tools bound to a mutable state reference.

    ``state_ref`` must contain at minimum:
    - ``log_dir``: str
    - ``log_inventory``: list[dict]
    - ``findings``: list[dict]  (mutable — tools append to this)
    - ``iocs``: list[dict]
    - ``timeline_events``: list[dict]
    - ``investigation_notes``: list[str]
    - ``investigation_complete``: bool (set by mark_investigation_complete)
    """
    ref = state_ref

    _finding_counter = [0]

    @tool
    def record_finding(
        title: str,
        description: str,
        severity: str,
        evidence_log: str,
        evidence_description: str,
        mitre_tactic: str = "",
        mitre_technique: str = "",
        mitre_id: str = "",
        evidence_line: int | None = None,
    ) -> str:
        """Record a forensic finding with evidence. The cited evidence_log MUST exist in the log inventory. If evidence_line is provided, it will be verified against the actual file content. Returns success or an error message requiring correction.

        Args:
            title: Short title for the finding.
            description: Detailed description of what was found.
            severity: One of: critical, high, medium, low, info.
            evidence_log: The Zeek log file name that contains the evidence.
            evidence_description: Description of what was found in the evidence.
            mitre_tactic: MITRE ATT&CK tactic (e.g., "Initial Access").
            mitre_technique: MITRE ATT&CK technique name.
            mitre_id: MITRE technique ID (e.g., "T1133").
            evidence_line: Optional specific line number in the log file.
        """
        # Validate evidence log exists
        err = validate_evidence_log(
            evidence_log, ref["log_dir"], ref["log_inventory"]
        )
        if err:
            return f"REJECTED: {err}"

        # Validate evidence line if specified
        err = validate_evidence_line(
            evidence_log, evidence_line, evidence_description, ref["log_dir"]
        )
        if err:
            return f"REJECTED: {err}"

        # Validate severity
        err = validate_severity(severity)
        if err:
            return f"REJECTED: {err}"

        # Validate MITRE ID
        err = validate_mitre_id(mitre_id)
        if err:
            return f"REJECTED: {err}"

        _finding_counter[0] += 1
        finding_id = chr(64 + _finding_counter[0]) if _finding_counter[0] <= 26 else str(_finding_counter[0])

        finding = {
            "id": finding_id,
            "title": title,
            "description": description,
            "severity": severity.lower(),
            "evidence_log": evidence_log,
            "evidence_description": evidence_description,
            "evidence_line": evidence_line,
            "mitre_tactic": mitre_tactic,
            "mitre_technique": mitre_technique,
            "mitre_id": mitre_id,
        }
        ref["findings"].append(finding)
        return f"Finding '{finding_id}: {title}' recorded successfully (severity: {severity})."

    @tool
    def record_ioc(
        ioc_type: str,
        value: str,
        context: str = "",
        source_phase: str = "investigation",
    ) -> str:
        """Record an Indicator of Compromise. Type must be one of: ip, domain, hash, account, filename. IP and domain values are validated.

        Args:
            ioc_type: Type of IOC — ip, domain, hash, account, or filename.
            value: The IOC value (e.g., an IP address, domain name, username).
            context: Brief context about this IOC.
            source_phase: Which phase discovered this IOC.
        """
        err = validate_ioc(ioc_type, value)
        if err:
            return f"REJECTED: {err}"

        # Dedup check
        for existing in ref["iocs"]:
            if existing.get("type") == ioc_type.lower() and existing.get("value") == value:
                return f"IOC already recorded: {ioc_type}/{value} (dedup)."

        ioc = {
            "type": ioc_type.lower(),
            "value": value,
            "context": context,
            "source_phase": source_phase,
        }
        ref["iocs"].append(ioc)
        return f"IOC recorded: [{ioc_type}] {value}"

    @tool
    def record_timeline_event(
        timestamp: str,
        description: str,
        source_ip: str = "",
        dest_ip: str = "",
        phase: str = "investigation",
        mitre_id: str = "",
    ) -> str:
        """Record a timeline event for the attack chronology.

        Args:
            timestamp: The timestamp (epoch float as string, or human-readable).
            description: What happened at this time.
            source_ip: Source IP address.
            dest_ip: Destination IP address.
            phase: Which investigation phase this belongs to.
            mitre_id: Optional MITRE technique ID.
        """
        event = {
            "timestamp": timestamp,
            "description": description,
            "source_ip": source_ip,
            "dest_ip": dest_ip,
            "phase": phase,
            "mitre_id": mitre_id,
        }
        ref["timeline_events"].append(event)
        return f"Timeline event recorded: {description[:80]}"

    @tool
    def mark_investigation_complete() -> str:
        """Signal that the investigation is complete. Call this when you have thoroughly analyzed all relevant logs and recorded all findings."""
        ref["investigation_complete"] = True
        n_findings = len(ref["findings"])
        n_iocs = len(ref["iocs"])
        n_events = len(ref["timeline_events"])
        return (
            f"Investigation marked complete. "
            f"Summary: {n_findings} findings, {n_iocs} IOCs, {n_events} timeline events."
        )

    return [
        record_finding,
        record_ioc,
        record_timeline_event,
        mark_investigation_complete,
    ]

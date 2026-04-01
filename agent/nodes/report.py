"""Report node — generate the final Markdown forensic report."""
from __future__ import annotations

from pathlib import Path

from langchain_openai import ChatOpenAI

from ..config import Config
from ..llm.prompts import EXECUTIVE_SUMMARY_PROMPT, FORENSIC_SYSTEM_PROMPT
from ..models import (
    ForensicReport, LogFile, LogCategory, NetworkHost,
    Finding, IOC, IOCType, TimelineEvent, MITREMapping,
    Evidence, Severity,
)
from ..report.generator import ReportGenerator
from ..state import ForensicState


def _rebuild_log_inventory(inventory_dicts: list[dict]) -> list[LogFile]:
    """Convert serialised log inventory back to LogFile objects."""
    logs = []
    for d in inventory_dicts:
        cat_str = d.get("category", "full_read")
        try:
            cat = LogCategory(cat_str)
        except (ValueError, KeyError):
            cat = LogCategory.FULL_READ
        logs.append(LogFile(
            name=d.get("name", ""),
            path=Path(d.get("path", "")),
            size=d.get("size", 0),
            category=cat,
            fields=d.get("fields", []),
            types=d.get("types", []),
            line_count=d.get("line_count", 0),
        ))
    return logs


def _rebuild_hosts(host_dicts: list[dict]) -> list[NetworkHost]:
    """Convert serialised hosts back to NetworkHost objects."""
    return [
        NetworkHost(
            ip=h.get("ip", ""),
            hostname=h.get("hostname", ""),
            role=h.get("role", ""),
            is_internal=h.get("is_internal", True),
            associated_accounts=h.get("associated_accounts", []),
        )
        for h in host_dicts
    ]


def report_node(state: ForensicState) -> dict:
    """Generate the final Markdown forensic report and optionally enhance
    the executive summary with an LLM call."""
    config = Config()

    # Get correlated objects (set by correlate node)
    findings = state.get("_correlated_findings", [])
    iocs = state.get("_correlated_iocs", [])
    timeline = state.get("_correlated_timeline", [])
    mitre = state.get("_correlated_mitre", [])

    # Rebuild structured objects from state
    log_inventory = _rebuild_log_inventory(state.get("log_inventory", []))
    network_hosts = _rebuild_hosts(state.get("network_hosts", []))

    # Attempt LLM-enhanced executive summary
    executive_summary = state.get("executive_summary", "")
    try:
        llm = ChatOpenAI(
            model=config.llm_model,
            base_url=config.llm_base_url,
            api_key=config.llm_api_key,
            temperature=config.llm_temperature,
        )
        findings_text = "\n".join(
            f"- [{f.severity.value.upper()}] {f.title}: {f.finding_text[:200]}"
            for f in findings[:20]
        )
        iocs_text = "\n".join(
            f"- [{i.type.value}] {i.value}: {i.context}" for i in iocs[:20]
        )
        prompt = (
            f"{EXECUTIVE_SUMMARY_PROMPT}\n\n"
            f"## Findings:\n{findings_text}\n\n"
            f"## IOCs:\n{iocs_text}\n\n"
            f"## Kill Chain Phases: {', '.join(state.get('kill_chain_phases', []))}"
        )
        from langchain_core.messages import SystemMessage, HumanMessage
        response = llm.invoke([
            SystemMessage(content=FORENSIC_SYSTEM_PROMPT),
            HumanMessage(content=prompt),
        ])
        executive_summary = response.content
        print("[REPORT] LLM executive summary generated.")
    except Exception as e:
        print(f"[REPORT] LLM summary failed ({e}), using deterministic summary.")

    # Build the report object
    report = ForensicReport(
        findings=findings,
        all_iocs=iocs,
        timeline=timeline,
        mitre_mappings=mitre,
        network_hosts=network_hosts,
        log_inventory=log_inventory,
        internal_subnet=state.get("internal_subnet", ""),
        domain=state.get("domain", ""),
        executive_summary=executive_summary,
        recommendations=state.get("recommendations", []),
        kill_chain_phases=state.get("kill_chain_phases", []),
        cost_metrics=state.get("cost_metrics", {}),
        investigation_notes=state.get("investigation_notes", []),
    )

    # Generate and save
    config.output_dir.mkdir(parents=True, exist_ok=True)
    output_path = config.output_dir / config.report_filename

    generator = ReportGenerator(report)
    generator.save(output_path)

    print(f"[REPORT] Saved to {output_path}")

    return {
        "report_path": str(output_path),
        "executive_summary": executive_summary,
    }

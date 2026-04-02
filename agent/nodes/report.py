"""Report node — generate the final Markdown forensic report."""
from __future__ import annotations

import json
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


CHARS_PER_TOKEN_ESTIMATE = 4


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


def _estimate_tokens_from_text(text: str) -> int:
    """Approximate token count when provider metadata is unavailable."""
    if not text:
        return 0
    return max(1, (len(text) + CHARS_PER_TOKEN_ESTIMATE - 1) // CHARS_PER_TOKEN_ESTIMATE)


def _extract_usage_tokens(response) -> tuple[int, int]:
    """Extract input/output token counts across common response schemas."""
    usage_candidates: list[dict] = []

    usage = getattr(response, "usage_metadata", None)
    if isinstance(usage, dict):
        usage_candidates.append(usage)

    response_metadata = getattr(response, "response_metadata", None)
    if isinstance(response_metadata, dict):
        for key in ("token_usage", "usage", "usage_metadata"):
            value = response_metadata.get(key)
            if isinstance(value, dict):
                usage_candidates.append(value)

    additional_kwargs = getattr(response, "additional_kwargs", None)
    if isinstance(additional_kwargs, dict):
        for key in ("token_usage", "usage"):
            value = additional_kwargs.get(key)
            if isinstance(value, dict):
                usage_candidates.append(value)

    for candidate in usage_candidates:
        input_tokens = candidate.get("input_tokens")
        if input_tokens is None:
            input_tokens = candidate.get("prompt_tokens")
        if input_tokens is None:
            input_tokens = candidate.get("input_token_count")
        if input_tokens is None:
            input_tokens = candidate.get("prompt_token_count")

        output_tokens = candidate.get("output_tokens")
        if output_tokens is None:
            output_tokens = candidate.get("completion_tokens")
        if output_tokens is None:
            output_tokens = candidate.get("output_token_count")
        if output_tokens is None:
            output_tokens = candidate.get("completion_token_count")

        try:
            in_tok = int(input_tokens or 0)
            out_tok = int(output_tokens or 0)
        except (TypeError, ValueError):
            continue

        if in_tok > 0 or out_tok > 0:
            return in_tok, out_tok

    return 0, 0


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
    cost_metrics = dict(state.get("cost_metrics", {}))

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
        import re as _re
        raw = response.content or ""

        # Strip <think>...</think> tags (matched pair or orphaned closing tag)
        cleaned = _re.sub(r"<think>.*?</think>", "", raw, flags=_re.DOTALL)
        if "</think>" in cleaned:
            cleaned = cleaned[cleaned.index("</think>") + len("</think>"):]
        cleaned = cleaned.replace("<think>", "").strip()

        # Some models output "Thinking Process:" or numbered planning sections
        # before the actual answer. The real content starts at the first
        # recognised section header we requested: **Incident Overview
        markers = ["**Incident Overview", "**Root Cause", "**Impact Scope", "**Key Timeline"]
        for marker in markers:
            idx = cleaned.find(marker)
            if idx != -1:
                cleaned = cleaned[idx:].strip()
                break

        executive_summary = cleaned or raw

        # Record token accounting for the report LLM call.
        input_tokens, output_tokens = _extract_usage_tokens(response)
        if input_tokens == 0 and output_tokens == 0:
            input_tokens = _estimate_tokens_from_text(FORENSIC_SYSTEM_PROMPT) + _estimate_tokens_from_text(prompt)
            output_tokens = _estimate_tokens_from_text(str(response.content))

        cost_metrics["total_llm_calls"] = int(cost_metrics.get("total_llm_calls", 0)) + 1
        cost_metrics["total_input_tokens"] = int(cost_metrics.get("total_input_tokens", 0)) + input_tokens
        cost_metrics["total_output_tokens"] = int(cost_metrics.get("total_output_tokens", 0)) + output_tokens
        cost_metrics["api_cost"] = round(
            (cost_metrics["total_input_tokens"] / 1000) * config.api_input_cost_per_1k
            + (cost_metrics["total_output_tokens"] / 1000) * config.api_output_cost_per_1k,
            4,
        )

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
        cost_metrics=cost_metrics,
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
        "cost_metrics": cost_metrics,
    }

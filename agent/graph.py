"""LangGraph StateGraph definition for the forensic analysis pipeline.

Architecture:
    START → ingest → triage → investigate → correlate → [human_review?] → report → END

The investigate node runs a ReAct loop internally; the graph itself does not
loop — all iteration happens inside the node.  The only human-in-the-loop
checkpoint is the optional interrupt between correlate and report, enabled
via the ``--human-review`` CLI flag.
"""
from __future__ import annotations

from typing import Literal

from langgraph.graph import StateGraph, START, END
from langgraph.checkpoint.memory import MemorySaver

from .state import ForensicState
from .nodes.ingest import ingest_node
from .nodes.triage import triage_node
from .nodes.investigate import investigate_node
from .nodes.correlate import correlate_node
from .nodes.report import report_node


# ---------------------------------------------------------------------------
# Human-review interrupt node
# ---------------------------------------------------------------------------

def human_review_node(state: ForensicState) -> dict:
    """Display a summary of findings and pause for operator approval.

    This node is only inserted into the graph when ``--human-review`` is
    passed on the CLI.  LangGraph's ``interrupt()`` mechanism suspends
    execution here so the operator can inspect findings before the report
    is generated.
    """
    from langgraph.types import interrupt  # type: ignore[import]

    findings = state.get("findings", [])
    iocs = state.get("iocs", [])
    kill_chain = state.get("kill_chain_phases", [])
    summary = state.get("executive_summary", "(no summary yet)")

    # Build a readable review block
    lines = [
        "",
        "=" * 70,
        "  HUMAN REVIEW — forensic investigation complete",
        "=" * 70,
        f"  Findings  : {len(findings)}",
        f"  IOCs      : {len(iocs)}",
        f"  Kill chain: {', '.join(kill_chain) if kill_chain else 'none identified'}",
        "",
        "  Executive summary (deterministic):",
        f"  {summary}",
        "",
        "  Top findings:",
    ]
    for f in findings[:5]:
        sev = f.get("severity", "?").upper()
        title = f.get("title", "Untitled")
        lines.append(f"    [{sev}] {title}")
    if len(findings) > 5:
        lines.append(f"    ... and {len(findings) - 5} more")
    lines += ["=" * 70, ""]
    print("\n".join(lines))

    interrupt("Review the findings above, then resume to generate the report.")
    return {}


# ---------------------------------------------------------------------------
# Graph factory
# ---------------------------------------------------------------------------

def build_graph(human_review: bool = False) -> "CompiledGraph":  # type: ignore[name-defined]
    """Build and compile the forensic analysis StateGraph.

    Args:
        human_review: If True, insert a ``human_review`` interrupt node
                      between correlate and report.

    Returns:
        A compiled LangGraph graph ready to invoke.
    """
    builder = StateGraph(ForensicState)

    # --- Add all nodes ---
    builder.add_node("ingest", ingest_node)
    builder.add_node("triage", triage_node)
    builder.add_node("investigate", investigate_node)
    builder.add_node("correlate", correlate_node)
    builder.add_node("report", report_node)

    if human_review:
        builder.add_node("human_review", human_review_node)

    # --- Wire edges ---
    builder.add_edge(START, "ingest")
    builder.add_edge("ingest", "triage")
    builder.add_edge("triage", "investigate")
    builder.add_edge("investigate", "correlate")

    if human_review:
        builder.add_edge("correlate", "human_review")
        builder.add_edge("human_review", "report")
    else:
        builder.add_edge("correlate", "report")

    builder.add_edge("report", END)

    # Use an in-memory checkpointer so interrupt/resume works
    memory = MemorySaver()
    return builder.compile(checkpointer=memory)

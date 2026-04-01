"""ForensicState — the shared state flowing through the LangGraph."""
from __future__ import annotations

from operator import add
from typing import Annotated, TypedDict


class ForensicState(TypedDict, total=False):
    """Typed state for the forensic analysis graph.

    Fields annotated with ``Annotated[list, add]`` use LangGraph's reducer
    semantics: each node can *append* items rather than overwrite.
    """

    # --- Input ---
    input_path: str
    pcap_path: str                                    # original PCAP (for tshark tools)
    log_dir: str                                      # resolved Zeek log directory

    # --- Triage results ---
    log_inventory: list[dict]                         # serialised LogFile objects
    network_hosts: list[dict]                         # serialised NetworkHost objects
    internal_subnet: str
    domain: str

    # --- Accumulated investigation results (append-reducers) ---
    findings: Annotated[list[dict], add]
    iocs: Annotated[list[dict], add]
    timeline_events: Annotated[list[dict], add]
    mitre_mappings: Annotated[list[dict], add]
    investigation_notes: Annotated[list[str], add]    # reasoning audit trail

    # --- ReAct message history ---
    messages: Annotated[list, add]

    # --- Control ---
    iteration_count: int
    max_iterations: int
    investigation_complete: bool

    # --- Report ---
    kill_chain_phases: list[str]
    executive_summary: str
    recommendations: list[str]
    report_path: str
    cost_metrics: dict
    _correlated_findings: list
    _correlated_iocs: list
    _correlated_timeline: list
    _correlated_mitre: list

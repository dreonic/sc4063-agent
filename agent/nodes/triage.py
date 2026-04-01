"""Triage node — inventory logs, detect subnet/domain, build network map."""
from __future__ import annotations

from dataclasses import asdict

from ..config import Config
from ..state import ForensicState
from ..analyzers.triage import TriageAnalyzer


def triage_node(state: ForensicState) -> dict:
    """Run TriageAnalyzer and populate state with inventory and network info."""
    from pathlib import Path
    log_dir = Path(state["log_dir"])
    config = Config()

    print("[TRIAGE] Inventorying log files and building network map...")
    inventory, hosts, subnet, domain = TriageAnalyzer(log_dir, config).run()

    # Serialise to dicts for JSON-safe state
    inventory_dicts = []
    for log_file in inventory:
        inventory_dicts.append({
            "name": log_file.name,
            "path": str(log_file.path),
            "size": log_file.size,
            "category": log_file.category.value,
            "fields": log_file.fields,
            "types": log_file.types,
            "line_count": log_file.line_count,
        })

    host_dicts = []
    for h in hosts:
        host_dicts.append({
            "ip": h.ip,
            "hostname": h.hostname,
            "role": h.role,
            "is_internal": h.is_internal,
            "associated_accounts": h.associated_accounts,
        })

    print(f"[TRIAGE] Found {len(inventory)} logs, {len(hosts)} hosts, subnet={subnet}, domain={domain}")

    return {
        "log_inventory": inventory_dicts,
        "network_hosts": host_dicts,
        "internal_subnet": subnet or "",
        "domain": domain or "",
    }

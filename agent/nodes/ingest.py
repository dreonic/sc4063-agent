"""Ingest node — resolve PCAP vs Zeek log directory, run Zeek if needed."""
from __future__ import annotations

from pathlib import Path

from ..state import ForensicState

_PCAP_SUFFIXES = {".pcap", ".pcapng"}


def _is_pcap_dir(path: Path) -> bool:
    """Return True if *path* is a directory containing only PCAP files (no .log files)."""
    entries = list(path.iterdir())
    has_pcap = any(e.suffix in _PCAP_SUFFIXES for e in entries if e.is_file())
    has_logs = any(e.suffix == ".log" for e in entries if e.is_file())
    return has_pcap and not has_logs


def ingest_node(state: ForensicState) -> dict:
    """Resolve the input path and set ``log_dir`` / ``pcap_path`` in state.

    Accepted inputs:
    - Single PCAP file (.pcap / .pcapng) — Zeek is run on it.
    - Directory of PCAP files — Zeek is run on each file and logs are merged.
    - Directory of Zeek logs — used directly (no Zeek invocation).
    """
    input_path = state["input_path"]
    path = Path(input_path)

    # --- Single PCAP file ---
    if path.is_file() and path.suffix in _PCAP_SUFFIXES:
        print(f"[INGEST] Single PCAP detected: {path.name}")
        from ..tools.pcap_ingest import run_zeek
        zeek_out = path.parent / "zeek_logs"
        log_dir = run_zeek(str(path), str(zeek_out))
        return {
            "log_dir": str(log_dir),
            "pcap_path": str(path),
        }

    if path.is_dir():
        # --- Directory of PCAP files ---
        if _is_pcap_dir(path):
            pcap_count = sum(1 for e in path.iterdir() if e.suffix in _PCAP_SUFFIXES)
            zeek_out = Path("forensic_output") / "zeek_logs"
            zeek_out.mkdir(parents=True, exist_ok=True)
            
            # Re-use existing logs if they exist (caching)
            existing_logs = list(zeek_out.glob("*.log"))
            if existing_logs:
                print(f"[INGEST] PCAP directory detected: {path} ({pcap_count} files)")
                print(f"[INGEST] Reusing existing Zeek output in {zeek_out}")
            else:
                print(f"[INGEST] PCAP directory detected: {path} ({pcap_count} files)")
                print(f"[INGEST] Starting with empty log directory for on-demand PCAP ingestion.")

            return {
                "log_dir": str(zeek_out.resolve()),
                "pcap_path": str(path),
            }

        # --- Zeek log directory ---
        print(f"[INGEST] Zeek log directory detected: {path}")
        return {
            "log_dir": str(path),
            "pcap_path": "",
        }

    raise ValueError(
        f"Input must be a PCAP file, a directory of PCAP files, or a directory "
        f"of Zeek logs. Got: {path}"
    )

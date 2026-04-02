"""LangChain @tool wrappers for micro-level Zeek log and tshark DPI operations.

All tools are factory functions that accept ``log_dir`` (and optionally
``pcap_path``, ``internal_subnet``) at construction time so the LLM does not
have to pass directory paths on every call.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

from langchain_core.tools import tool

from .log_reader import ZeekLogReader
from . import search as search_mod
from . import stats as stats_mod

MAX_RECORDS = 200  # truncation cap per tool call


def _records_to_str(records: list[dict], limit: int = MAX_RECORDS) -> str:
    """Serialise records to a truncated JSON string."""
    truncated = records[:limit]
    out = json.dumps(truncated, indent=1, default=str)
    if len(out) > 4000:
        out = out[:4000] + "\n\n[... output truncated due to 4000 character limit]"
    elif len(records) > limit:
        out += f"\n[... truncated: {len(records) - limit} more records]"
    return out


def _reader(log_dir: str, log_name: str) -> ZeekLogReader:
    path = Path(log_dir) / log_name
    return ZeekLogReader(path)


# =====================================================================
# Factory: builds all micro tools bound to a specific log_dir / pcap
# =====================================================================

def build_micro_tools(
    log_dir: str,
    internal_subnet: str,
    pcap_path: str | None = None,
):
    """Return a list of LangChain tools bound to the given log directory."""
    internal_subnets = [internal_subnet] if internal_subnet else [
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"
    ]

    # ------------------------------------------------------------------
    # Zeek log micro tools
    # ------------------------------------------------------------------

    @tool
    def list_available_logs() -> str:
        """List all Zeek log files in the analysis directory with their field names and sizes."""
        log_path = Path(log_dir)
        logs = sorted(log_path.glob("*.log"))
        if not logs:
            msg = "No .log files found in the current working log directory."
            if pcap_path and Path(pcap_path).is_dir():
                msg += " Hint: Use `list_available_pcaps` and `ingest_pcap` to populate this directory from PCAP sources."
            return msg
        lines = []
        for lp in logs:
            size = lp.stat().st_size
            try:
                rdr = ZeekLogReader(lp)
                fields_str = ", ".join(rdr.fields[:8])
                if len(rdr.fields) > 8:
                    fields_str += f" (+{len(rdr.fields) - 8} more)"
                lines.append(f"  {lp.name}  ({size:,} bytes)  fields: {fields_str}")
            except Exception as e:
                lines.append(f"  {lp.name}  ({size:,} bytes)  [header parse error: {e}]")
        return f"Found {len(logs)} log files:\n" + "\n".join(lines)

    @tool
    def read_log_head(log_name: str, n: int = 20) -> str:
        """Read the first N records from a Zeek log file. Returns field-keyed JSON records."""
        rdr = _reader(log_dir, log_name)
        records = rdr.read_head(min(n, MAX_RECORDS))
        return f"First {len(records)} records from {log_name}:\n{_records_to_str(records)}"

    @tool
    def grep_log(log_name: str, pattern: str, max_results: int = 100) -> str:
        """Search a Zeek log file for lines matching a regex/fixed pattern. Returns matching records as JSON."""
        rdr = _reader(log_dir, log_name)
        cap = min(max_results, MAX_RECORDS)
        records = rdr.grep(pattern, max_results=cap)
        return f"grep '{pattern}' in {log_name}: {len(records)} match(es)\n{_records_to_str(records)}"

    @tool
    def grep_count(log_name: str, pattern: str) -> str:
        """Count lines matching a pattern in a Zeek log file."""
        rdr = _reader(log_dir, log_name)
        count = rdr.grep_count(pattern)
        return f"grep -c '{pattern}' in {log_name}: {count} matching lines"

    @tool
    def find_connections_by_port(port: int) -> str:
        """Find connections to a specific destination port in conn.log."""
        conn_path = Path(log_dir) / "conn.log"
        if not conn_path.exists():
            return "conn.log not found."
        rdr = ZeekLogReader(conn_path)
        records = search_mod.find_connections_by_port(rdr, port, direction="dest")
        return f"Connections to port {port}: {len(records)} found\n{_records_to_str(records)}"

    @tool
    def find_external_ips(log_name: str, ip_field: str = "id.orig_h") -> str:
        """Find all external (non-internal) IP addresses in a specific field of a Zeek log."""
        rdr = _reader(log_dir, log_name)
        records = rdr.read_head(5000)
        ext_ips = sorted(search_mod.find_external_ips(records, ip_field, internal_subnets))
        result = f"External IPs in {log_name}.{ip_field}: {ext_ips}"
        if len(result) > 4000:
            result = result[:4000] + "... [truncated]"
        return result

    @tool
    def find_auth_failures(log_name: str) -> str:
        """Find failed authentication records in a Zeek log (ntlm.log, ssh.log, etc.)."""
        rdr = _reader(log_dir, log_name)
        records = rdr.read_full()
        failures = search_mod.find_auth_failures(records)
        return f"Auth failures in {log_name}: {len(failures)}\n{_records_to_str(failures)}"

    @tool
    def find_auth_successes(log_name: str) -> str:
        """Find successful authentication records in a Zeek log."""
        rdr = _reader(log_dir, log_name)
        records = rdr.read_full()
        successes = search_mod.find_auth_successes(records)
        return f"Auth successes in {log_name}: {len(successes)}\n{_records_to_str(successes)}"

    @tool
    def count_by_field(log_name: str, field: str) -> str:
        """Count occurrences of each unique value in a field. Returns top values and their counts."""
        rdr = _reader(log_dir, log_name)
        records = rdr.read_full()
        counter = stats_mod.count_by_field(records, field)
        top = counter.most_common(30)
        lines = [f"{val}: {cnt}" for val, cnt in top]
        total = len(counter)
        result = f"Field '{field}' in {log_name}: {total} unique values\n" + "\n".join(lines)
        if total > 30:
            result += f"\n[... {total - 30} more values]"
        return result

    @tool
    def top_n_values(log_name: str, field: str, n: int = 10) -> str:
        """Return the top N most common values for a field in a Zeek log."""
        rdr = _reader(log_dir, log_name)
        records = rdr.read_full()
        top = stats_mod.top_n(records, field, n)
        lines = [f"  {val}: {cnt}" for val, cnt in top]
        return f"Top {n} values for '{field}' in {log_name}:\n" + "\n".join(lines)

    @tool
    def get_time_range(log_name: str) -> str:
        """Get the earliest and latest timestamp in a Zeek log file."""
        rdr = _reader(log_dir, log_name)
        records = rdr.read_head(5000)
        try:
            earliest, latest = stats_mod.time_range(records)
            return (
                f"Time range in {log_name}: "
                f"{stats_mod.epoch_to_human(earliest)} to {stats_mod.epoch_to_human(latest)}"
            )
        except ValueError:
            return f"No valid timestamps found in {log_name}."

    tools = [
        list_available_logs,
        read_log_head,
        grep_log,
        grep_count,
        find_connections_by_port,
        find_external_ips,
        find_auth_failures,
        find_auth_successes,
        count_by_field,
        top_n_values,
        get_time_range,
    ]

    # ------------------------------------------------------------------
    # PCAP tools (ingestion + tshark DPI)
    # ------------------------------------------------------------------

    if pcap_path:
        _pcap_path = Path(pcap_path)
        _is_pcap_dir = _pcap_path.is_dir()

        def _resolve_pcap(pcap_file: str = "") -> str | None:
            """Resolve a PCAP file path. Returns the path string or None with error."""
            if _is_pcap_dir:
                if not pcap_file:
                    return None  # caller must handle
                full = _pcap_path / pcap_file
                return str(full) if full.exists() else None
            # Single file mode — ignore pcap_file param
            return str(_pcap_path) if _pcap_path.exists() else None

        # -- Ingestion tools (PCAP directory only) -------------------------

        if _is_pcap_dir:
            @tool
            def list_pcap_files() -> str:
                """List all PCAP files in the source directory with size and first-packet timestamp. Use this to survey available data before deciding which PCAPs to ingest."""
                import struct
                import datetime

                pcaps = sorted(
                    p for p in _pcap_path.iterdir()
                    if p.suffix in {".pcap", ".pcapng"}
                )
                if not pcaps:
                    return "No PCAP files found in the source directory."

                lines = []
                for p in pcaps:
                    size_mb = p.stat().st_size / (1024 * 1024)
                    # Read first-packet timestamp from PCAP header (24 byte global + 16 byte pkt)
                    ts_str = "?"
                    try:
                        with open(p, "rb") as fh:
                            fh.read(24)  # skip global header
                            pkt_hdr = fh.read(16)
                            if len(pkt_hdr) >= 8:
                                ts_sec = struct.unpack("<I", pkt_hdr[:4])[0]
                                ts_str = datetime.datetime.utcfromtimestamp(ts_sec).strftime("%Y-%m-%d %H:%M UTC")
                    except Exception:
                        pass
                    lines.append(f"  {p.name}  ({size_mb:.0f} MB)  starts: {ts_str}")

                return f"Found {len(pcaps)} PCAP file(s):\n" + "\n".join(lines)

            @tool
            def ingest_pcap(pcap_filename: str) -> str:
                """Run Zeek on a specific PCAP file and merge its logs into the analysis directory. After ingestion, all Zeek log tools (grep_log, read_log_head, etc.) will see the new data. Each PCAP takes 1-3 minutes to process."""
                from .pcap_ingest import ingest_single_pcap

                target = _pcap_path / pcap_filename
                if not target.exists():
                    avail = sorted(p.name for p in _pcap_path.iterdir() if p.suffix in {".pcap", ".pcapng"})
                    hint = ", ".join(avail[:5])
                    return f"Error: '{pcap_filename}' not found. Available: {hint}..."

                try:
                    print(f"  [TOOL] Ingesting {pcap_filename} via Zeek ...")
                    stats = ingest_single_pcap(str(target), log_dir)
                    if not stats:
                        return f"Zeek processed {pcap_filename} but produced no log output."
                    lines = [f"Successfully ingested {pcap_filename}. New records:"]
                    for log_name, count in sorted(stats.items()):
                        lines.append(f"  {log_name}: +{count} records")
                    lines.append("Use list_available_logs to see the updated log inventory.")
                    return "\n".join(lines)
                except Exception as e:
                    return f"Ingestion failed for {pcap_filename}: {e}"

            tools.extend([list_pcap_files, ingest_pcap])

        # -- tshark DPI tools ----------------------------------------------

        @tool
        def list_pcap_protocols(pcap_file: str = "") -> str:
            """List protocol hierarchy statistics from a PCAP file. For PCAP directories, specify which file to analyze."""
            resolved = _resolve_pcap(pcap_file)
            if not resolved:
                return f"PCAP file not found: '{pcap_file}'. Use list_pcap_files to see available files."
            try:
                result = subprocess.run(
                    ["tshark", "-r", resolved, "-qz", "io,phs"],
                    capture_output=True, text=True, timeout=120,
                )
                return f"Protocol hierarchy for {Path(resolved).name}:\n{result.stdout[:4000]}"
            except FileNotFoundError:
                return "tshark not found. Install Wireshark/tshark to use DPI tools."
            except subprocess.TimeoutExpired:
                return "tshark timed out."

        @tool
        def extract_pcap_stream(stream_index: int, protocol: str = "tcp", pcap_file: str = "") -> str:
            """Extract and display a TCP or UDP stream by stream index. For PCAP directories, specify which file."""
            resolved = _resolve_pcap(pcap_file)
            if not resolved:
                return f"PCAP file not found: '{pcap_file}'. Use list_pcap_files to see available files."
            try:
                result = subprocess.run(
                    ["tshark", "-r", resolved, "-qz", f"follow,{protocol},ascii,{stream_index}"],
                    capture_output=True, text=True, timeout=120,
                )
                output = result.stdout[:4000]
                if len(result.stdout) > 4000:
                    output += "\n[... truncated]"
                return f"Stream {stream_index} ({protocol}) from {Path(resolved).name}:\n{output}"
            except FileNotFoundError:
                return "tshark not found."
            except subprocess.TimeoutExpired:
                return "tshark timed out."

        @tool
        def apply_bpf_filter(display_filter: str, max_packets: int = 50, pcap_file: str = "") -> str:
            """Apply a Wireshark display filter to a PCAP and return matching packet summaries. For PCAP directories, specify which file. Example filters: 'ip.addr == 1.2.3.4', 'tcp.port == 443'."""
            resolved = _resolve_pcap(pcap_file)
            if not resolved:
                return f"PCAP file not found: '{pcap_file}'. Use list_pcap_files to see available files."
            try:
                result = subprocess.run(
                    ["tshark", "-r", resolved, "-Y", display_filter, "-c", str(max_packets)],
                    capture_output=True, text=True, timeout=120,
                )
                output = result.stdout[:4000]
                if len(result.stdout) > 4000:
                    output += "\n[... truncated]"
                return f"Filter '{display_filter}' on {Path(resolved).name} ({max_packets} max):\n{output}"
            except FileNotFoundError:
                return "tshark not found."
            except subprocess.TimeoutExpired:
                return "tshark timed out."

        @tool
        def get_packet_details(start_frame: int, end_frame: int, pcap_file: str = "") -> str:
            """Get detailed packet dissection for a range of frame numbers. For PCAP directories, specify which file."""
            resolved = _resolve_pcap(pcap_file)
            if not resolved:
                return f"PCAP file not found: '{pcap_file}'. Use list_pcap_files to see available files."
            frame_range = min(end_frame - start_frame + 1, 10)
            actual_end = start_frame + frame_range - 1
            try:
                result = subprocess.run(
                    [
                        "tshark", "-r", resolved,
                        "-Y", f"frame.number >= {start_frame} && frame.number <= {actual_end}",
                        "-V",
                    ],
                    capture_output=True, text=True, timeout=120,
                )
                output = result.stdout[:4000]
                if len(result.stdout) > 4000:
                    output += "\n[... truncated]"
                return f"Packets {start_frame}-{actual_end} from {Path(resolved).name}:\n{output}"
            except FileNotFoundError:
                return "tshark not found."
            except subprocess.TimeoutExpired:
                return "tshark timed out."

        @tool
        def extract_http_objects(pcap_file: str = "") -> str:
            """Export HTTP objects (files) from a PCAP. For PCAP directories, specify which file."""
            resolved = _resolve_pcap(pcap_file)
            if not resolved:
                return f"PCAP file not found: '{pcap_file}'. Use list_pcap_files to see available files."
            import tempfile
            outdir = Path(tempfile.mkdtemp(prefix="http_objects_"))
            try:
                subprocess.run(
                    ["tshark", "-r", resolved, "--export-objects", f"http,{outdir}"],
                    capture_output=True, text=True, timeout=120,
                )
                files = list(outdir.iterdir())
                if not files:
                    return f"No HTTP objects found in {Path(resolved).name}."
                lines = []
                for f in files[:50]:
                    lines.append(f"  {f.name} ({f.stat().st_size:,} bytes)")
                out = f"Extracted {len(files)} HTTP object(s) from {Path(resolved).name}:\n" + "\n".join(lines)
                if len(files) > 50:
                    out += f"\n[... {len(files) - 50} more files]"
                return out
            except FileNotFoundError:
                return "tshark not found."
            except subprocess.TimeoutExpired:
                return "tshark timed out."

        tools.extend([
            list_pcap_protocols,
            extract_pcap_stream,
            apply_bpf_filter,
            get_packet_details,
            extract_http_objects,
        ])

    return tools

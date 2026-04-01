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
    # tshark DPI tools (only if PCAP available)
    # ------------------------------------------------------------------

    if pcap_path and Path(pcap_path).exists():
        _pcap = pcap_path

        @tool
        def list_pcap_protocols() -> str:
            """List protocol hierarchy statistics from the PCAP file. Shows what protocols are present and their packet/byte counts."""
            try:
                result = subprocess.run(
                    ["tshark", "-r", _pcap, "-qz", "io,phs"],
                    capture_output=True, text=True, timeout=120,
                )
                return f"Protocol hierarchy:\n{result.stdout[:4000]}"
            except FileNotFoundError:
                return "tshark not found. Install Wireshark/tshark to use DPI tools."
            except subprocess.TimeoutExpired:
                return "tshark timed out."

        @tool
        def extract_pcap_stream(stream_index: int, protocol: str = "tcp") -> str:
            """Extract and display a TCP or UDP stream from the PCAP by stream index. Shows raw payload bytes and ASCII representation."""
            try:
                result = subprocess.run(
                    ["tshark", "-r", _pcap, "-qz", f"follow,{protocol},ascii,{stream_index}"],
                    capture_output=True, text=True, timeout=120,
                )
                output = result.stdout[:4000]
                if len(result.stdout) > 4000:
                    output += "\n[... truncated]"
                return f"Stream {stream_index} ({protocol}):\n{output}"
            except FileNotFoundError:
                return "tshark not found."
            except subprocess.TimeoutExpired:
                return "tshark timed out."

        @tool
        def apply_bpf_filter(display_filter: str, max_packets: int = 50) -> str:
            """Apply a Wireshark display filter to the PCAP and return matching packet summaries. Example filters: 'ip.addr == 1.2.3.4', 'tcp.port == 443', 'http.request'."""
            try:
                result = subprocess.run(
                    ["tshark", "-r", _pcap, "-Y", display_filter, "-c", str(max_packets)],
                    capture_output=True, text=True, timeout=120,
                )
                output = result.stdout[:4000]
                if len(result.stdout) > 4000:
                    output += "\n[... truncated]"
                return f"Filter '{display_filter}' ({max_packets} max):\n{output}"
            except FileNotFoundError:
                return "tshark not found."
            except subprocess.TimeoutExpired:
                return "tshark timed out."

        @tool
        def get_packet_details(start_frame: int, end_frame: int) -> str:
            """Get detailed packet dissection for a range of frame numbers. Shows headers and payload details."""
            frame_range = min(end_frame - start_frame + 1, 10)
            actual_end = start_frame + frame_range - 1
            try:
                result = subprocess.run(
                    [
                        "tshark", "-r", _pcap,
                        "-Y", f"frame.number >= {start_frame} && frame.number <= {actual_end}",
                        "-V",
                    ],
                    capture_output=True, text=True, timeout=120,
                )
                output = result.stdout[:4000]
                if len(result.stdout) > 4000:
                    output += "\n[... truncated]"
                return f"Packets {start_frame}-{actual_end}:\n{output}"
            except FileNotFoundError:
                return "tshark not found."
            except subprocess.TimeoutExpired:
                return "tshark timed out."

        @tool
        def extract_http_objects() -> str:
            """Export HTTP objects (files) from the PCAP. Lists extracted files and their details."""
            import tempfile
            outdir = Path(tempfile.mkdtemp(prefix="http_objects_"))
            try:
                subprocess.run(
                    ["tshark", "-r", _pcap, "--export-objects", f"http,{outdir}"],
                    capture_output=True, text=True, timeout=120,
                )
                files = list(outdir.iterdir())
                if not files:
                    return "No HTTP objects found in PCAP."
                lines = []
                for f in files[:50]:
                    lines.append(f"  {f.name} ({f.stat().st_size:,} bytes)")
                result = f"Extracted {len(files)} HTTP object(s):\n" + "\n".join(lines)
                if len(files) > 50:
                    result += f"\n[... {len(files) - 50} more files]"
                return result
            except FileNotFoundError:
                return "tshark not found."
            except subprocess.TimeoutExpired:
                return "tshark timed out."

        # ------------------------------------------------------------------
        # Selective Ingestion Tools (Only if input is a PCAP directory)
        # ------------------------------------------------------------------

        @tool
        def list_available_pcaps() -> str:
            """List all PCAP files available in the source directory for ingestion.
            Use this to see which dates/times to analyze next.
            """
            if not pcap_path or not Path(pcap_path).is_dir():
                return "No source PCAP directory available in this investigation environment."
            
            pcaps = sorted([
                p.name for p in Path(pcap_path).iterdir()
                if p.suffix in {".pcap", ".pcapng"}
            ])
            if not pcaps:
                return "No PCAP files found in the source directory."
            
            return f"Found {len(pcaps)} available PCAP(s):\n" + "\n".join(f"  - {p}" for p in pcaps)

        @tool
        def ingest_pcap(filename: str) -> str:
            """Run Zeek on a specific PCAP file from the source directory and add its telemetry
            to the working log directory. This merges and sorts the new data into existing logs.
            """
            from .pcap_ingest import ingest_single_pcap
            if not pcap_path or not Path(pcap_path).is_dir():
                return "Error: No source PCAP directory configured."
            
            target = Path(pcap_path) / filename
            if not target.exists():
                return f"Error: PCAP '{filename}' not found. Use `list_available_pcaps` first."

            try:
                print(f"[TOOL] Ingesting {filename} ...")
                stats = ingest_single_pcap(str(target), log_dir)
                if not stats:
                    return f"PCAP {filename} processed, but no relevant Zeek logs were produced."
                
                lines = [f"Successfully ingested {filename}. Records added for:"]
                for log_name, count in stats.items():
                    lines.append(f"  - {log_name}: {count} records")
                return "\n".join(lines)
            except Exception as e:
                return f"Failed to ingest {filename}: {str(e)}"

        tools.extend([
            list_pcap_protocols,
            extract_pcap_stream,
            apply_bpf_filter,
            get_packet_details,
            extract_http_objects,
            list_available_pcaps,
            ingest_pcap,
        ])

    return tools

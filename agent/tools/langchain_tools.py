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

    # Shared ingestion state — tracks attempted and successful PCAPs so that
    # list_available_logs and ingest_pcap can give directed recovery hints.
    _attempted_pcaps: list[str] = []   # all pcap_filename values tried
    _successful_pcaps: list[str] = []  # ones that produced at least one log
    _get_time_range_call_count: dict[str, int] = {}   # per-log limiter

    # ------------------------------------------------------------------
    # Zeek log micro tools
    # ------------------------------------------------------------------

    @tool
    def list_available_logs() -> str:
        """List all Zeek log files in the analysis directory with their field names and sizes."""
        import re as _re
        log_path = Path(log_dir)
        logs = sorted(log_path.glob("*.log"))
        if not logs:
            msg = "No Zeek logs found yet."
            if pcap_path and Path(pcap_path).is_dir():
                # Find the next untried representative PCAP and direct the agent to it
                _pcap_dir = Path(pcap_path)
                all_pcaps = sorted(p.name for p in _pcap_dir.iterdir() if p.suffix in {".pcap", ".pcapng"})
                seen_groups: set[str] = set()
                reps: list[str] = []
                for name in all_pcaps:
                    m = _re.search(r'-(\d{6})-', name)
                    key = m.group(1) if m else name
                    if key not in seen_groups:
                        seen_groups.add(key)
                        reps.append(name)
                untried = [f for f in reps if f not in _attempted_pcaps]
                if untried:
                    next_file = untried[0]
                    msg += (
                        f" You have tried: {_attempted_pcaps or 'nothing yet'}.\n"
                        f"Call ingest_pcap NOW with the next untried file:\n"
                        f'{{"name": "ingest_pcap", "arguments": {{"pcap_filename": "{next_file}"}}}}'
                    )
                elif _attempted_pcaps:
                    msg += (
                        f" All representative PCAPs have been tried: {_attempted_pcaps}.\n"
                        "If ingestion failed, check whether Zeek (WSL) is working. "
                        "Try: ingest_pcap with a different file from the list."
                    )
                else:
                    msg += " Call ingest_pcap with a PCAP filename to populate logs."
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
        """Get the earliest and latest timestamp in a Zeek log file. Each log may be queried at most twice — act on the result immediately rather than re-checking."""
        _get_time_range_call_count[log_name] = _get_time_range_call_count.get(log_name, 0) + 1
        if _get_time_range_call_count[log_name] > 2:
            return (
                f"ERROR: get_time_range already called twice for {log_name}. Do NOT call it again. "
                "Act on the result you already have."
            )
        log_path = Path(log_dir) / log_name
        if not log_path.exists():
            return f"{log_name} not found."
        rdr = _reader(log_dir, log_name)
        head = rdr.read_head(100)
        # Efficiently read last ~100 data lines using binary seek from EOF
        tail: list[dict] = []
        try:
            file_size = log_path.stat().st_size
            chunk = min(32768, file_size)
            with open(log_path, "rb") as fh:
                fh.seek(max(0, file_size - chunk))
                raw_bytes = fh.read()
            tail_text = raw_bytes.decode("utf-8", errors="replace")
            tail_lines = [l for l in tail_text.splitlines() if l.strip() and not l.startswith("#")]
            for raw in tail_lines[-100:]:
                rec = rdr._parse_line(raw)
                if rec is not None:
                    tail.append(rec)
        except Exception:
            pass
        all_records = head + tail
        try:
            earliest, latest = stats_mod.time_range(all_records)
            span_days = (latest - earliest) / 86400
            msg = (
                f"Time range in {log_name}: "
                f"{stats_mod.epoch_to_human(earliest)} to {stats_mod.epoch_to_human(latest)} "
                f"({span_days:.1f} days)"
            )
            if span_days < 20:
                msg += (
                    f"\nCoverage is {span_days:.1f} days — too narrow. "
                    "Call list_pcap_files to see available date groups, then ingest_pcap "
                    "for each uncovered group."
                )
            elif span_days < 73:
                msg += (
                    f"\nCoverage is {span_days:.1f} days — this is all the data available in the PCAP dataset "
                    f"(full incident is ~73 days but the capture does not cover the entire window). "
                    f"Note this gap in findings and proceed to Phase 2."
                )
            else:
                msg += f"\nFull incident window covered ({span_days:.1f} days). Proceed to Phase 2."
            return msg
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
            _list_pcap_call_count = [0]

            @tool
            def list_pcap_files() -> str:
                """List PCAP files grouped by date with ready-to-use ingest_pcap calls. Call this ONCE, then immediately call ingest_pcap for each group. Do NOT call this tool more than once."""
                import struct
                import datetime
                import re as _re

                _list_pcap_call_count[0] += 1

                # If Zeek logs already exist with adequate coverage, skip ingestion
                _existing_logs = list(Path(log_dir).glob("*.log"))
                if _existing_logs and _list_pcap_call_count[0] == 1:
                    # Quick coverage check via conn.log
                    _conn = Path(log_dir) / "conn.log"
                    if _conn.exists():
                        try:
                            import struct as _struct2, datetime as _dt2
                            _file_size = _conn.stat().st_size
                            _chunk = min(32768, _file_size)
                            with open(_conn, "rb") as _fh:
                                _fh.seek(max(0, _file_size - _chunk))
                                _tail_bytes = _fh.read()
                            _tail_lines = [l for l in _tail_bytes.decode("utf-8", errors="replace").splitlines()
                                           if l.strip() and not l.startswith("#")]
                            _head_lines: list[str] = []
                            with open(_conn, "r", encoding="utf-8", errors="replace") as _fh2:
                                for _line in _fh2:
                                    if not _line.startswith("#") and _line.strip():
                                        _head_lines.append(_line)
                                        if len(_head_lines) >= 5:
                                            break
                            _ts_vals = []
                            for _raw in (_head_lines[:3] + _tail_lines[-3:]):
                                try:
                                    _ts_vals.append(float(_raw.split("\t", 1)[0]))
                                except Exception:
                                    pass
                            if len(_ts_vals) >= 2:
                                _span = (max(_ts_vals) - min(_ts_vals)) / 86400
                                if _span >= 20:
                                    return (
                                        f"Zeek logs already exist with {_span:.1f} days of coverage — "
                                        f"adequate for analysis. Do NOT ingest more PCAPs.\n"
                                        f"Call list_available_logs to review logs, then proceed to Phase 2."
                                    )
                        except Exception:
                            pass

                if _list_pcap_call_count[0] > 1:
                    # Find first UNTRIED representative file to direct the agent
                    pcaps_hint = sorted(
                        p for p in _pcap_path.iterdir()
                        if p.suffix in {".pcap", ".pcapng"}
                    )
                    seen: set[str] = set()
                    reps = []
                    for p in pcaps_hint:
                        m = _re.search(r'-(\d{6})-', p.name)
                        key = m.group(1) if m else p.name
                        if key not in seen:
                            seen.add(key)
                            reps.append(p.name)
                    untried = [f for f in reps if f not in _attempted_pcaps]
                    next_file = untried[0] if untried else (reps[0] if reps else "the_first.pcap")
                    return (
                        f"ERROR: Do NOT call list_pcap_files again.\n"
                        f"Already attempted: {_attempted_pcaps or 'none yet'}.\n"
                        f"Call ingest_pcap NOW with the next untried file:\n"
                        f'{{"name": "ingest_pcap", "arguments": {{"pcap_filename": "{next_file}"}}}}'
                    )

                pcaps = sorted(
                    p for p in _pcap_path.iterdir()
                    if p.suffix in {".pcap", ".pcapng"}
                )
                if not pcaps:
                    return "No PCAP files found in the source directory."

                def _read_ts(path):
                    try:
                        with open(path, "rb") as fh:
                            fh.read(24)
                            pkt_hdr = fh.read(16)
                            if len(pkt_hdr) >= 8:
                                ts_sec = struct.unpack("<I", pkt_hdr[:4])[0]
                                return datetime.datetime.fromtimestamp(ts_sec, datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
                    except Exception:
                        pass
                    return "?"

                # Group by the date portion in the filename (e.g. "250301")
                groups: dict[str, list] = {}
                for p in pcaps:
                    m = _re.search(r'-(\d{6})-', p.name)
                    key = m.group(1) if m else "unknown"
                    groups.setdefault(key, []).append(p)

                lines = [
                    f"Found {len(pcaps)} PCAP file(s) in {len(groups)} date groups.",
                    "WARNING: Call this tool only ONCE. Now call ingest_pcap for each group below.\n",
                ]
                for key in sorted(groups.keys()):
                    grp = groups[key]
                    first_ts = _read_ts(grp[0])
                    last_ts = _read_ts(grp[-1])
                    lines.append(
                        f"Group {key} ({len(grp)} files): "
                        f"incident time {first_ts} → {last_ts}"
                    )
                    lines.append(f"  Ingest: {grp[0].name}")

                lines.append(
                    "\nCall ingest_pcap for EACH group (one call per message):"
                )
                for key in sorted(groups.keys()):
                    grp = groups[key]
                    lines.append(
                        f'  {{"name": "ingest_pcap", "arguments": {{"pcap_filename": "{grp[0].name}"}}}}'
                    )

                result_str = "\n".join(lines)
                print(f"  [list_pcap_files] {len(groups)} date groups: {sorted(groups.keys())}")
                return result_str

            @tool
            def ingest_pcap(pcap_filename: str) -> str:
                """Run Zeek on a specific PCAP file and merge its logs into the analysis directory. After ingestion, all Zeek log tools (grep_log, read_log_head, etc.) will see the new data. Each PCAP takes 1-3 minutes to process."""
                import re as _re2
                from .pcap_ingest import ingest_single_pcap

                # Record this attempt regardless of outcome
                if pcap_filename not in _attempted_pcaps:
                    _attempted_pcaps.append(pcap_filename)

                # If already successfully ingested, skip re-running Zeek
                if pcap_filename in _successful_pcaps:
                    return (
                        f"{pcap_filename} was already ingested successfully. "
                        "Call ingest_pcap with the NEXT date group file, "
                        "or call list_available_logs to see current logs."
                    )

                target = _pcap_path / pcap_filename
                if not target.exists():
                    avail = sorted(p.name for p in _pcap_path.iterdir() if p.suffix in {".pcap", ".pcapng"})
                    hint = ", ".join(avail[:5])
                    return f"Error: '{pcap_filename}' not found. Available: {hint}..."

                # Find next untried representative to suggest on failure
                all_pcaps = sorted(p.name for p in _pcap_path.iterdir() if p.suffix in {".pcap", ".pcapng"})
                seen_g: set[str] = set()
                reps: list[str] = []
                for name in all_pcaps:
                    m = _re2.search(r'-(\d{6})-', name)
                    key = m.group(1) if m else name
                    if key not in seen_g:
                        seen_g.add(key)
                        reps.append(name)
                untried = [f for f in reps if f not in _attempted_pcaps]
                next_hint = (
                    f'\nNext: {{"name": "ingest_pcap", "arguments": {{"pcap_filename": "{untried[0]}"}}}}'
                    if untried else "\nAll date groups have been attempted."
                )

                try:
                    import re as _re3
                    _grp_m = _re3.search(r'-(\d{6})-', pcap_filename)
                    _grp_key = _grp_m.group(1) if _grp_m else "unknown"
                    print(f"  [INGEST] Starting: {pcap_filename} (date group {_grp_key}) ...")
                    stats = ingest_single_pcap(str(target), log_dir)
                    if not stats:
                        print(f"  [INGEST] No output: {pcap_filename}")
                        return (
                            f"Zeek ran on {pcap_filename} but produced no log records. "
                            f"This PCAP may be empty or contain only unrecognised traffic.{next_hint}"
                        )
                    _successful_pcaps.append(pcap_filename)
                    total_records = sum(stats.values())
                    top_logs = sorted(stats.items(), key=lambda x: -x[1])[:5]
                    print(f"  [INGEST] Done: {pcap_filename} → {total_records:,} records across {len(stats)} logs")
                    # Append to persistent ingestion log alongside the report output
                    try:
                        import datetime as _dt
                        _ingest_log = Path(log_dir).parent / "ingested_pcaps.log"
                        with open(_ingest_log, "a", encoding="utf-8") as _lf:
                            _ts = _dt.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
                            _lf.write(f"{_ts}  {pcap_filename}  ({total_records:,} records)\n")
                    except Exception:
                        pass
                    for _ln, _cnt in top_logs:
                        print(f"    {_ln}: +{_cnt:,}")
                    lines = [
                        f"Successfully ingested {pcap_filename} (group {_grp_key}). "
                        f"{total_records:,} new records across {len(stats)} log types."
                    ]
                    for log_name, count in sorted(stats.items()):
                        lines.append(f"  {log_name}: +{count} records")
                    lines.append(
                        f"Ingested so far: {len(_successful_pcaps)} group(s). "
                        f"Remaining: {len(untried)} group(s) not yet ingested.{next_hint}"
                    )
                    return "\n".join(lines)
                except Exception as e:
                    print(f"  [INGEST] ERROR: {pcap_filename}: {e}")
                    return f"Ingestion failed for {pcap_filename}: {e}{next_hint}"

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

"""Investigate node — fully autonomous ReAct agent loop.

This is the core of the agentic forensic analysis. The LLM autonomously
decides which tools to call, interprets results, and records findings.
No human interrupts occur within this loop.
"""
from __future__ import annotations

import json
import re
import uuid
from pathlib import Path

from langchain_openai import ChatOpenAI

from ..config import Config
from ..guardrails.cost_tracker import HybridCostTracker
from ..llm.prompts import AGENT_SYSTEM_PROMPT
from ..state import ForensicState
from ..tools.langchain_tools import build_micro_tools
from ..tools.macro_tools import build_macro_tools
from ..tools.state_tools import build_state_tools


MAX_TOOL_RESULT_CHARS = 8000
MAX_NOTE_CHARS = 500
MAX_CONTEXT_MESSAGES = 120


def _strip_thinking(text: str) -> str:
    """Remove <think>...</think> chain-of-thought blocks from model output.

    Handles three patterns emitted by Qwen/DeepSeek-R1 style models:
    1. Full <think>...</think> block — remove the block entirely.
    2. Orphaned </think> only (reasoning has no opening tag) — strip
       everything up to and including </think>, keeping what follows.
    3. Orphaned <think> only — remove the tag.
    """
    if not text:
        return text
    # Pattern 1: matched pair
    cleaned = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL)
    # Pattern 2: orphaned closing tag — drop all content before it
    if "</think>" in cleaned:
        cleaned = cleaned[cleaned.index("</think>") + len("</think>"):]
    # Pattern 3: orphaned opening tag
    cleaned = cleaned.replace("<think>", "")
    return cleaned.strip()


def _truncate_text(text: str, max_chars: int) -> str:
    """Keep long content bounded to avoid blowing up model context."""
    if len(text) <= max_chars:
        return text

    head_len = max_chars // 2
    tail_len = max_chars - head_len
    removed = len(text) - max_chars
    return (
        text[:head_len]
        + f"\n\n...[truncated {removed} chars to fit context]...\n\n"
        + text[-tail_len:]
    )


def _trim_message_history(messages: list, progress_summary: str = ""):
    """Preserve core prompt and recent turns while trimming old context."""
    if len(messages) <= (MAX_CONTEXT_MESSAGES + 2):
        return messages

    from langchain_core.messages import HumanMessage

    original_len = len(messages)
    trimmed = messages[:2] + messages[-MAX_CONTEXT_MESSAGES:]
    summary_text = (
        f"[Context trimmed: kept latest {MAX_CONTEXT_MESSAGES} of "
        f"{original_len} messages. Continue investigation from where you left off.]"
    )
    if progress_summary:
        summary_text += f"\n\n[PROGRESS SUMMARY — do NOT redo completed steps]\n{progress_summary}"
    trimmed.insert(2, HumanMessage(content=summary_text))
    return trimmed


def _format_tool_catalog(tools: list) -> str:
    """Render available tools and accepted argument names for the prompt."""
    lines = []
    for t in tools:
        arg_schema = getattr(t, "args", None)
        arg_names = []
        if isinstance(arg_schema, dict):
            arg_names = [str(k) for k in arg_schema.keys()]
        arg_text = ", ".join(arg_names) if arg_names else "no arguments"
        lines.append(f"  - {t.name}({arg_text})")
    return "\n".join(lines) if lines else "  (no tools available)"


def _strip_tool_call_tags(text: str) -> str:
    """Remove <tool_call>...</tool_call> wrapper tags used by Qwen/Hermes models.

    These models wrap the JSON payload in XML-style tags:
      <tool_call>{"name": ...}</tool_call>
    The tags themselves are not valid JSON and cause json.loads to fail.
    Strip matched pairs, orphaned closing tags, and orphaned opening tags.

    Also handles the hybrid malformed format where the model mixes JSON and
    Hermes XML-style function tags for parallel calls:
      <function=tool_name", "arguments": {...}}
    This is converted to valid JSON:
      {"name": "tool_name", "arguments": {...}}
    so that the multi-object JSON parser can extract all parallel calls.
    """
    if not text:
        return text
    # Pattern 1: matched pair — keep the inner content
    cleaned = re.sub(r"<tool_call>(.*?)</tool_call>", r"\1", text, flags=re.DOTALL)
    # Pattern 2: orphaned closing tag — remove it
    cleaned = cleaned.replace("</tool_call>", "")
    # Pattern 3: orphaned opening tag — remove it
    cleaned = cleaned.replace("<tool_call>", "")
    # Pattern 4: Hermes hybrid format — <function=name" continues as JSON args.
    # Model emits: <function=grep_count", "arguments": {...}}
    # Replace the tag prefix so it becomes: {"name": "grep_count", "arguments": {...}}
    cleaned = re.sub(r'<function=(\w+)"', r'{"name": "\1"', cleaned)
    # Pattern 5: Hermes pure XML function blocks — <function=name>...</function>
    # These appear as empty duplicates when the model already emitted a valid JSON
    # call earlier in the same message. Converting them to JSON produces an invalid
    # half-formed object that poisons the multi-object parser and causes the valid
    # first call to also be dropped. Strip the entire block instead.
    cleaned = re.sub(r'<function=\w+>.*?</function>', '', cleaned, flags=re.DOTALL)
    # Also strip any orphaned </function> tags (no matching opening tag left after above).
    cleaned = cleaned.replace('</function>', '')
    return cleaned.strip()


def _extract_tool_calls_from_text(content: str) -> list[dict]:
    """Parse tool calls from model text when native tool_call parsing fails.

    Supports both a single JSON object and a JSON array of objects, with keys
    ``args`` or ``arguments``.
    """
    if not content:
        return []

    # Strip <tool_call>...</tool_call> wrapper tags (Qwen/Hermes format) before
    # any JSON extraction so trailing </tool_call> doesn't break json.loads.
    content = _strip_tool_call_tags(content)

    candidates: list[str] = []
    for block in re.findall(r"```(?:json)?\n(.*?)\n```", content, re.DOTALL):
        candidates.append(block.strip())

    stripped = content.strip()
    if stripped.startswith("{") or stripped.startswith("["):
        candidates.append(stripped)

    # Third: JSON objects embedded in prose after reasoning text.
    # Models like Qwen output reasoning WITHOUT <think> tags, then emit
    # {"name":...} blocks. Find the first occurrence and take everything
    # from there to the end of the string.
    m = re.search(r'(?:^|\n)({"name"\s*:)', content)
    if m:
        json_block = content[m.start(1):].strip()
        if json_block not in candidates:
            candidates.append(json_block)

    parsed_calls: list[dict] = []
    seen: set[tuple[str, str]] = set()

    for candidate in candidates:
        payload = None
        # First try: parse as-is (single object or array)
        try:
            payload = json.loads(candidate)
        except Exception:
            pass

        # Second try: multiple top-level objects in one block (no array brackets)
        # e.g. {"name":"foo"}\n{"name":"bar"} — auto-wrap as array
        if payload is None:
            wrapped = re.sub(r'}\s*\n\s*{', '},{', candidate)
            if not wrapped.startswith('['):
                wrapped = f'[{wrapped}]'
            try:
                payload = json.loads(wrapped)
            except Exception:
                pass

        if payload is None:
            # Warn when a candidate looks like a truncated tool call (starts with
            # {"name": but failed to parse). This happens when the model's output
            # was cut off by a token limit mid-string, producing an unterminated
            # JSON string (e.g. "pattern": "id\\.orig_h.*10\\.128.*succe  <eof>).
            if candidate.lstrip().startswith('{"name"'):
                print(f"    [WARN] Could not parse tool call JSON (possibly truncated): "
                      f"{candidate[:120]!r}")
            continue

        raw_calls = payload if isinstance(payload, list) else [payload]
        for raw in raw_calls:
            if not isinstance(raw, dict) or "name" not in raw:
                continue

            args = raw.get("arguments", raw.get("args", {}))
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except Exception:
                    args = {}
            if not isinstance(args, dict):
                args = {}

            name = str(raw.get("name", "")).strip()
            if not name:
                continue

            key = (name, json.dumps(args, sort_keys=True, default=str))
            if key in seen:
                continue
            seen.add(key)

            parsed_calls.append({
                "name": name,
                "args": args,
                "id": f"call_{uuid.uuid4().hex[:8]}",
            })

    return parsed_calls


def _sanitize_tool_args(tool_obj, raw_args: dict) -> tuple[dict, list[str]]:
    """Drop unsupported arguments so near-miss tool calls can still execute."""
    if not isinstance(raw_args, dict):
        return {}, []

    schema = getattr(tool_obj, "args", None)
    if not isinstance(schema, dict) or not schema:
        return raw_args, []

    allowed = set(schema.keys())
    sanitized = {k: v for k, v in raw_args.items() if k in allowed}
    dropped = [k for k in raw_args.keys() if k not in allowed]
    return sanitized, dropped


def _format_inventory(inventory: list[dict]) -> str:
    """Pretty-print the log inventory for the agent's system prompt."""
    lines = []
    for entry in inventory:
        name = entry.get("name", "?")
        size = entry.get("size", 0)
        fields = entry.get("fields", [])
        fields_str = ", ".join(fields[:8])
        if len(fields) > 8:
            fields_str += f" (+{len(fields) - 8} more)"
        lines.append(f"  - {name} ({size:,} bytes): {fields_str}")
    return "\n".join(lines) if lines else "  (no logs available)"


def _format_hosts(hosts: list[dict]) -> str:
    """Pretty-print the network hosts for the agent's system prompt."""
    lines = []
    for h in hosts[:20]:
        ip = h.get("ip", "?")
        hostname = h.get("hostname", "")
        role = h.get("role", "")
        accts = h.get("associated_accounts", [])
        acct_str = ", ".join(accts[:3])
        line = f"  - {ip}"
        if hostname:
            line += f" ({hostname})"
        if role:
            line += f" [{role}]"
        if acct_str:
            line += f" accounts: {acct_str}"
        lines.append(line)
    if len(hosts) > 20:
        lines.append(f"  ... and {len(hosts) - 20} more hosts")
    return "\n".join(lines) if lines else "  (no hosts discovered)"


def _pick_representative_pcaps(pcap_dir: Path, n: int = 18) -> list[str]:
    """Select ~n PCAPs evenly distributed across the actual packet timestamp range.

    Reads the first-packet timestamp from each PCAP's global header (40 bytes)
    and selects files whose timestamps are evenly spaced across the full span.
    This gives much better temporal coverage than batch-label grouping, since
    files from different batch groups can cover the same or different time windows.

    Falls back to alphabetical even-spacing if timestamps cannot be read.
    """
    import struct as _struct
    import datetime as _dt

    pcaps = sorted(
        p for p in pcap_dir.iterdir()
        if p.suffix in (".pcap", ".pcapng")
    )
    if not pcaps:
        return []

    # Read first-packet timestamp from each file
    timed: list[tuple[float, str]] = []
    for p in pcaps:
        try:
            with open(p, "rb") as fh:
                fh.read(24)  # global header
                hdr = fh.read(16)
                if len(hdr) >= 8:
                    ts = _struct.unpack("<I", hdr[:4])[0]
                    timed.append((float(ts), p.name))
        except Exception:
            pass

    if len(timed) < 2:
        # Fallback: evenly-spaced alphabetically
        names = [p.name for p in pcaps]
        step = max(1, (len(names) - 1) / (n - 1))
        return [names[round(i * step)] for i in range(min(n, len(names)))]

    timed.sort(key=lambda x: x[0])
    earliest_ts = timed[0][0]
    latest_ts = timed[-1][0]
    span = latest_ts - earliest_ts

    if span == 0 or len(timed) <= n:
        return [name for _, name in timed]

    # Pick files whose timestamps are closest to evenly-spaced target times
    selected: list[str] = []
    used: set[str] = set()
    for i in range(n):
        target = earliest_ts + (span * i / (n - 1))
        best = min(timed, key=lambda x: (abs(x[0] - target), x[1] in used))
        if best[1] not in used:
            selected.append(best[1])
            used.add(best[1])

    earliest_dt = _dt.datetime.fromtimestamp(earliest_ts, _dt.timezone.utc).strftime("%Y-%m-%d")
    latest_dt = _dt.datetime.fromtimestamp(latest_ts, _dt.timezone.utc).strftime("%Y-%m-%d")
    print(f"[INVESTIGATE] PCAP timestamp range: {earliest_dt} to {latest_dt} "
          f"({span/86400:.1f} days) — selected {len(selected)} representative files")

    return selected


def investigate_node(state: ForensicState) -> dict:
    """Run the autonomous ReAct investigation agent.

    The agent receives the triage context and decides which tools to call.
    It loops until it calls ``mark_investigation_complete`` or hits the
    iteration cap.
    """
    config = Config()
    # Derive /metrics URL from LLM base URL (strip /v1 suffix if present)
    _metrics_base = config.llm_base_url.rstrip("/")
    if _metrics_base.endswith("/v1"):
        _metrics_base = _metrics_base[:-3]
    _metrics_url = _metrics_base + "/metrics"
    tracker = HybridCostTracker(
        api_input_cost_per_1k=config.api_input_cost_per_1k,
        api_output_cost_per_1k=config.api_output_cost_per_1k,
        gpu_hourly_rate=config.gpu_hourly_rate,
        gpu_description=f"Local GPU @ ${config.gpu_hourly_rate:.2f}/hr",
        metrics_url=_metrics_url,
    )
    tracker.start()
    tracker.start_phase("investigate")

    log_dir = state["log_dir"]
    pcap_path = state.get("pcap_path", "")
    internal_subnet = state.get("internal_subnet", "")
    inventory = state.get("log_inventory", [])
    hosts = state.get("network_hosts", [])
    max_iterations = state.get("max_iterations", config.max_iterations)

    # Mutable state reference for state-mutation tools
    state_ref = {
        "log_dir": log_dir,
        "log_inventory": inventory,
        "findings": [],
        "iocs": [],
        "timeline_events": [],
        "investigation_notes": [],
        "investigation_complete": False,
    }

    # Build all tools
    micro_tools = build_micro_tools(log_dir, internal_subnet, pcap_path or None)
    macro_tools = build_macro_tools(log_dir, internal_subnet, hosts, state_ref=state_ref)
    state_mutation_tools = build_state_tools(state_ref)
    all_tools = micro_tools + macro_tools + state_mutation_tools

    # Build the LLM
    llm = ChatOpenAI(
        model=config.llm_model,
        base_url=config.llm_base_url,
        api_key=config.llm_api_key,
        temperature=config.llm_temperature,
    )

    # Build context-enriched system prompt
    pcap_note = ""
    _representative_pcaps: list[str] = []
    if pcap_path and Path(pcap_path).is_dir():
        pcap_dir = Path(pcap_path)
        pcap_count = sum(1 for p in pcap_dir.iterdir() if p.suffix in (".pcap", ".pcapng"))
        _representative_pcaps = _pick_representative_pcaps(pcap_dir)
        print(f"[INVESTIGATE] PCAP directory: {pcap_count} files, {len(_representative_pcaps)} date groups selected:")
        for _i, _f in enumerate(_representative_pcaps, 1):
            print(f"  Group {_i}: {_f}")
        rep_list = "\n".join(f"  {i+1}. {f}" for i, f in enumerate(_representative_pcaps))
        has_logs = bool(inventory)
        if has_logs:
            pcap_note = (
                f"\n\n## PCAP SOURCE DIRECTORY"
                f"\nA directory of {pcap_count} PCAP file(s) is available. "
                f"Zeek logs exist but coverage may be incomplete."
                f"\n\nFollow Phase 1 in the system prompt: call `get_time_range` on conn.log "
                f"to check coverage. If span < 20 days, call `list_pcap_files` then "
                f"ingest additional PCAPs from the underrepresented date groups."
                f"\n\nFallback filenames (one per date group) if `list_pcap_files` is unavailable:"
                f"\n{rep_list}"
                f"\n\nYou can also use tshark DPI tools (list_pcap_protocols, apply_bpf_filter, "
                f"extract_pcap_stream, get_packet_details, extract_http_objects) on any PCAP "
                f"file by specifying pcap_file=<filename>."
            )
        else:
            pcap_note = (
                f"\n\n## PCAP SOURCE DIRECTORY — NO ZEEK LOGS YET"
                f"\nA directory of {pcap_count} PCAP file(s) is available. "
                f"The Zeek log directory is currently EMPTY."
                f"\n\nStart by calling `list_pcap_files` to see the available PCAPs "
                f"grouped by date — it will show you exactly which `ingest_pcap` calls "
                f"to make. Then call `ingest_pcap` for one file per date group."
                f"\n\nFallback: if you already know filenames, call `ingest_pcap` directly:"
                f"\n{rep_list}"
            )
    elif pcap_path and Path(pcap_path).is_file():
        pcap_note = (
            "\n\nA single PCAP file is available. You can use tshark deep packet inspection "
            "tools (list_pcap_protocols, extract_pcap_stream, apply_bpf_filter, "
            "get_packet_details, extract_http_objects) to inspect raw packet payloads."
        )
    else:
        pcap_note = (
            "\n\nNo PCAP file is available — only Zeek logs. "
            "The tshark DPI tools are not available for this analysis."
        )

    # Pre-built nudge text for loop-detection recovery
    _ingest_nudge_text = ""
    if _representative_pcaps:
        first_pcap = _representative_pcaps[0]
        _ingest_nudge_text = (
            f"You have already called list_pcap_files. Stop calling it again.\n"
            f"You need to call ingest_pcap for each of the {len(_representative_pcaps)} "
            f"date groups to cover the full incident window.\n"
            f"Start NOW with this call (output only the JSON, no prose):\n"
            f'{{"name": "ingest_pcap", "arguments": {{"pcap_filename": "{first_pcap}"}}}}\n'
            f"Then continue with the remaining groups one call at a time."
        )

    system_prompt = (
        f"{AGENT_SYSTEM_PROMPT}\n\n"
        f"## AVAILABLE ZEEK LOGS\n{_format_inventory(inventory)}\n\n"
        f"## AVAILABLE TOOLS\n{_format_tool_catalog(all_tools)}\n\n"
        f"## NETWORK ENVIRONMENT\n"
        f"Internal subnet: {internal_subnet or 'auto-detected'}\n"
        f"Domain: {state.get('domain', 'unknown')}\n\n"
        f"## DISCOVERED HOSTS\n{_format_hosts(hosts)}"
        f"{pcap_note}"
    )

    # Run the ReAct loop manually (tool-calling loop)
    from langchain_core.messages import HumanMessage, SystemMessage, AIMessage

    # Build initial message list: system prompt, optional briefing, then task
    briefing_text = state.get("briefing_text", "").strip()
    briefing_message: list = []
    if briefing_text:
        briefing_message = [HumanMessage(content=(
            "CLIENT BRIEFING DOCUMENTS\n"
            "==========================\n"
            "The following context was provided to the investigation team by the client "
            "before analysis began. Use this to frame your investigation, but derive all "
            "findings from the log evidence — do not assert facts from the briefing as "
            "forensic findings unless confirmed by the data.\n\n"
            f"{briefing_text}"
        ))]

    messages = [
        SystemMessage(content=system_prompt),
        *briefing_message,
        HumanMessage(content=(
            "Begin your autonomous forensic investigation. Analyze the network "
            "capture for signs of compromise. Use the available tools to examine "
            "logs, record findings, and build a complete picture of any attack. "
            "Follow the TOOL CALLING CONTRACT and REQUIRED COVERAGE checklist in "
            "the system prompt. Do not conclude until coverage is complete."
        )),
    ]

    llm_with_tools = llm.bind_tools(all_tools)

    # Build a tool-name-to-function map
    tool_map = {t.name: t for t in all_tools}

    iteration = 0
    # Rolling window of the last 6 tool names — used for loop detection
    _recent_tool_names: list[str] = []
    # Rolling window of (tool_name, primary_arg) tuples for near-duplicate detection
    _recent_tool_signatures: list[tuple[str, str]] = []
    # Session-level tracking of PCAP ingestion (mirrors what the tool closure tracks,
    # but accessible here without fragile closure introspection)
    _ingested_pcaps: set[str] = set()
    _macros_run: set[str] = set()
    print(f"[INVESTIGATE] Starting autonomous ReAct investigation (max {max_iterations} iterations)...")

    while iteration < max_iterations and not state_ref["investigation_complete"]:
        iteration += 1
        print(f"  [INVESTIGATE] Iteration {iteration}/{max_iterations}...")

        # Get LLM response
        # Get LLM response (streaming to console)
        try:
            response = None
            print("    Agent thought:\n", end="", flush=True)
            for chunk in llm_with_tools.stream(messages):
                if chunk.content:
                    print(chunk.content, end="", flush=True)
                if response is None:
                    response = chunk
                else:
                    response = response + chunk
            print("\n")
        except Exception as e:
            print(f"\n  [INVESTIGATE] LLM error: {e}")
            state_ref["investigation_notes"].append(f"LLM error at iteration {iteration}: {e}")
            break

        # Record token usage (langchain-openai populates usage_metadata)
        usage = getattr(response, "usage_metadata", None) or {}
        tracker.record_llm_call(
            input_tokens=usage.get("input_tokens", 0),
            output_tokens=usage.get("output_tokens", 0),
        )

        messages.append(response)

        raw_content = response.content or ""

        # Strip <think>...</think> chain-of-thought. For models that put
        # their reasoning AND planned actions inside <think>, also try the
        # raw text — tool JSON may be embedded inside the think block.
        visible_content = _strip_thinking(raw_content)

        # Log a brief note (prefer stripped, fall back to raw snippet)
        note_text = visible_content or raw_content
        if note_text:
            state_ref["investigation_notes"].append(
                f"[Step {iteration}] {note_text[:MAX_NOTE_CHARS]}"
            )

        # Check for tool calls: native → stripped text → raw text
        if not response.tool_calls:
            response.tool_calls = _extract_tool_calls_from_text(visible_content)
        if not response.tool_calls and visible_content != raw_content:
            # Some models embed JSON inside <think>; try the full raw text
            response.tool_calls = _extract_tool_calls_from_text(raw_content)

        if not response.tool_calls:
            state_ref["investigation_notes"].append(
                f"[Step {iteration}] Agent reasoned but did not call a tool."
            )
            from langchain_core.messages import HumanMessage as _HumanMessage

            # Detect completion-ready pattern: agent describes having finished all
            # tasks but doesn't emit the tool call.
            # IMPORTANT: check only the visible (non-thinking) content to avoid
            # triggering on the model reasoning *about* mark_investigation_complete
            # while deciding it's not ready yet. Also gate on minimum work done.
            _macro_tools = {"run_initial_access_analysis", "run_lateral_movement_analysis",
                            "run_exfiltration_analysis", "run_payload_analysis"}
            _macros_called = len(_macro_tools & set(_recent_tool_names))
            _enough_work = tracker.total_tool_invocations >= 12 and _macros_called >= 2

            combined = (visible_content or "").lower()
            completion_signals = [
                "all phase 3 tasks",
                "all tasks complete",
                "i've completed all",
                "completed all phase",
                "phase 3 is complete",
                "completed the investigation",
            ]
            is_completion_ready = _enough_work and any(sig in combined for sig in completion_signals)

            if is_completion_ready:
                nudge = _HumanMessage(content=(
                    'Output exactly this and nothing else:\n'
                    '{"name": "mark_investigation_complete", "arguments": {}}'
                ))
            elif _representative_pcaps and _recent_tool_names and _recent_tool_names[-1] == "list_pcap_files":
                # Model called list_pcap_files but didn't follow through to ingest_pcap.
                _next_file = next((f for f in _representative_pcaps if f not in _ingested_pcaps), _representative_pcaps[0])
                nudge = _HumanMessage(content=(
                    f"You called list_pcap_files. Now you MUST call ingest_pcap.\n"
                    f"Output only this JSON, nothing else:\n"
                    f'{{"name": "ingest_pcap", "arguments": {{"pcap_filename": "{_next_file}"}}}}'
                ))
            else:
                valid_tools = ", ".join(sorted(tool_map.keys()))
                nudge = _HumanMessage(content=(
                    "Output a JSON tool call now. No <think> tags, no prose. "
                    "Put the JSON directly with no other text. Example:\n"
                    '{"name": "record_ioc", "arguments": {"ioc_type": "ip", "value": "1.2.3.4", "context": "Primary attacker", "source_phase": "initial_access"}}\n'
                    "If investigation is complete, output:\n"
                    '{"name": "mark_investigation_complete", "arguments": {}}\n'
                    f"Valid tools: {valid_tools}"
                ))
            messages.append(nudge)
            continue

        # Execute each tool call
        from langchain_core.messages import ToolMessage

        for tool_call in response.tool_calls:
            tool_name = tool_call.get("name", "")
            tool_args = tool_call.get("args", {})
            if not isinstance(tool_args, dict):
                tool_args = {}

            print(f"    Tool: {tool_name}({', '.join(f'{k}={repr(v)[:40]}' for k, v in tool_args.items())})")

            # Track recent tool calls for loop detection
            _recent_tool_names.append(tool_name)
            if len(_recent_tool_names) > 6:
                _recent_tool_names.pop(0)

            # Track (tool_name, primary_arg) signature for near-duplicate detection.
            # Primary arg: first string value in args (pattern, log_name, field, etc.)
            _primary_arg = next(
                (str(v)[:60] for v in tool_args.values() if isinstance(v, str)),
                "",
            )
            _recent_tool_signatures.append((tool_name, _primary_arg))
            if len(_recent_tool_signatures) > 12:
                _recent_tool_signatures.pop(0)

            tracker.record_tool_invocation()
            if tool_name in tool_map:
                invoke_args, dropped_args = _sanitize_tool_args(tool_map[tool_name], tool_args)
                if dropped_args:
                    print(
                        f"    Note: Dropped unsupported arg(s) for {tool_name}: "
                        f"{', '.join(dropped_args)}"
                    )
                try:
                    result = tool_map[tool_name].invoke(invoke_args)
                except Exception as e:
                    result = f"Tool error: {e}"
                    print(f"    Error: {e}")
            else:
                result = f"Unknown tool: {tool_name}"

            tool_output = _truncate_text(str(result), MAX_TOOL_RESULT_CHARS)
            messages.append(ToolMessage(content=tool_output, tool_call_id=tool_call["id"]))

            # Track session-level progress
            if tool_name == "ingest_pcap" and "Successfully ingested" in tool_output:
                _ingested_pcaps.add(tool_args.get("pcap_filename", ""))
            if tool_name in {"run_initial_access_analysis", "run_lateral_movement_analysis",
                             "run_exfiltration_analysis", "run_payload_analysis"}:
                _macros_run.add(tool_name)

        # Keep message history bounded. Inject a progress summary so the model
        # retains awareness of completed work after context trimming.
        _progress_parts = []
        if _ingested_pcaps:
            _progress_parts.append(
                f"PCAPs successfully ingested ({len(_ingested_pcaps)}): "
                + ", ".join(sorted(_ingested_pcaps))
            )
        if _macros_run:
            _progress_parts.append(f"Macro analysis tools completed: {', '.join(sorted(_macros_run))}")
        if state_ref["findings"]:
            _progress_parts.append(f"Findings recorded: {len(state_ref['findings'])}")
        if state_ref["iocs"]:
            _progress_parts.append(f"IOCs recorded: {len(state_ref['iocs'])}")
        _progress_summary = "\n".join(_progress_parts)
        messages = _trim_message_history(messages, _progress_summary)

        # Loop detection: repeated tool calls without progress.
        # list_pcap_files loop: called >= 2 times without ingest_pcap
        if (
            _ingest_nudge_text
            and _recent_tool_names.count("list_pcap_files") >= 2
            and "ingest_pcap" not in _recent_tool_names
        ):
            from langchain_core.messages import HumanMessage as _HM
            print("    [LOOP DETECTED] list_pcap_files called repeatedly without ingest — injecting nudge")
            messages.append(_HM(content=_ingest_nudge_text))
            _recent_tool_names.clear()

        # record_timeline_event / record_ioc loop: pure recording with no analysis
        elif _recent_tool_names.count("record_timeline_event") >= 3:
            from langchain_core.messages import HumanMessage as _HM
            print("    [LOOP DETECTED] record_timeline_event spam — nudging toward completion")
            messages.append(_HM(content=(
                "STOP recording timeline events. You have recorded enough.\n"
                "If all Phase 3 tasks are complete, call mark_investigation_complete now:\n"
                '{"name": "mark_investigation_complete", "arguments": {}}\n'
                "If Phase 3 tasks remain, call the next required micro tool instead."
            )))
            _recent_tool_names.clear()

        # Near-duplicate tool call loop: same (tool, log) pair called 3+ times in
        # the last 8 analysis calls, regardless of pattern/max_results variation.
        # Catches retry spirals where the model keeps re-querying the same log with
        # slightly different patterns or growing max_results because it wants more
        # data but the log simply does not have it.
        _skip_tools = {"record_finding", "record_ioc", "record_timeline_event",
                       "mark_investigation_complete"}
        _analysis_sigs = [s for s in _recent_tool_signatures[-8:] if s[0] not in _skip_tools]
        _stuck_sig = None
        for _sig in set(_analysis_sigs):
            if _analysis_sigs.count(_sig) >= 3:
                _stuck_sig = _sig
                break
        if _stuck_sig:
            from langchain_core.messages import HumanMessage as _HM
            print(f"    [LOOP DETECTED] {_stuck_sig[0]}('{_stuck_sig[1]}') x{_analysis_sigs.count(_stuck_sig)} — injecting nudge")
            messages.append(_HM(content=(
                f"You have queried '{_stuck_sig[1]}' with {_stuck_sig[0]} "
                f"{_analysis_sigs.count(_stuck_sig)} times and are not getting new information. "
                "Stop retrying. The data you already have is the answer — draw your conclusion from it and move on. "
                "If the log does not contain what you expected, that is itself a forensic finding worth noting. "
                "Proceed to the next Phase 3 task, or call mark_investigation_complete if all tasks are done."
            )))
            _recent_tool_signatures.clear()
            _recent_tool_names.clear()

    if iteration >= max_iterations and not state_ref["investigation_complete"]:
        print(f"  [INVESTIGATE] Hit iteration cap ({max_iterations}). Proceeding to correlation.")
        state_ref["investigation_notes"].append(
            f"Investigation stopped at iteration cap ({max_iterations})."
        )

    print(f"[INVESTIGATE] Complete: {len(state_ref['findings'])} findings, "
          f"{len(state_ref['iocs'])} IOCs, {len(state_ref['timeline_events'])} timeline events")
    if _ingested_pcaps:
        print(f"[INVESTIGATE] PCAPs ingested this session ({len(_ingested_pcaps)}/{len(_representative_pcaps)} groups):")
        for _f in sorted(_ingested_pcaps):
            print(f"  + {_f}")
    not_ingested = [f for f in _representative_pcaps if f not in _ingested_pcaps]
    if not_ingested:
        print(f"[INVESTIGATE] WARNING: {len(not_ingested)} date group(s) NOT ingested:")
        for _f in not_ingested:
            print(f"  - {_f}")

    tracker.stop()
    cost_metrics = tracker.get_metrics()

    return {
        "findings": state_ref["findings"],
        "iocs": state_ref["iocs"],
        "timeline_events": state_ref["timeline_events"],
        "investigation_notes": state_ref["investigation_notes"],
        "investigation_complete": state_ref["investigation_complete"],
        "iteration_count": iteration,
        "cost_metrics": cost_metrics,
    }

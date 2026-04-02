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
MAX_CONTEXT_MESSAGES = 60
CHARS_PER_TOKEN_ESTIMATE = 4


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


def _trim_message_history(messages: list):
    """Preserve core prompt and recent turns while trimming old context."""
    if len(messages) <= (MAX_CONTEXT_MESSAGES + 2):
        return messages

    from langchain_core.messages import SystemMessage

    original_len = len(messages)
    trimmed = messages[:2] + messages[-MAX_CONTEXT_MESSAGES:]
    trimmed.insert(
        2,
        SystemMessage(
            content=(
                f"Conversation history was truncated to keep prompt size within "
                f"model context. Kept latest {MAX_CONTEXT_MESSAGES} messages out "
                f"of {original_len}."
            )
        ),
    )
    return trimmed


def _estimate_tokens_from_text(text: str) -> int:
    """Approximate token count when provider metadata is unavailable."""
    if not text:
        return 0
    return max(1, (len(text) + CHARS_PER_TOKEN_ESTIMATE - 1) // CHARS_PER_TOKEN_ESTIMATE)


def _stringify_message_content(content) -> str:
    """Normalize message content into plain text for token estimation."""
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict):
                if "text" in item:
                    parts.append(str(item.get("text", "")))
                elif "content" in item:
                    parts.append(str(item.get("content", "")))
                else:
                    parts.append(json.dumps(item, default=str))
            else:
                parts.append(str(item))
        return "\n".join(parts)
    return str(content)


def _estimate_input_tokens(messages: list) -> int:
    """Estimate input tokens for the current prompt window."""
    total = 0
    for msg in messages:
        total += _estimate_tokens_from_text(
            _stringify_message_content(getattr(msg, "content", ""))
        )
        tool_calls = getattr(msg, "tool_calls", None)
        if tool_calls:
            total += _estimate_tokens_from_text(json.dumps(tool_calls, default=str))
    return total


def _extract_usage_tokens(response) -> tuple[int, int]:
    """Extract input/output token counts across different provider schemas."""
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


def _extract_tool_calls_from_text(content: str) -> list[dict]:
    """Parse tool calls from model text when native tool_call parsing fails.

    Supports both a single JSON object and a JSON array of objects, with keys
    ``args`` or ``arguments``.
    """
    if not content:
        return []

    candidates: list[str] = []
    for block in re.findall(r"```(?:json)?\n(.*?)\n```", content, re.DOTALL):
        candidates.append(block.strip())

    stripped = content.strip()
    if stripped.startswith("{") or stripped.startswith("["):
        candidates.append(stripped)

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


def investigate_node(state: ForensicState) -> dict:
    """Run the autonomous ReAct investigation agent.

    The agent receives the triage context and decides which tools to call.
    It loops until it calls ``mark_investigation_complete`` or hits the
    iteration cap.
    """
    config = Config()
    tracker = HybridCostTracker(
        api_input_cost_per_1k=config.api_input_cost_per_1k,
        api_output_cost_per_1k=config.api_output_cost_per_1k,
        gpu_hourly_rate=config.gpu_hourly_rate,
        gpu_description=f"Local GPU @ ${config.gpu_hourly_rate:.2f}/hr",
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
    if pcap_path and Path(pcap_path).is_dir():
        pcap_count = sum(
            1 for p in Path(pcap_path).iterdir()
            if p.suffix in (".pcap", ".pcapng")
        )
        pcap_note = (
            f"\n\n## PCAP SOURCE DIRECTORY"
            f"\nA directory of {pcap_count} PCAP file(s) is available."
            f"\n\n**PCAP Ingestion Strategy:**"
            f"\n1. Call `list_pcap_files` to see all PCAPs with timestamps and sizes."
            f"\n2. Call `ingest_pcap(filename)` to run Zeek on a specific PCAP — this "
            f"creates/updates Zeek logs in the analysis directory (takes 1-3 min per file)."
            f"\n3. After ingestion, use Zeek log tools (grep_log, read_log_head, "
            f"count_by_field, etc.) and macro analysis tools on the resulting logs."
            f"\n4. Ingest additional PCAPs as needed to expand the investigation window."
            f"\n\nYou can also use tshark DPI tools (list_pcap_protocols, apply_bpf_filter, "
            f"extract_pcap_stream, get_packet_details, extract_http_objects) directly on "
            f"any PCAP file by specifying pcap_file=<filename>."
            f"\n\nStart by listing PCAPs and ingesting a few to get initial Zeek logs. "
            f"Then analyze and decide whether to ingest more."
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

    messages = [
        SystemMessage(content=system_prompt),
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
    token_estimate_notice_logged = False
    print(f"[INVESTIGATE] Starting autonomous ReAct investigation (max {max_iterations} iterations)...")

    while iteration < max_iterations and not state_ref["investigation_complete"]:
        iteration += 1
        print(f"  [INVESTIGATE] Iteration {iteration}/{max_iterations}...")

        # Get LLM response
        # Get LLM response (streaming to console)
        estimated_input_tokens = _estimate_input_tokens(messages)
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
        input_tokens, output_tokens = _extract_usage_tokens(response)
        if input_tokens == 0 and output_tokens == 0:
            input_tokens = estimated_input_tokens
            output_tokens = _estimate_tokens_from_text(
                _stringify_message_content(getattr(response, "content", ""))
            )
            response_tool_calls = getattr(response, "tool_calls", None)
            if response_tool_calls:
                output_tokens += _estimate_tokens_from_text(
                    json.dumps(response_tool_calls, default=str)
                )
            if not token_estimate_notice_logged:
                print("    Note: Provider token metadata missing; using estimated token counts.")
                token_estimate_notice_logged = True

        tracker.record_llm_call(
            input_tokens=input_tokens,
            output_tokens=output_tokens,
        )

        messages.append(response)

        # Log reasoning to notes
        if response.content:
            note = response.content[:MAX_NOTE_CHARS]
            state_ref["investigation_notes"].append(f"[Step {iteration}] {note}")

        # Check for tool calls
        if not response.tool_calls:
            response.tool_calls = _extract_tool_calls_from_text(response.content)

        if not response.tool_calls:
            state_ref["investigation_notes"].append(
                f"[Step {iteration}] Agent reasoned but did not call a tool."
            )
            # Nudge the agent instead of aborting the whole investigation
            from langchain_core.messages import SystemMessage
            valid_tools = ", ".join(sorted(tool_map.keys()))
            nudge = SystemMessage(content=(
                "You provided reasoning but no tools were invoked. "
                "Do NOT output shell commands or explanatory prose. "
                "Invoke one or more tools now using valid tool names and valid args only. "
                "If complete, call 'mark_investigation_complete'. "
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

        # Keep message history bounded across long investigations.
        messages = _trim_message_history(messages)

    if iteration >= max_iterations and not state_ref["investigation_complete"]:
        print(f"  [INVESTIGATE] Hit iteration cap ({max_iterations}). Proceeding to correlation.")
        state_ref["investigation_notes"].append(
            f"Investigation stopped at iteration cap ({max_iterations})."
        )

    print(f"[INVESTIGATE] Complete: {len(state_ref['findings'])} findings, "
          f"{len(state_ref['iocs'])} IOCs, {len(state_ref['timeline_events'])} timeline events")

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

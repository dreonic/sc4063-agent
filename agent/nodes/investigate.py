"""Investigate node — fully autonomous ReAct agent loop.

This is the core of the agentic forensic analysis. The LLM autonomously
decides which tools to call, interprets results, and records findings.
No human interrupts occur within this loop.
"""
from __future__ import annotations

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
MAX_CONTEXT_MESSAGES = 28


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
    if pcap_path:
        pcap_note = (
            "\n\nA PCAP file is available. You can use tshark deep packet inspection "
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
            "logs, record findings, and build a complete picture of any attack."
        )),
    ]

    llm_with_tools = llm.bind_tools(all_tools)

    # Build a tool-name-to-function map
    tool_map = {t.name: t for t in all_tools}

    iteration = 0
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

        # Log reasoning to notes
        if response.content:
            note = response.content[:MAX_NOTE_CHARS]
            state_ref["investigation_notes"].append(f"[Step {iteration}] {note}")

        # Check for tool calls
        if not response.tool_calls:
            # Fallback: Sometimes local LLMs (like Qwen) output the tool call as a Markdown JSON block 
            # in the text content, but vLLM fails to parse it natively. Let's catch it manually!
            import re
            import json
            import uuid
            
            json_blocks = re.findall(r"```(?:json)?\n(.*?)\n```", response.content, re.DOTALL)
            for block in json_blocks:
                try:
                    parsed = json.loads(block.strip())
                    if isinstance(parsed, dict) and "name" in parsed:
                        response.tool_calls.append({
                            "name": parsed["name"],
                            "args": parsed.get("arguments", parsed.get("args", {})),
                            "id": f"call_{uuid.uuid4().hex[:8]}"
                        })
                except Exception:
                    pass

        if not response.tool_calls:
            state_ref["investigation_notes"].append(
                f"[Step {iteration}] Agent reasoned but did not call a tool."
            )
            # Nudge the agent instead of aborting the whole investigation
            from langchain_core.messages import SystemMessage
            nudge = SystemMessage(content=(
                "You provided reasoning but no tools were invoked. "
                "You must proceed autonomously by invoking a tool to search the logs, "
                "or call 'finish_investigation' if you have no further actions."
            ))
            messages.append(nudge)
            continue

        # Execute each tool call
        from langchain_core.messages import ToolMessage

        for tool_call in response.tool_calls:
            tool_name = tool_call["name"]
            tool_args = tool_call["args"]

            print(f"    Tool: {tool_name}({', '.join(f'{k}={repr(v)[:40]}' for k, v in tool_args.items())})")

            tracker.record_tool_invocation()
            if tool_name in tool_map:
                try:
                    result = tool_map[tool_name].invoke(tool_args)
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

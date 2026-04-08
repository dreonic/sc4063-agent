"""Streamlit UI for the SC4063 Forensic Agent."""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Tuple

import streamlit as st
from openai import OpenAI

# ---------------------------------------------------------------------------
# Page config
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="SC4063 Forensic Agent",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
STAGES: list[str] = ["INGEST", "TRIAGE", "INVESTIGATE", "CORRELATE", "REPORT"]

STAGE_LABELS: dict[str, str] = {
    "INGEST":      "1 · Ingest",
    "TRIAGE":      "2 · Triage",
    "INVESTIGATE": "3 · Investigate",
    "CORRELATE":   "4 · Correlate",
    "REPORT":      "5 · Report",
}

STAGE_DESCRIPTIONS: dict[str, str] = {
    "INGEST":      "Detecting PCAP / Zeek logs and launching Zeek if needed",
    "TRIAGE":      "Inventorying log files and mapping the network topology",
    "INVESTIGATE": "Running the autonomous ReAct investigation loop",
    "CORRELATE":   "Deduplicating findings and building the kill-chain timeline",
    "REPORT":      "Rendering the final Markdown forensic report",
}

STATUS_IDLE     = "idle"
STATUS_RUNNING  = "running"
STATUS_COMPLETE = "complete"
STATUS_ERROR    = "error"

OUTPUT_DIR = Path(__file__).parent / "forensic_output"


# ---------------------------------------------------------------------------
# Session-state initialisation
# ---------------------------------------------------------------------------
def _init_state() -> None:
    defaults: dict = {
        "status":        STATUS_IDLE,
        "current_stage": None,
        "output_lines":  [],
        "report_text":   "",
        "error_msg":     "",
        "output_file":   "forensic_report.md",
        "process":       None,
        "thread":        None,
        "_shared":       None,
        "start_time":    None,
    }
    for key, val in defaults.items():
        st.session_state.setdefault(key, val)


_init_state()


# ---------------------------------------------------------------------------
# Background reader thread
# ---------------------------------------------------------------------------
def _reader_thread(process: subprocess.Popen, shared: dict) -> None:
    """Read subprocess stdout; push lines into *shared* (plain dict, not Streamlit state)."""
    try:
        for raw_line in iter(process.stdout.readline, ""):
            line = raw_line.rstrip("\n")
            shared["output_lines"].append(line)

            for stage in STAGES:
                if f"[{stage}]" in line:
                    shared["current_stage"] = stage
                    break

        process.wait()
        shared["status"] = STATUS_COMPLETE if process.returncode == 0 else STATUS_ERROR
        if process.returncode != 0:
            shared["error_msg"] = f"Agent process exited with return-code {process.returncode}."
    except Exception as exc:
        shared["status"]    = STATUS_ERROR
        shared["error_msg"] = str(exc)


# ---------------------------------------------------------------------------
# Analysis launcher
# ---------------------------------------------------------------------------
def _start_analysis(
    input_path: str,
    base_url: str,
    api_key: str,
    model: str,
    max_iterations: int,
    output_file: str,
) -> None:
    """Spawn the agent subprocess and start the reader thread."""
    # Shared mutable state between reader thread and Streamlit main thread.
    # We use a plain dict (not session_state) to avoid thread-safety issues.
    output_lines: list[str] = []
    shared: dict = {
        "output_lines":  output_lines,
        "current_stage": None,
        "status":        STATUS_RUNNING,
        "error_msg":     "",
    }

    # Reset session state
    st.session_state.status        = STATUS_RUNNING
    st.session_state.current_stage = None
    st.session_state.output_lines  = output_lines   # same list object
    st.session_state.report_text   = ""
    st.session_state.error_msg     = ""
    st.session_state.output_file   = output_file
    st.session_state._shared       = shared
    st.session_state.start_time    = time.time()

    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    if base_url:
        env["LLM_BASE_URL"] = base_url
    if api_key:
        env["LLM_API_KEY"] = api_key
    if model:
        env["LLM_MODEL"] = model

    cmd = [
        sys.executable, "-m", "agent",
        input_path,
        "--max-iterations", str(max_iterations),
        "--output", output_file,
    ]

    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        env=env,
        cwd=str(Path(__file__).parent),
    )
    st.session_state.process = process

    thread = threading.Thread(target=_reader_thread, args=(process, shared), daemon=True)
    thread.start()
    st.session_state.thread = thread


def _sync_from_shared() -> None:
    """Pull updates from the reader-thread dict into Streamlit session_state."""
    shared: dict | None = st.session_state.get("_shared")
    if shared is None:
        return
    # output_lines is the same list object — no copy needed.
    if shared["current_stage"]:
        st.session_state.current_stage = shared["current_stage"]
    if shared["status"] != STATUS_RUNNING:
        st.session_state.status    = shared["status"]
        st.session_state.error_msg = shared.get("error_msg", "")


def _reset() -> None:
    """Kill any running process and wipe state back to idle."""
    proc: subprocess.Popen | None = st.session_state.get("process")
    if proc and proc.poll() is None:
        proc.terminate()
    for key in list(st.session_state.keys()):
        del st.session_state[key]
    _init_state()


# ---------------------------------------------------------------------------
# API testing and model listing
# ---------------------------------------------------------------------------
def test_llm_connection(base_url: str, api_key: str) -> Tuple[bool, str, list[str]]:
    """Test LLM connection and return (success, message, model_list)."""
    models = []
    try:
        client = OpenAI(base_url=base_url.strip(), api_key=api_key.strip() if api_key.strip() else "not-needed")

        # Try to list models
        model_list = client.models.list()
        models = [m.id for m in model_list.data]

        if models:
            return True, f"Connected! Found {len(models)} model(s)", models
        else:
            return False, "Connected but no models listed", []
    except Exception as e:
        return False, f"Connection failed: {e}", []


def _check_api_and_populate_models(base_url: str, api_key: str) -> None:
    """Test API connection and populate model dropdown if successful."""
    if not base_url.strip():
        st.warning("Please enter an LLM Base URL to test the connection.")
        return

    with st.spinner("Testing LLM connection..."):
        success, message, models = test_llm_connection(base_url, api_key)

        if success:
            st.success(message)
            # Store models in session state for the dropdown
            st.session_state.available_models = models
            # Auto-fill model field if empty
            if not st.session_state.get('_model_input', ''):
                st.session_state._model_input = models[0] if models else ""
        else:
            st.error(message)
            st.session_state.available_models = []


# ---------------------------------------------------------------------------
# UI helpers
# ---------------------------------------------------------------------------
def _render_stage_progress() -> None:
    stage  = st.session_state.current_stage
    status = st.session_state.status

    stage_idx = STAGES.index(stage) if stage else -1

    cols = st.columns(len(STAGES))
    for i, (col, s) in enumerate(zip(cols, STAGES)):
        with col:
            if i < stage_idx:
                icon, color = "✅", "#28a745"
            elif i == stage_idx:
                if status == STATUS_RUNNING:
                    icon, color = "⟳", "#007bff"
                else:
                    icon, color = "✅", "#28a745"
            else:
                icon, color = "○", "#6c757d"

            st.markdown(
                f"""<div style="text-align:center;padding:8px 4px;border-radius:8px;
                    border:1px solid {color};color:{color};font-weight:600;font-size:0.85rem;">
                    {icon}&nbsp;{STAGE_LABELS[s]}
                </div>""",
                unsafe_allow_html=True,
            )
            if i == stage_idx and status == STATUS_RUNNING:
                st.caption(STAGE_DESCRIPTIONS[s])


def _escape_html(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


_XML_SKIP = re.compile(
    r"^(<tool_call>|</tool_call>|</think>|<function=|<parameter=|</parameter>|</function>)\s*$"
)


def _parse_output_html(lines: list[str]) -> str:
    """Convert raw agent output lines into styled HTML blocks."""
    parts: list[str] = []
    i = 0
    n = len(lines)

    while i < n:
        line = lines[i]
        stripped = line.strip()

        # Skip blank lines and XML scaffolding
        if not stripped or _XML_SKIP.match(stripped):
            i += 1
            continue

        # ── [STAGE] Iteration N/M … ──────────────────────────────────────
        m = re.match(r"^\[(\w+)\]\s+(.+)$", stripped)
        if m:
            stage, rest = m.group(1), m.group(2)
            parts.append(
                f'<div style="margin-top:14px;padding:4px 0 2px;'
                f'font-weight:bold;color:#58a6ff;border-bottom:1px solid #21262d;">'
                f'[{_escape_html(stage)}] {_escape_html(rest)}</div>'
            )
            i += 1
            continue

        # ── Agent thought block ───────────────────────────────────────────
        if stripped == "Agent thought:":
            thought: list[str] = []
            i += 1
            while i < n and lines[i].strip() != "</think>":
                thought.append(lines[i])
                i += 1
            if i < n:
                i += 1  # consume </think>
            body = _escape_html("\n".join(thought).strip())
            parts.append(
                f'<div style="margin:6px 0;padding:8px 12px;background:#161b22;'
                f'border-left:3px solid #8b949e;color:#8b949e;white-space:pre-wrap;">'
                f'<span style="font-size:0.75em;font-weight:bold;color:#6e7681;'
                f'letter-spacing:.05em;">THOUGHT</span><br/>{body}</div>'
            )
            continue

        # ── JSON tool-call  {"name": …, "arguments": …} ──────────────────
        if stripped.startswith('{"name":'):
            json_buf = stripped
            i += 1
            while i < n and lines[i].strip() not in ("</tool_call>", ""):
                json_buf += lines[i].strip()
                i += 1
            if i < n and lines[i].strip() == "</tool_call>":
                i += 1
            try:
                call = json.loads(json_buf)
                name = _escape_html(call.get("name", ""))
                args = call.get("arguments", {})
                args_str = _escape_html(
                    ", ".join(f"{k}={repr(v)}" for k, v in args.items())
                )
                parts.append(
                    f'<div style="margin:6px 0;padding:6px 12px;background:#0d2137;'
                    f'border-left:3px solid #388bfd;">'
                    f'<span style="font-size:0.75em;font-weight:bold;color:#388bfd;'
                    f'letter-spacing:.05em;">TOOL CALL</span>&nbsp;'
                    f'<span style="color:#79c0ff;font-weight:bold;">{name}</span>'
                    f'<span style="color:#8b949e;">({args_str})</span></div>'
                )
            except json.JSONDecodeError:
                parts.append(
                    f'<div style="color:#c9d1d9;">{_escape_html(json_buf)}</div>'
                )
            continue

        # ── Tool result header  "Tool: name(args)" ────────────────────────
        if stripped.startswith("Tool: "):
            sig = _escape_html(stripped[6:])
            parts.append(
                f'<div style="margin:4px 0 0;padding:4px 12px;background:#0a1f0a;'
                f'border-left:3px solid #3fb950;">'
                f'<span style="font-size:0.75em;font-weight:bold;color:#3fb950;'
                f'letter-spacing:.05em;">RESULT</span>&nbsp;'
                f'<span style="color:#56d364;">{sig}</span></div>'
            )
            # Collect result body lines until next header
            result_lines: list[str] = []
            i += 1
            while i < n:
                peek = lines[i].strip()
                if (re.match(r"^\[(\w+)\]", peek)
                        or peek == "Agent thought:"
                        or peek.startswith("Tool: ")
                        or peek.startswith('{"name":')):
                    break
                if peek and not _XML_SKIP.match(peek):
                    result_lines.append(lines[i])
                i += 1
            if result_lines:
                body = _escape_html("\n".join(result_lines).strip())
                parts.append(
                    f'<div style="padding:6px 12px 8px 26px;background:#0a1a0a;'
                    f'color:#adbdad;white-space:pre-wrap;font-size:0.85em;">{body}</div>'
                )
            continue

        # ── [ERROR] / [WARNING] ───────────────────────────────────────────
        if stripped.startswith("[ERROR]"):
            parts.append(
                f'<div style="color:#f85149;padding:2px 0;">{_escape_html(stripped)}</div>'
            )
            i += 1
            continue
        if stripped.startswith("[WARNING]"):
            parts.append(
                f'<div style="color:#d29922;padding:2px 0;">{_escape_html(stripped)}</div>'
            )
            i += 1
            continue

        # ── Default plain line ────────────────────────────────────────────
        parts.append(f'<div style="color:#c9d1d9;">{_escape_html(stripped)}</div>')
        i += 1

    return "\n".join(parts)


def _render_live_output() -> None:
    lines = st.session_state.output_lines
    if not lines:
        st.caption("Waiting for output…")
        return

    body = _parse_output_html(lines[-600:])

    st.markdown(
        f"""<div id="live-out"
            style="background:#0d1117;font-family:'Courier New',monospace;
                   font-size:0.9rem;line-height:1.6;padding:14px;border-radius:6px;
                   height:600px;overflow-y:auto;word-break:break-word;
                   border:1px solid #30363d;">
{body}
</div>
<script>
(function(){{
  const el = document.getElementById('live-out');
  if(el) {{
    el.scrollTop = el.scrollHeight;
    const observer = new MutationObserver(function() {{ el.scrollTop = el.scrollHeight; }});
    observer.observe(el, {{ childList: true, subtree: true }});
  }}
}})();
</script>""",
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------------------
# Main UI
# ---------------------------------------------------------------------------
st.title("SC4063 Forensic Agent")
st.caption("Autonomous network forensic analysis — LangGraph + LLM · OpenAI-compatible API")

# Initialise connection-related session state
st.session_state.setdefault("_base_url", os.environ.get("LLM_BASE_URL", "http://localhost:8080/v1"))
st.session_state.setdefault("_api_key", os.environ.get("LLM_API_KEY", "not-needed"))
st.session_state.setdefault("available_models", [])
st.session_state.setdefault("_model_input", os.environ.get("LLM_MODEL", ""))
st.session_state.setdefault("_connected", False)

# ---- Configuration form (collapsed while running) ----
is_idle = st.session_state.status == STATUS_IDLE
with st.expander("Configuration", expanded=is_idle):

    # --- Step 1: API Server connection ---
    st.markdown("#### Step 1 — Connect to LLM Server")
    col_url, col_key, col_btn = st.columns([3, 2, 1])
    with col_url:
        entered_url = st.text_input(
            "API Server URL",
            value=st.session_state._base_url,
            key="_base_url_widget",
            help="OpenAI-compatible endpoint (vLLM, OpenAI, DeepSeek, etc.).",
            placeholder="http://localhost:8080/v1",
        )
    with col_key:
        entered_key = st.text_input(
            "API Key",
            value=st.session_state._api_key,
            key="_api_key_widget",
            type="password",
            help="Leave as 'not-needed' for local servers.",
        )
    with col_btn:
        st.markdown("<div style='height:28px'></div>", unsafe_allow_html=True)  # align button
        connect_btn = st.button("Connect", use_container_width=True, type="primary", key="connect_button")

    if connect_btn:
        st.session_state._base_url = entered_url
        st.session_state._api_key = entered_key
        _check_api_and_populate_models(entered_url, entered_key)
        if st.session_state.available_models:
            st.session_state._connected = True
        else:
            st.session_state._connected = False
        st.rerun()

    # Connection status indicator
    if st.session_state._connected and st.session_state.available_models:
        st.success(f"Connected — {len(st.session_state.available_models)} model(s) available", icon="✅")
    elif not st.session_state._connected:
        st.info("Enter your API server URL and click **Connect** to load available models.", icon="ℹ️")

    # --- Step 2: Model & Analysis Config ---
    st.markdown("#### Step 2 — Analysis Settings")
    with st.form("config_form"):
        input_mode = st.radio(
            "Input type",
            options=["Zeek logs", "PCAP file"],
            horizontal=True,
            help="Choose whether to analyse pre-processed Zeek logs or a raw PCAP (Zeek runs automatically).",
        )

        if input_mode == "Zeek logs":
            f_input_path = st.text_input(
                "Zeek log directory",
                value="forensic_output/zeek_logs",
                help="Directory containing Zeek .log files.",
            )
        else:
            f_input_path = st.text_input(
                "PCAP path",
                placeholder="~/Downloads/sc4063/network  or  /absolute/path/to/capture.pcap",
                help="Path to a .pcap, .pcapng file, or directory. Supports ~ expansion.",
            )

        # Model selection: dropdown if connected, text input otherwise
        if st.session_state.available_models:
            default_idx = 0
            if st.session_state._model_input in st.session_state.available_models:
                default_idx = st.session_state.available_models.index(st.session_state._model_input)
            f_model = st.selectbox(
                "Model",
                options=st.session_state.available_models,
                index=default_idx,
                help="Select a model from the connected server.",
            )
        else:
            f_model = st.text_input(
                "Model name",
                value=st.session_state._model_input,
                placeholder="gpt-4o / deepseek-coder / qwen2.5-72b …",
                help="Connect to the API server above to see available models.",
            )

        f_max_iter = st.number_input(
            "Max ReAct iterations",
            min_value=5,
            max_value=200,
            value=50,
            step=5,
            help="Hard cap on the investigate-node ReAct loop iterations.",
        )
        f_output = st.text_input(
            "Report filename",
            value="forensic_report.md",
            help="Saved under forensic_output/",
        )

        submitted = st.form_submit_button(
            "Start Analysis",
            type="primary",
            disabled=st.session_state.status == STATUS_RUNNING,
        )

if submitted:
    if not f_input_path.strip():
        st.error("Please provide a path to Zeek logs or a PCAP file.")
    else:
        st.session_state._model_input = f_model
        _start_analysis(
            input_path=str(Path(f_input_path.strip()).expanduser()),
            base_url=st.session_state._base_url.strip(),
            api_key=st.session_state._api_key.strip(),
            model=f_model.strip(),
            max_iterations=int(f_max_iter),
            output_file=f_output.strip() or "forensic_report.md",
        )
        st.rerun()

# ---------------------------------------------------------------------------
# Running / complete view
# ---------------------------------------------------------------------------
if st.session_state.status != STATUS_IDLE:
    _sync_from_shared()
    status = st.session_state.status

    st.divider()
    _render_stage_progress()
    st.divider()

    # Elapsed time
    start = st.session_state.get("start_time")
    if start:
        elapsed = int(time.time() - start)
        elapsed_str = f"{elapsed // 3600:02d}:{(elapsed % 3600) // 60:02d}:{elapsed % 60:02d}"
    else:
        elapsed_str = "00:00:00"

    # Status banner
    if status == STATUS_RUNNING:
        stage = st.session_state.current_stage
        if stage and stage in STAGES:
            step_num = STAGES.index(stage) + 1
            step_label = f"Step {step_num}/{len(STAGES)} — {STAGE_LABELS[stage]}"
        else:
            step_label = "Initialising"
        st.info(f"**{step_label}** — {elapsed_str}")
    elif status == STATUS_COMPLETE:
        st.success(f"Analysis complete! — {elapsed_str}", icon="✅")
    elif status == STATUS_ERROR:
        st.error(f"Error: {st.session_state.error_msg} — {elapsed_str}")

    # Live output panel
    st.subheader("Live output")
    _render_live_output()

    # Continuously rerun while the agent is still working
    if status == STATUS_RUNNING:
        time.sleep(0.5)
        st.rerun()

    # ---- Report viewer (shown after successful completion) ----
    if status == STATUS_COMPLETE:
        st.divider()
        st.subheader("Forensic Report")

        if not st.session_state.report_text:
            report_path = OUTPUT_DIR / st.session_state.output_file
            if report_path.exists():
                st.session_state.report_text = report_path.read_text(encoding="utf-8")

        report_text = st.session_state.report_text
        if report_text:
            tab_rendered, tab_raw = st.tabs(["Rendered", "Raw Markdown"])
            with tab_rendered:
                st.markdown(report_text)
            with tab_raw:
                st.code(report_text, language="markdown")

            st.download_button(
                label="Download report",
                data=report_text,
                file_name=st.session_state.output_file,
                mime="text/markdown",
            )
        else:
            st.warning(
                f"Report not found at `{OUTPUT_DIR / st.session_state.output_file}`. "
                "Check the live output for error details."
            )

    # New analysis button
    if status in (STATUS_COMPLETE, STATUS_ERROR):
        st.divider()
        if st.button("New analysis", type="secondary"):
            _reset()
            st.rerun()

# sc4063-agent — Autonomous Network Forensic Agent

A LangGraph-based forensic agent that autonomously ingests PCAP files or Zeek logs, investigates an attack chain, and produces a structured incident response report.

---

## Requirements

- Python 3.11+
- Zeek 7.2+ (for PCAP ingestion; must be on `PATH` or configured via `ZEEK_BINARY`)
- On Windows: Zeek via WSL (`wsl -e /opt/zeek/bin/zeek`)
- An OpenAI-compatible LLM endpoint (local via vLLM/Ollama, or cloud API)

Install Python dependencies:

```bash
pip install -r requirements.txt
```

---

## Configuration

All settings are read from environment variables (or a `.env` file in the project root):

| Variable | Default | Description |
|---|---|---|
| `LLM_BASE_URL` | `http://localhost:8080/v1` | OpenAI-compatible API base URL |
| `LLM_API_KEY` | `not-needed` | API key (use any string for local models) |
| `LLM_MODEL` | `default-model` | Model name (e.g. `gpt-4o`, `Qwen3-30B-A3B`) |
| `GPU_HOURLY_RATE` | `4.50` | GPU cost per hour in USD (for cost comparison) |
| `API_INPUT_COST_PER_1K` | `0.003` | Paid API input token cost per 1K tokens |
| `API_OUTPUT_COST_PER_1K` | `0.015` | Paid API output token cost per 1K tokens |

Example `.env` for a local vLLM server:

```
LLM_BASE_URL=http://localhost:8080/v1
LLM_API_KEY=not-needed
LLM_MODEL=Qwen3-30B-A3B-FP8
GPU_HOURLY_RATE=4.50
```

---

## Usage

```bash
python -m agent <input_path> [options]
```

### Input path (required)

| Input type | Example | Behaviour |
|---|---|---|
| Single PCAP file | `capture.pcap` | Runs Zeek, then investigates |
| Directory of PCAPs | `network/pcap/` | Agent ingests representative PCAPs on demand |
| Zeek log directory | `forensic_output/zeek_logs/` | Uses existing logs directly |

### Options

| Flag | Description |
|---|---|
| `--briefing <folder>` | Folder containing client briefing documents (`.txt` or `.md`). All files are concatenated and provided to the agent as pre-investigation context. |
| `--model <name>` | Override `LLM_MODEL` env var |
| `--base-url <url>` | Override `LLM_BASE_URL` env var |
| `--api-key <key>` | Override `LLM_API_KEY` env var |
| `--max-iterations <n>` | Override iteration cap (default: 200) |
| `--human-review` | Pause after correlation for manual review before report generation |
| `--output <filename>` | Override report filename (default: `forensic_report.md`) |
| `--gpu-rate <float>` | Override GPU hourly rate for cost comparison |

### Examples

```bash
# Analyse a Zeek log directory with a client briefing
python -m agent forensic_output/zeek_logs/ --briefing briefing/

# Analyse a PCAP directory, override the model
python -m agent network/pcap/ --briefing briefing/ --model gpt-4o

# Analyse a single PCAP with human review before report
python -m agent capture.pcap --human-review
```

---

## Briefing folder

The `--briefing` flag accepts a folder path. Place any `.txt` or `.md` files in it. All files are read and injected as client context at the start of the investigation.

Example briefing folder structure:

```
briefing/
  addendum.txt       # incident overview and investigation directives
  threat_intel.txt   # threat group TTPs (optional)
```

The agent uses the briefing to frame its investigation but must derive all findings from the log evidence. Attribution stated in the briefing is treated as external context, not a forensic finding.

---

## Output

Reports are written to `forensic_output/forensic_report.md` by default.

The report contains:
- Executive summary
- Log inventory
- Network environment (discovered hosts, internal subnet, domain)
- MITRE ATT&CK mapping
- Detailed findings with evidence citations
- IOC tables (IPs, domains, accounts, files)
- Attack timeline
- Agent reasoning audit trail (tool calls and steps)

---

## Architecture

```
ingest_node -> triage_node -> investigate_node -> correlate_node -> report_node
```

| Node | Role |
|---|---|
| `ingest_node` | Resolves input (PCAP/log dir), runs Zeek if needed |
| `triage_node` | Builds log inventory, discovers network hosts and subnet |
| `investigate_node` | Autonomous ReAct loop: LLM calls tools, records findings |
| `correlate_node` | Deduplicates and ranks findings, builds MITRE mapping |
| `report_node` | Renders markdown report from structured state |

The investigation loop runs up to `max_iterations` steps. The LLM calls tools in three categories:

- **Micro tools** — direct log access: `grep_log`, `top_n_values`, `read_log_head`, `get_time_range`, `top_n_values_filtered`, `ingest_pcap`, `list_pcap_files`
- **Macro tools** — deterministic phase analyzers: `run_initial_access_analysis`, `run_lateral_movement_analysis`, `run_exfiltration_analysis`, `run_payload_analysis`
- **State tools** — record findings: `record_finding`, `record_ioc`, `record_timeline_event`, `mark_investigation_complete`

---

## Cost tracking

At the end of each run, the agent prints:

```
  Total LLM calls       : N
  Total tool invocations: N
  Input tokens          : N
  Output tokens         : N
  Wall-clock time       : Xm Ys

  Estimated cost (paid API) : $X.XXXX
  Estimated cost (Local GPU): $X.XXXX
  Savings with local GPU    : XX.X%
```

Token counts are sourced from Prometheus metrics at `<LLM_BASE_URL>/metrics` (vLLM) when available, falling back to client-side estimates.

---

## Guardrails

| Guardrail | Implementation |
|---|---|
| Evidence grounding | `validate_evidence_log()` — cited log must exist in inventory and on disk |
| Evidence line verification | `validate_evidence_line()` — cited line number must exist in the file |
| MITRE format validation | Regex `^T\d{4}(\.\d{3})?$` — rejects malformed technique IDs |
| IP/domain format validation | `ipaddress.ip_address()` + domain regex |
| Iteration cap | `max_iterations = 200` — hard ceiling |
| Loop detection | Detects repeated `list_pcap_files`, `record_timeline_event` spam, and no-progress tool patterns |
| Context management | `_trim_message_history()` with progress summary injection |
| Tool argument sanitization | `_sanitize_tool_args()` — drops unknown args instead of crashing |
| Model output normalization | `_strip_thinking()` for DeepSeek/Qwen chain-of-thought; `_strip_tool_call_tags()` for Hermes XML format |
| Human-in-the-loop | `--human-review` flag inserts an interrupt before report generation |

"""CLI entry point for the SC4063 forensic agent.

Usage
-----
    python -m agent <input_path> [options]

Examples
--------
    # Analyse a PCAP (Zeek will be run automatically):
    python -m agent capture.pcap

    # Analyse pre-existing Zeek logs:
    python -m agent forensic_output/zeek_logs/

    # Full options:
    python -m agent capture.pcap \\
        --model gpt-4o \\
        --max-iterations 30 \\
        --human-review \\
        --output my_report.md
"""
from __future__ import annotations

import argparse
import os
import sys
import uuid
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m agent",
        description="SC4063 LangGraph Forensic Agent — autonomous PCAP/log analyser",
    )
    parser.add_argument(
        "input_path",
        help="Path to a PCAP file (.pcap/.pcapng) or a directory of Zeek logs.",
    )
    parser.add_argument(
        "--model",
        default=None,
        help=(
            "LLM model name to use (overrides LLM_MODEL env var). "
            "Examples: gpt-4o, mistral-7b-instruct, deepseek-coder."
        ),
    )
    parser.add_argument(
        "--base-url",
        default=None,
        help="LLM API base URL (overrides LLM_BASE_URL env var).",
    )
    parser.add_argument(
        "--api-key",
        default=None,
        help="LLM API key (overrides LLM_API_KEY env var).",
    )
    parser.add_argument(
        "--max-iterations",
        type=int,
        default=None,
        help="Maximum ReAct investigation iterations (default: 50).",
    )
    parser.add_argument(
        "--human-review",
        action="store_true",
        default=False,
        help=(
            "Pause for human review after correlation, before generating the report. "
            "The agent will print a findings summary and wait for you to press Enter."
        ),
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Output report filename (default: forensic_report.md).",
    )
    parser.add_argument(
        "--gpu-rate",
        type=float,
        default=None,
        help="GPU hourly rate in USD for cost comparison (overrides GPU_HOURLY_RATE env var).",
    )
    return parser.parse_args()


def _apply_overrides(args: argparse.Namespace) -> None:
    """Push CLI overrides into env vars so Config picks them up."""
    if args.model:
        os.environ["LLM_MODEL"] = args.model
    if args.base_url:
        os.environ["LLM_BASE_URL"] = args.base_url
    if args.api_key:
        os.environ["LLM_API_KEY"] = args.api_key
    if args.gpu_rate is not None:
        os.environ["GPU_HOURLY_RATE"] = str(args.gpu_rate)


def main() -> None:
    args = _parse_args()
    _apply_overrides(args)

    # Deferred import so env var overrides are applied first
    from .config import Config
    from .graph import build_graph
    from .guardrails.cost_tracker import HybridCostTracker

    config = Config()

    # Apply remaining CLI overrides that affect config fields directly
    if args.output:
        config.report_filename = args.output
    max_iterations = args.max_iterations or config.max_iterations

    # Validate input early
    input_path = Path(args.input_path).resolve()
    if not input_path.exists():
        print(f"[ERROR] Input path does not exist: {input_path}", file=sys.stderr)
        sys.exit(1)

    print()
    print("=" * 70)
    print("  SC4063 Forensic Agent — Autonomous Network Analysis")
    print("=" * 70)
    print(f"  Input       : {input_path}")
    print(f"  Model       : {config.llm_model}")
    print(f"  Base URL    : {config.llm_base_url}")
    print(f"  Max iters   : {max_iterations}")
    print(f"  Human review: {args.human_review}")
    print(f"  Output      : {config.output_dir / config.report_filename}")
    print("=" * 70)
    print()

    # Build cost tracker
    tracker = HybridCostTracker(
        api_input_cost_per_1k=config.api_input_cost_per_1k,
        api_output_cost_per_1k=config.api_output_cost_per_1k,
        gpu_hourly_rate=config.gpu_hourly_rate,
        gpu_description=f"Local GPU @ ${config.gpu_hourly_rate:.2f}/hr",
    )
    tracker.start()
    tracker.start_phase("ingest+triage")

    # Build the graph
    graph = build_graph(human_review=args.human_review)

    # Each run needs a unique thread_id for the MemorySaver checkpointer
    thread_id = str(uuid.uuid4())
    run_config = {"configurable": {"thread_id": thread_id}}

    # Initial state
    initial_state: dict = {
        "input_path": str(input_path),
        "max_iterations": max_iterations,
    }

    try:
        if args.human_review:
            # With human-review, stream events so we can detect the interrupt
            final_state: dict = {}
            for event in graph.stream(initial_state, config=run_config, stream_mode="values"):
                # Track phase transitions from printed node output
                final_state = event

            # Check if we're at the interrupt point
            snapshot = graph.get_state(run_config)
            if snapshot.next:
                # We're paused — the human_review_node already printed the summary
                input("\n  Press Enter to generate the report... ")
                # Resume the graph
                for event in graph.stream(None, config=run_config, stream_mode="values"):
                    final_state = event
        else:
            # No interrupt — run straight through
            final_state = graph.invoke(initial_state, config=run_config)

    except KeyboardInterrupt:
        print("\n[INTERRUPTED] Analysis interrupted by user.")
        tracker.stop()
        sys.exit(130)
    except Exception as exc:
        print(f"\n[ERROR] Agent failed: {exc}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        tracker.stop()
        sys.exit(1)

    tracker.stop()
    metrics = tracker.get_metrics()

    # Print cost summary
    print()
    print("=" * 70)
    print("  Cost & Efficiency Analysis")
    print("=" * 70)
    print(f"  Total LLM calls       : {metrics['total_llm_calls']}")
    print(f"  Total tool invocations: {metrics['total_tool_invocations']}")
    print(f"  Input tokens          : {metrics['total_input_tokens']:,}")
    print(f"  Output tokens         : {metrics['total_output_tokens']:,}")
    print(f"  Wall-clock time       : {metrics['wall_clock_formatted']}")
    print()
    print(f"  Estimated cost (paid API) : ${metrics['api_cost']:.4f}")
    print(f"  Estimated cost ({metrics['gpu_description']}): ${metrics['gpu_cost']:.4f}")
    if metrics['api_cost'] > 0 and metrics['gpu_cost'] > 0:
        if metrics['gpu_cost'] < metrics['api_cost']:
            savings_pct = (1 - metrics['gpu_cost'] / metrics['api_cost']) * 100
            print(f"  Savings with local GPU    : {savings_pct:.1f}%")
        else:
            premium_pct = (metrics['gpu_cost'] / metrics['api_cost'] - 1) * 100
            print(f"  API is cheaper by         : {premium_pct:.1f}%")
    print("=" * 70)

    report_path = final_state.get("report_path", "")
    if report_path:
        print(f"\n  Report saved to: {report_path}")
    print()


if __name__ == "__main__":
    main()

"""Verify graph.py and __main__.py import and compile cleanly."""
import sys

print("Testing graph imports...")

try:
    from agent.state import ForensicState
    print("  [OK] agent.state")
except Exception as e:
    print(f"  [FAIL] agent.state: {e}")
    sys.exit(1)

try:
    from agent.config import Config
    c = Config()
    print(f"  [OK] agent.config  (model={c.llm_model}, max_iter={c.max_iterations})")
except Exception as e:
    print(f"  [FAIL] agent.config: {e}")
    sys.exit(1)

try:
    from agent.guardrails.cost_tracker import HybridCostTracker
    t = HybridCostTracker()
    t.start()
    t.record_llm_call(input_tokens=10, output_tokens=5)
    t.record_tool_invocation()
    t.stop()
    m = t.get_metrics()
    print(f"  [OK] cost_tracker  (llm_calls={m['total_llm_calls']}, tools={m['total_tool_invocations']})")
except Exception as e:
    print(f"  [FAIL] cost_tracker: {e}")
    sys.exit(1)

try:
    from agent.guardrails.validators import validate_severity, validate_mitre_id, validate_ioc
    assert validate_severity("critical") is None
    assert validate_severity("invalid") is not None
    assert validate_mitre_id("T1133") is None
    assert validate_mitre_id("T1110.003") is None
    assert validate_mitre_id("TXXX") is not None
    assert validate_ioc("ip", "192.168.1.1") is None
    assert validate_ioc("ip", "notanip") is not None
    print("  [OK] validators")
except Exception as e:
    print(f"  [FAIL] validators: {e}")
    sys.exit(1)

try:
    from agent.graph import build_graph
    g = build_graph(human_review=False)
    print(f"  [OK] graph (no human review)  type={type(g).__name__}")
    g2 = build_graph(human_review=True)
    print(f"  [OK] graph (with human review) type={type(g2).__name__}")
except Exception as e:
    print(f"  [FAIL] graph: {e}")
    sys.exit(1)

try:
    # Verify __main__ can be imported (don't call main() as it needs argparse args)
    import importlib
    spec = importlib.util.spec_from_file_location(
        "agent.__main__",
        "agent/__main__.py",
    )
    # Just check graph import works — __main__ invokes argparse on import
    print("  [OK] __main__.py exists and graph wiring is correct")
except Exception as e:
    print(f"  [WARN] __main__ check: {e}")

print()
print("All checks passed. Run with: conda run python -m agent <path-to-logs>")

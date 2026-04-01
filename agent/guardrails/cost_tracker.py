"""Hybrid cost tracker — tracks token usage (API cost) and wall-clock time (GPU cost) simultaneously."""
from __future__ import annotations

import time
from typing import Any


class HybridCostTracker:
    """Tracks both token-based API pricing and compute-time GPU pricing.

    Usage::

        tracker = HybridCostTracker(api_input_cost_per_1k=0.003, ...)
        tracker.start()
        # ... run the agent ...
        tracker.stop()
        metrics = tracker.get_metrics()
    """

    def __init__(
        self,
        api_input_cost_per_1k: float = 0.003,
        api_output_cost_per_1k: float = 0.015,
        gpu_hourly_rate: float = 4.50,
        gpu_description: str = "H200 @ $4.50/hr",
    ):
        self.api_input_cost_per_1k = api_input_cost_per_1k
        self.api_output_cost_per_1k = api_output_cost_per_1k
        self.gpu_hourly_rate = gpu_hourly_rate
        self.gpu_description = gpu_description

        self.total_input_tokens: int = 0
        self.total_output_tokens: int = 0
        self.total_llm_calls: int = 0
        self.total_tool_invocations: int = 0

        self._wall_start: float = 0.0
        self._wall_end: float = 0.0
        self._phase_times: dict[str, float] = {}
        self._phase_start: float = 0.0
        self._current_phase: str = ""

    def start(self) -> None:
        """Mark the start of the analysis run."""
        self._wall_start = time.time()

    def stop(self) -> None:
        """Mark the end of the analysis run."""
        self._wall_end = time.time()
        if self._current_phase:
            self._phase_times[self._current_phase] = (
                self._phase_times.get(self._current_phase, 0)
                + (self._wall_end - self._phase_start)
            )
            self._current_phase = ""

    def start_phase(self, phase_name: str) -> None:
        """Start tracking time for a specific phase."""
        if self._current_phase:
            self._phase_times[self._current_phase] = (
                self._phase_times.get(self._current_phase, 0)
                + (time.time() - self._phase_start)
            )
        self._current_phase = phase_name
        self._phase_start = time.time()

    def record_llm_call(self, input_tokens: int = 0, output_tokens: int = 0) -> None:
        """Record a single LLM invocation with token counts."""
        self.total_llm_calls += 1
        self.total_input_tokens += input_tokens
        self.total_output_tokens += output_tokens

    def record_tool_invocation(self) -> None:
        """Record a tool invocation."""
        self.total_tool_invocations += 1

    @property
    def wall_clock_seconds(self) -> float:
        end = self._wall_end if self._wall_end else time.time()
        return end - self._wall_start if self._wall_start else 0.0

    @property
    def api_cost(self) -> float:
        """Estimated cost if running on a paid API."""
        input_cost = (self.total_input_tokens / 1000) * self.api_input_cost_per_1k
        output_cost = (self.total_output_tokens / 1000) * self.api_output_cost_per_1k
        return input_cost + output_cost

    @property
    def gpu_cost(self) -> float:
        """Estimated cost of local GPU execution."""
        hours = self.wall_clock_seconds / 3600
        return hours * self.gpu_hourly_rate

    def _format_duration(self, seconds: float) -> str:
        if seconds < 60:
            return f"{seconds:.1f}s"
        minutes = int(seconds // 60)
        secs = seconds % 60
        return f"{minutes}m {secs:.0f}s"

    def get_metrics(self) -> dict[str, Any]:
        """Return all metrics as a dict suitable for the report."""
        return {
            "total_llm_calls": self.total_llm_calls,
            "total_tool_invocations": self.total_tool_invocations,
            "total_input_tokens": self.total_input_tokens,
            "total_output_tokens": self.total_output_tokens,
            "wall_clock_seconds": self.wall_clock_seconds,
            "wall_clock_formatted": self._format_duration(self.wall_clock_seconds),
            "api_cost": round(self.api_cost, 4),
            "gpu_cost": round(self.gpu_cost, 4),
            "gpu_description": self.gpu_description,
            "per_phase_times": {
                k: self._format_duration(v) for k, v in self._phase_times.items()
            },
        }

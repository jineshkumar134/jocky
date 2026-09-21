"""
JOCKY Security Research Lab — Benchmark Engine
==============================================
Collects execution and detection metrics for reproducible research benchmarking.
"""

from __future__ import annotations

import time
from typing import List

from research.models import (
    ResearchScenario,
    ResearchObservable,
    ResearchFinding,
    ResearchBenchmark,
)


class ResearchBenchmarkEngine:
    """Measures detection coverage, execution time, and metrics for research scenarios."""

    def benchmark(
        self,
        scenario: ResearchScenario,
        observables: List[ResearchObservable],
        findings: List[ResearchFinding],
        start_time: float,
    ) -> ResearchBenchmark:
        duration_ms = (time.perf_counter() - start_time) * 1000.0

        obs_count = len(observables)
        det_count = len(findings)

        # Coverage is ratio of observables that triggered at least one finding
        covered_obs_ids = set()
        for f in findings:
            covered_obs_ids.update(f.observable_ids)

        coverage = len(covered_obs_ids) / obs_count if obs_count > 0 else 0.0

        metrics = {
            "category": scenario.category.value,
            "safety_level": scenario.safety_level.value,
            "simulated": scenario.simulated,
            "covered_observables": len(covered_obs_ids),
        }

        return ResearchBenchmark(
            scenario_id=scenario.scenario_id,
            duration_ms=round(duration_ms, 2),
            observable_count=obs_count,
            detection_count=det_count,
            detection_coverage=round(coverage, 2),
            metric_details=metrics,
        )

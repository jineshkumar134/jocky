"""
JOCKY Security Research Lab — Core Research Engine
==================================================
Coordinates scenario loading, observable generation, defensive detection,
benchmarking, and deterministic result hashing.
"""

from __future__ import annotations

import time
from typing import Dict, List, Optional

from research.models import ResearchResult, ResearchScenario
from research.scenarios import ScenarioRegistry
from research.detector import ResearchDetector
from research.benchmark import ResearchBenchmarkEngine
from research.serialization import compute_result_hash


class ResearchLabEngine:
    """Main execution engine for the safe security research lab."""

    def __init__(self, registry: Optional[ScenarioRegistry] = None) -> None:
        self.registry = registry or ScenarioRegistry()
        self.detector = ResearchDetector()
        self.benchmark_engine = ResearchBenchmarkEngine()

    def run_scenario(self, scenario_id: str) -> ResearchResult:
        """
        Executes a safe research scenario end-to-end:
        1. Retrieve scenario from safe registry
        2. Generate synthetic observables
        3. Evaluate defensive detection rules
        4. Benchmark metrics & coverage
        5. Compute deterministic result hash
        """
        scenario = self.registry.get_scenario(scenario_id)
        if not scenario:
            raise KeyError(
                f"Scenario '{scenario_id}' is not registered in the safe research lab."
            )

        start_time = time.perf_counter()

        # Generate observables safely
        observables = self.registry.generate_observables(scenario_id)

        # Run defensive detection rules
        findings = self.detector.evaluate(scenario_id, observables)

        # Measure performance and detection coverage
        benchmark = self.benchmark_engine.benchmark(
            scenario=scenario,
            observables=observables,
            findings=findings,
            start_time=start_time,
        )

        # Compute deterministic separate hash
        res_hash = compute_result_hash(scenario, observables, findings)

        return ResearchResult(
            scenario=scenario,
            observables=observables,
            findings=findings,
            benchmark=benchmark,
            result_hash=res_hash,
        )

"""
JOCKY Security Research Lab (Phase 15)
======================================
Safe, reproducible security research and defensive benchmarking.
Strictly non-destructive, isolated from production forensic hashes,
and explicitly simulation-based.
"""

from .models import (
    ResearchScenario,
    ResearchObservable,
    ResearchFinding,
    ResearchBenchmark,
    ResearchResult,
    ScenarioCategory,
    ResearchSafetyLevel,
    ResearchSeverity,
)
from .scenarios import ScenarioRegistry
from .detector import ResearchDetector
from .benchmark import ResearchBenchmarkEngine
from .engine import ResearchLabEngine
from .serialization import (
    scenario_to_dict,
    observable_to_dict,
    finding_to_dict,
    benchmark_to_dict,
    result_to_dict,
    compute_result_hash,
)

__all__ = [
    "ResearchScenario",
    "ResearchObservable",
    "ResearchFinding",
    "ResearchBenchmark",
    "ResearchResult",
    "ScenarioCategory",
    "ResearchSafetyLevel",
    "ResearchSeverity",
    "ScenarioRegistry",
    "ResearchDetector",
    "ResearchBenchmarkEngine",
    "ResearchLabEngine",
    "scenario_to_dict",
    "observable_to_dict",
    "finding_to_dict",
    "benchmark_to_dict",
    "result_to_dict",
    "compute_result_hash",
]

"""
JOCKY Security Research Lab — Core Data Models (Phase 15)
========================================================
Defines strongly typed, deterministic data models for safe security research,
benchmarking, synthetic observables, and defensive detection findings.

Key Principles:
- Every observable and scenario is marked `simulated=True`.
- Non-destructive, local, deterministic measurement.
- Explicitly isolated from production EvidencePackage integrity.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class ScenarioCategory(str, Enum):
    """Categorization of safe security research scenarios."""
    POLYMORPHISM = "POLYMORPHISM"
    MEMORY_EXECUTION = "MEMORY_EXECUTION"
    DRIVER_RISK = "DRIVER_RISK"
    SECURITY_CONTROL = "SECURITY_CONTROL"
    NETWORK_BEHAVIOR = "NETWORK_BEHAVIOR"


class ResearchSafetyLevel(str, Enum):
    """Strict safety level classification."""
    SAFE_SYNTHETIC = "SAFE_SYNTHETIC"
    SAFE_BENCHMARK = "SAFE_BENCHMARK"
    SAFE_INSPECTION = "SAFE_INSPECTION"


class ResearchSeverity(str, Enum):
    """Detection severity rating."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


@dataclass(frozen=True)
class ResearchObservable:
    """A discrete synthetic observation recorded during scenario execution."""
    observable_id: str
    observable_type: str
    timestamp: str
    source: str
    attributes: Dict[str, Any]
    confidence: float = 1.0
    simulated: bool = True


@dataclass(frozen=True)
class ResearchScenario:
    """Definition of a safe, reproducible security research scenario."""
    scenario_id: str
    name: str
    category: ScenarioCategory
    description: str
    safety_level: ResearchSafetyLevel = ResearchSafetyLevel.SAFE_SYNTHETIC
    simulated: bool = True
    expected_observables: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ResearchFinding:
    """Defensive detection finding produced by the research detector."""
    finding_id: str
    rule_id: str
    severity: ResearchSeverity
    confidence: float
    explanation: str
    observable_ids: List[str] = field(default_factory=list)
    simulated: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ResearchBenchmark:
    """Measurements and performance statistics collected during a benchmark run."""
    scenario_id: str
    duration_ms: float
    observable_count: int
    detection_count: int
    detection_coverage: float  # 0.0 - 1.0
    metric_details: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ResearchResult:
    """Aggregated output of a research scenario execution."""
    scenario: ResearchScenario
    observables: List[ResearchObservable]
    findings: List[ResearchFinding]
    benchmark: ResearchBenchmark
    generated_at: str = field(default_factory=_now_iso)
    result_hash: str = ""

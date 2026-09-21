"""
JOCKY Security Research Lab — Deterministic Serialization & Hash Utilities
"""

from __future__ import annotations

import dataclasses
from typing import Any, Dict

from forensic.evidence.canonical import canonical_hash
from research.models import (
    ResearchScenario,
    ResearchObservable,
    ResearchFinding,
    ResearchBenchmark,
    ResearchResult,
)


def scenario_to_dict(scenario: ResearchScenario) -> Dict[str, Any]:
    return {
        "scenario_id": scenario.scenario_id,
        "name": scenario.name,
        "category": scenario.category.value,
        "description": scenario.description,
        "safety_level": scenario.safety_level.value,
        "simulated": scenario.simulated,
        "expected_observables": scenario.expected_observables,
        "metadata": scenario.metadata,
    }


def observable_to_dict(obs: ResearchObservable) -> Dict[str, Any]:
    return {
        "observable_id": obs.observable_id,
        "observable_type": obs.observable_type,
        "timestamp": obs.timestamp,
        "source": obs.source,
        "attributes": obs.attributes,
        "confidence": obs.confidence,
        "simulated": obs.simulated,
    }


def finding_to_dict(finding: ResearchFinding) -> Dict[str, Any]:
    return {
        "finding_id": finding.finding_id,
        "rule_id": finding.rule_id,
        "severity": finding.severity.value,
        "confidence": finding.confidence,
        "explanation": finding.explanation,
        "observable_ids": finding.observable_ids,
        "simulated": finding.simulated,
        "metadata": finding.metadata,
    }


def benchmark_to_dict(bm: ResearchBenchmark) -> Dict[str, Any]:
    return {
        "scenario_id": bm.scenario_id,
        "duration_ms": bm.duration_ms,
        "observable_count": bm.observable_count,
        "detection_count": bm.detection_count,
        "detection_coverage": bm.detection_coverage,
        "metric_details": bm.metric_details,
    }


def compute_result_hash(
    scenario: ResearchScenario,
    observables: list[ResearchObservable],
    findings: list[ResearchFinding],
) -> str:
    """
    Computes a deterministic SHA-256 hash identifying the scenario and finding state.
    Excludes mutable timestamps and duration metrics so identical behavior produces
    the exact same hash. Completely distinct and separate from package_hash and case_hash.
    """
    hash_input = {
        "scenario_id": scenario.scenario_id,
        "category": scenario.category.value,
        "observables": sorted(
            [
                {
                    "id": o.observable_id,
                    "type": o.observable_type,
                    "attrs": o.attributes,
                }
                for o in observables
            ],
            key=lambda x: x["id"],
        ),
        "findings": sorted(
            [
                {
                    "rule": f.rule_id,
                    "severity": f.severity.value,
                    "expl": f.explanation,
                }
                for f in findings
            ],
            key=lambda x: (x["rule"], x["severity"]),
        ),
    }
    return canonical_hash(hash_input)


def result_to_dict(result: ResearchResult) -> Dict[str, Any]:
    return {
        "scenario": scenario_to_dict(result.scenario),
        "observables": [observable_to_dict(o) for o in result.observables],
        "findings": [finding_to_dict(f) for f in result.findings],
        "benchmark": benchmark_to_dict(result.benchmark),
        "generated_at": result.generated_at,
        "result_hash": result.result_hash,
    }

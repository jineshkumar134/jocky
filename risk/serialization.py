"""
JOCKY Investigation Risk — Serialization & Integrity Hashing
============================================================
Provides deterministic canonical hashing and serialization utilities for
RiskAssessment instances.

Deterministic Hash Formula:
---------------------------
  payload = {
      "case_id": assessment.case_id,
      "host": assessment.host,
      "score": assessment.score,
      "severity": assessment.severity.value,
      "findings": sorted([f.to_dict() for f in assessment.findings], key=lambda x: x["id"]),
      "metadata": assessment.metadata,
  }
  risk_hash = canonical_hash(payload)

Notice that volatile timestamps (like `generated_at`) are strictly omitted
from the integrity digest.
"""

from __future__ import annotations

import json
from typing import Any, Dict

from forensic.evidence.canonical import canonical_hash


def compute_risk_hash(assessment_or_dict: Any) -> str:
    """
    Compute a deterministic SHA-256 digest over risk assessment score, severity,
    sorted findings, case_id, host, and metadata.
    """
    if hasattr(assessment_or_dict, "to_dict"):
        raw = assessment_or_dict.to_dict()
    elif isinstance(assessment_or_dict, dict):
        raw = dict(assessment_or_dict)
    else:
        raise TypeError(f"Cannot compute risk hash for type {type(assessment_or_dict)}")

    findings = sorted(raw.get("findings", []), key=lambda f: f.get("id", ""))

    payload: Dict[str, Any] = {
        "case_id": raw.get("case_id", ""),
        "host": raw.get("host", ""),
        "score": raw.get("score", 0),
        "severity": raw.get("severity", ""),
        "findings": findings,
        "metadata": raw.get("metadata", {}),
    }

    return canonical_hash(payload)


def risk_to_dict(assessment: Any) -> Dict[str, Any]:
    """Serialize risk assessment to dictionary."""
    if hasattr(assessment, "to_dict"):
        return assessment.to_dict()
    raise TypeError(f"Cannot serialize {type(assessment)} to dict")


def risk_to_json(assessment: Any, indent: int = 2) -> str:
    """Serialize risk assessment to formatted JSON."""
    return json.dumps(risk_to_dict(assessment), indent=indent, ensure_ascii=False)

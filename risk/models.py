"""
JOCKY Investigation Risk — Data Models
======================================
Defines strongly typed Pydantic v2 models for:
- RiskSeverity: Standardized severity bands (LOW, MEDIUM, HIGH, CRITICAL).
- RiskFinding: Individual explainable risk finding with explicit evidence grounding.
- RiskAssessment: Aggregated assessment with capped score [0, 100], severity, and canonical risk_hash.

Important Distinction:
----------------------
- RiskFinding.severity: Severity corresponding to its own score contribution.
- RiskAssessment.severity: Severity corresponding to total capped score.
- Confidence is NOT score: Score measures investigative priority; confidence measures evidence certainty.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


class RiskSeverity(str, Enum):
    """Categorical risk severity levels."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RiskFinding(BaseModel):
    """
    Individual explainable risk indicator derived from observed evidence.

    Rules:
    - Never produce guilt/ownership assertions.
    - Deterministic ID derived from rule_id + sorted evidence_ids + sorted correlation_ids.
    - Confidence is preserved separately from score.
    """
    id: str
    rule_id: str
    severity: RiskSeverity
    score: int = Field(ge=0, le=100)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    title: str
    explanation: str
    evidence_ids: List[str] = Field(default_factory=list)
    correlation_ids: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = {"frozen": True}

    @field_validator("confidence", mode="before")
    @classmethod
    def clamp_confidence(cls, v: float) -> float:
        return round(max(0.0, min(1.0, float(v))), 4)

    def to_dict(self) -> Dict[str, Any]:
        d = self.model_dump()
        d["severity"] = self.severity.value
        return d


class RiskAssessment(BaseModel):
    """
    Consolidated investigation risk assessment.

    Score is capped at MAX_RISK_SCORE = 100.
    Severity is determined by the total capped score.
    """
    case_id: str
    host: str
    score: int = Field(ge=0, le=100)
    severity: RiskSeverity
    findings: List[RiskFinding] = Field(default_factory=list)
    evidence_count: int = 0
    generated_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    risk_hash: str = ""
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = {"frozen": True}

    def verify_integrity(self) -> bool:
        """Verify that the recorded risk_hash matches the computed hash."""
        from risk.serialization import compute_risk_hash
        return compute_risk_hash(self) == self.risk_hash

    def to_dict(self) -> Dict[str, Any]:
        """Convert risk assessment to JSON-serializable dictionary."""
        return {
            "case_id": self.case_id,
            "host": self.host,
            "score": self.score,
            "severity": self.severity.value,
            "findings": [f.to_dict() for f in self.findings],
            "evidence_count": self.evidence_count,
            "generated_at": self.generated_at,
            "risk_hash": self.risk_hash,
            "metadata": self.metadata,
        }

    def to_json(self, indent: int = 2) -> str:
        """Serialize risk assessment to formatted JSON string."""
        import json
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

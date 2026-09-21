"""
JOCKY Correlation Engine — Data Models
=======================================
Strongly typed Pydantic v2 models for correlation findings and results.

Correlation ID formula
----------------------
  seed   = canonical_json({"inputs": inputs_dict, "type": correlation_type})
  digest = sha256(seed.encode("utf-8")).hexdigest()[:12]
  tag    = correlation_type.replace("_", "")[:8].upper()
  id     = f"CORR-{tag}-{digest}"

Same evidence package + same rules → same IDs + same scores + same explanations.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List

from pydantic import BaseModel, Field, field_validator

from forensic.evidence.canonical import canonical_json


# ──────────────────────────────────────────────────────────
# Enums
# ──────────────────────────────────────────────────────────

class CorrelationType(str, Enum):
    """Classification of correlation findings by the domain pair involved."""
    PROCESS_NETWORK     = "PROCESS_NETWORK"
    NETWORK_BLOCKCHAIN  = "NETWORK_BLOCKCHAIN"
    WALLET_TRANSACTION  = "WALLET_TRANSACTION"
    TRANSACTION_VASP    = "TRANSACTION_VASP"
    ENDPOINT_BLOCKCHAIN = "ENDPOINT_BLOCKCHAIN"
    CROSS_DOMAIN        = "CROSS_DOMAIN"


# ──────────────────────────────────────────────────────────
# Deterministic ID generation
# ──────────────────────────────────────────────────────────

def generate_correlation_id(correlation_type: str, inputs: Dict[str, Any]) -> str:
    """
    Generate a deterministic, stable correlation ID.

    Formula::
        seed   = canonical_json({"inputs": inputs, "type": correlation_type})
        digest = sha256(seed.encode("utf-8")).hexdigest()[:12]
        tag    = correlation_type.replace("_", "")[:8].upper()
        id     = f"CORR-{tag}-{digest}"

    Same inputs always produce the same ID.
    """
    seed = canonical_json({"inputs": inputs, "type": correlation_type})
    digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:12]
    tag = correlation_type.replace("_", "")[:8].upper()
    return f"CORR-{tag}-{digest}"


# ──────────────────────────────────────────────────────────
# Finding Model
# ──────────────────────────────────────────────────────────

class CorrelationFinding(BaseModel):
    """
    A single, evidence-grounded correlation finding.

    Every finding carries:
    - A deterministic ID derived from its source/target evidence IDs and rule
    - Bounded confidence and score in [0.0, 1.0]
    - A human-readable explanation
    - Source and target evidence IDs (references only; no duplicated evidence)
    - The rule_id that produced this finding
    - A confidence_type label: DIRECT_OBSERVATION | EXPLICIT_MAPPING | ATTRIBUTION
    """
    id: str
    correlation_type: CorrelationType
    source_evidence_ids: List[str]
    target_evidence_ids: List[str]
    relationship_type: str
    confidence: float = Field(ge=0.0, le=1.0)
    score: float = Field(ge=0.0, le=1.0)
    explanation: str
    rule_id: str
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = {"frozen": True}

    @field_validator("confidence", "score", mode="before")
    @classmethod
    def clamp_to_unit(cls, v: float) -> float:
        return round(max(0.0, min(1.0, float(v))), 4)

    def to_dict(self) -> Dict[str, Any]:
        d = self.model_dump()
        d["correlation_type"] = self.correlation_type.value
        return d


# ──────────────────────────────────────────────────────────
# Result Model
# ──────────────────────────────────────────────────────────

class CorrelationResult(BaseModel):
    """
    Aggregate result of running the Correlation Engine against an EvidencePackage.

    confidence is the overall investigation confidence, computed as the minimum
    of all individual finding confidences (weakest-link principle).
    Returns 0.0 when there are no findings.
    """
    case_id: str
    host: str
    findings: List[CorrelationFinding] = Field(default_factory=list)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    summary: Dict[str, Any] = Field(default_factory=dict)
    generated_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    model_config = {"frozen": True}

    @field_validator("confidence", mode="before")
    @classmethod
    def clamp_confidence(cls, v: float) -> float:
        return round(max(0.0, min(1.0, float(v))), 4)

    def to_dict(self) -> Dict[str, Any]:
        d = self.model_dump()
        d["findings"] = [f.to_dict() for f in self.findings]
        return d

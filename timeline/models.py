"""
JOCKY Investigation Timeline — Data Models
==========================================
Defines strongly typed Pydantic v2 models for:
- TimelineEventType: Standardized categories of chronological events.
- TimelineEvent: Distinct event record with grounded evidence and correlation references.
- InvestigationTimeline: Container maintaining ordered events, summary metrics, and canonical timeline_hash.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


class TimelineEventType(str, Enum):
    """Supported timeline event categories."""
    PROCESS = "PROCESS"
    FILE = "FILE"
    SYSTEM = "SYSTEM"
    NETWORK_CONNECTION = "NETWORK_CONNECTION"
    NETWORK_LISTENER = "NETWORK_LISTENER"
    DNS_RECORD = "DNS_RECORD"
    WALLET = "WALLET"
    TRANSACTION = "TRANSACTION"
    VASP_ATTRIBUTION = "VASP_ATTRIBUTION"
    BLOCKCHAIN_EVENT = "BLOCKCHAIN_EVENT"
    CORRELATION = "CORRELATION"


class TimelineEvent(BaseModel):
    """
    Chronological event record in a forensic investigation timeline.

    Rules:
    - Never invent timestamps: if an entity lacks an event timestamp, timestamp = None.
    - Evidence collection timestamp is strictly distinct and preserved in metadata only.
    - Confidence is bounded in [0.0, 1.0].
    """
    id: str
    timestamp: Optional[str] = None
    event_type: TimelineEventType
    title: str
    description: str
    evidence_ids: List[str] = Field(default_factory=list)
    relationship_ids: List[str] = Field(default_factory=list)
    correlation_ids: List[str] = Field(default_factory=list)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    source: str = "collector"
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = {"frozen": True}

    @field_validator("confidence", mode="before")
    @classmethod
    def clamp_confidence(cls, v: float) -> float:
        return round(max(0.0, min(1.0, float(v))), 4)

    def to_dict(self) -> Dict[str, Any]:
        d = self.model_dump()
        d["event_type"] = self.event_type.value
        return d


class InvestigationTimeline(BaseModel):
    """
    Chronological timeline container for an investigation.

    Maintains deterministically ordered events, summary metrics, and a canonical hash.
    """
    case_id: str
    host: str
    events: List[TimelineEvent] = Field(default_factory=list)
    generated_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    timeline_hash: str = ""
    summary: Dict[str, Any] = Field(default_factory=dict)

    model_config = {"frozen": True}

    def verify_integrity(self) -> bool:
        """Verify that the recorded timeline_hash matches the computed hash."""
        from timeline.serialization import compute_timeline_hash
        return compute_timeline_hash(self) == self.timeline_hash

    def to_dict(self) -> Dict[str, Any]:
        """Convert timeline to JSON-serializable dictionary."""
        return {
            "case_id": self.case_id,
            "host": self.host,
            "events": [e.to_dict() for e in self.events],
            "generated_at": self.generated_at,
            "timeline_hash": self.timeline_hash,
            "summary": self.summary,
        }

    def to_json(self, indent: int = 2) -> str:
        """Serialize timeline to formatted JSON string."""
        import json
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

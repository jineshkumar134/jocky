"""Data models for central investigation management."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional

class CaseStatus(str, Enum):
    OPEN = "OPEN"
    IN_PROGRESS = "IN_PROGRESS"
    CLOSED = "CLOSED"

class HostStatus(str, Enum):
    ONLINE = "ONLINE"
    OFFLINE = "OFFLINE"
    UNKNOWN = "UNKNOWN"

def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat() + "Z"

@dataclass(frozen=True)
class HostRecord:
    host_id: str
    hostname: str
    status: HostStatus = HostStatus.UNKNOWN
    platform_info: Optional[dict] = None
    last_seen: Optional[str] = None
    metadata: dict = field(default_factory=dict)

@dataclass
class InvestigationCase:
    case_id: str
    title: str
    description: str = ""
    status: CaseStatus = CaseStatus.OPEN
    created_at: str = field(default_factory=_now_iso)
    updated_at: str = field(default_factory=_now_iso)
    hosts: List[str] = field(default_factory=list)  # host IDs
    evidence_packages: List[str] = field(default_factory=list)  # package hashes
    metadata: dict = field(default_factory=dict)

    def touch(self) -> None:
        object.__setattr__(self, "updated_at", _now_iso())

@dataclass(frozen=True)
class CaseSummary:
    case_id: str
    status: CaseStatus
    host_count: int = 0
    evidence_package_count: int = 0
    evidence_item_count: int = 0
    relationship_count: int = 0
    correlation_count: int = 0
    highest_risk_score: int = 0
    highest_risk_severity: str = ""
    blockchain_finding_count: int = 0
    vasp_finding_count: int = 0
    anchor_record_count: int = 0
    generated_at: str = field(default_factory=_now_iso)

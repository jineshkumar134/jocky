"""
management — Phase 13 Central Investigation Management layer.

Public API:
    CentralInvestigationManager  — create/manage cases, register hosts, attach evidence
    HostRegistry                 — in-memory host store
    InvestigationCase            — mutable case record
    HostRecord                   — immutable host record (frozen dataclass)
    CaseSummary                  — immutable aggregated case summary
    CaseStatus / HostStatus      — status enums
"""

from .models import CaseStatus, HostStatus, HostRecord, InvestigationCase, CaseSummary
from .registry import HostRegistry
from .manager import CentralInvestigationManager
from .serialization import case_to_dict, compute_case_hash

__all__ = [
    "CaseStatus", "HostStatus", "HostRecord", "InvestigationCase", "CaseSummary",
    "HostRegistry", "CentralInvestigationManager",
    "case_to_dict", "compute_case_hash",
]

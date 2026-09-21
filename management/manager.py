"""Central investigation manager — Phase 13."""

from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Optional

from .models import (
    CaseStatus, HostStatus,
    HostRecord, InvestigationCase, CaseSummary,
)
from .registry import HostRegistry
from .serialization import compute_case_hash


# ── Class-level cache shared across all manager instances.
# Populated by the runtime dispatcher ATTACH_EVIDENCE handler so the manager
# can look up the live EvidencePackage objects.
# Key: package_hash str, Value: forensic.evidence.models.EvidencePackage
_PACKAGE_CACHE: Dict[str, Any] = {}


def _make_host_id(hostname: str, case_id: str) -> str:
    """Produce a deterministic host ID from hostname + case_id."""
    seed = f"{case_id}|{hostname}"
    return "HOST-" + hashlib.sha256(seed.encode()).hexdigest()[:12]


class CentralInvestigationManager:
    """Manages investigation cases, host registrations, and evidence attachment.

    Design constraints (Phase 13):
    - All state is in-memory; no persistence, no remote control.
    - EvidencePackage.package_hash is NEVER mutated.
    - case_hash is separate from package_hash.
    - Correlation / risk reuse existing Phase 8 / Phase 10 engines.
    - No new risk or correlation algorithm is introduced.
    """

    # Global instance — one manager per runtime execution (created lazily
    # in the dispatcher; tests can create their own instances).
    _global: Optional["CentralInvestigationManager"] = None

    @classmethod
    def global_instance(cls) -> "CentralInvestigationManager":
        if cls._global is None:
            cls._global = cls()
        return cls._global

    @classmethod
    def reset_global(cls) -> None:
        """Reset global instance (used in tests)."""
        cls._global = None
        _PACKAGE_CACHE.clear()

    # ---- construction ----

    def __init__(self) -> None:
        self._cases: Dict[str, InvestigationCase] = {}
        self.host_registry = HostRegistry()

    # ---- case API ----

    def create_case(self, case_id: str, title: str, description: str = "") -> InvestigationCase:
        if case_id in self._cases:
            raise ValueError(f"Case {case_id!r} already exists")
        case = InvestigationCase(case_id=case_id, title=title, description=description)
        self._cases[case_id] = case
        return case

    def get_case(self, case_id: str) -> Optional[InvestigationCase]:
        return self._cases.get(case_id)

    def get_or_create_case(self, case_id: str, title: str = "", description: str = "") -> InvestigationCase:
        if case_id in self._cases:
            return self._cases[case_id]
        return self.create_case(case_id, title or case_id, description)

    # ---- host API ----

    def register_host(
        self,
        case_id: str,
        hostname: str,
        status: HostStatus = HostStatus.UNKNOWN,
        platform_info: Optional[dict] = None,
    ) -> HostRecord:
        """Register a host with the case.

        A deterministic ``host_id`` is derived from ``hostname`` and ``case_id``
        so that repeated calls produce the same ID.
        """
        case = self._cases[case_id]
        host_id = _make_host_id(hostname, case_id)
        record = HostRecord(
            host_id=host_id,
            hostname=hostname,
            status=status,
            platform_info=platform_info,
        )
        self.host_registry.add(record)
        if host_id not in case.hosts:
            case.hosts.append(host_id)
            case.touch()
        return record

    # ---- evidence API ----

    def register_package(self, package_hash: str, pkg: Any) -> None:
        """Store a reference to an EvidencePackage object without mutating it."""
        _PACKAGE_CACHE[package_hash] = pkg

    def attach_evidence(self, case_id: str, hostname: str, package_hash: str) -> None:
        """Associate an existing EvidencePackage hash with a case.

        The package_hash is NEVER recomputed or altered here.
        """
        case = self._cases[case_id]
        if package_hash not in case.evidence_packages:
            case.evidence_packages.append(package_hash)
            case.touch()

    # ---- summary API ----

    def compute_case_hash(self, case_id: str) -> str:
        """Return a deterministic hash of the case state, separate from any package_hash."""
        case = self._cases[case_id]
        return compute_case_hash(case)

    def generate_summary(self, case_id: str) -> CaseSummary:
        """Generate an aggregated summary using existing correlation / risk data."""
        case = self._cases[case_id]

        evidence_item_count = 0
        correlation_count = 0
        relationship_count = 0
        highest_risk_score = 0
        highest_risk_severity = ""
        blockchain_finding_count = 0
        vasp_finding_count = 0
        anchor_record_count = 0

        for pkg_hash in case.evidence_packages:
            pkg = _PACKAGE_CACHE.get(pkg_hash)
            if pkg is None:
                continue
            # Evidence items
            evidence_item_count += len(getattr(pkg, "evidence", []))
            # Relationships
            relationship_count += len(getattr(pkg, "relationships", []))
            # Correlation findings — stored as list of dicts in EvidencePackage.correlations
            correlation_count += len(getattr(pkg, "correlations", []))
            # Risk — stored in execution context; look up from metadata if present
            risk = getattr(pkg, "_risk_assessment", None)
            if risk is not None:
                score = getattr(risk, "score", 0)
                if score > highest_risk_score:
                    highest_risk_score = score
                    sev = getattr(risk, "severity", None)
                    highest_risk_severity = sev.value if hasattr(sev, "value") else str(sev) if sev else ""
            # Blockchain / VASP counts stored as metadata on package (set by dispatcher)
            bc = getattr(pkg, "_blockchain_finding_count", 0)
            blockchain_finding_count += bc
            vs = getattr(pkg, "_vasp_finding_count", 0)
            vasp_finding_count += vs
            anc = getattr(pkg, "_anchor_record_count", 0)
            anchor_record_count += anc

        return CaseSummary(
            case_id=case.case_id,
            status=case.status,
            host_count=len(case.hosts),
            evidence_package_count=len(case.evidence_packages),
            evidence_item_count=evidence_item_count,
            relationship_count=relationship_count,
            correlation_count=correlation_count,
            highest_risk_score=highest_risk_score,
            highest_risk_severity=highest_risk_severity,
            blockchain_finding_count=blockchain_finding_count,
            vasp_finding_count=vasp_finding_count,
            anchor_record_count=anchor_record_count,
        )

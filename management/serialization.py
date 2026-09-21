"""Deterministic case serialization and hash utilities."""

from __future__ import annotations

from typing import Any, Dict

from forensic.evidence.canonical import canonical_hash

from .models import InvestigationCase, CaseSummary


def case_to_dict(case: InvestigationCase) -> Dict[str, Any]:
    """Return a JSON-serializable dict of the case.

    Timestamps are included in full for display purposes, but are explicitly
    *excluded* from the hash input (see :func:`compute_case_hash`).
    """
    return {
        "case_id": case.case_id,
        "title": case.title,
        "description": case.description,
        "status": case.status.value,
        "created_at": case.created_at,
        "updated_at": case.updated_at,
        "hosts": sorted(case.hosts),
        "evidence_packages": sorted(case.evidence_packages),
        "metadata": case.metadata,
    }


def _hash_input(case: InvestigationCase) -> Dict[str, Any]:
    """Return a deterministic dict suitable for hashing.

    Mutable timestamps are deliberately excluded so the hash is stable.
    """
    return {
        "case_id": case.case_id,
        "title": case.title,
        "hosts": sorted(case.hosts),
        "evidence_packages": sorted(case.evidence_packages),
    }


def compute_case_hash(case: InvestigationCase) -> str:
    """Return a deterministic SHA-256 hex digest that identifies a case state.

    This hash is:
      - computed from the existing :func:`forensic.evidence.canonical.canonical_hash`
      - derived from ``{case_id, title, sorted(hosts), sorted(evidence_packages)}``
      - completely independent from any ``EvidencePackage.package_hash``
    """
    return canonical_hash(_hash_input(case))


def case_summary_to_dict(summary: CaseSummary) -> Dict[str, Any]:
    """Return a JSON-serializable dict of a :class:`CaseSummary`."""
    return {
        "case_id": summary.case_id,
        "status": summary.status.value,
        "host_count": summary.host_count,
        "evidence_package_count": summary.evidence_package_count,
        "evidence_item_count": summary.evidence_item_count,
        "relationship_count": summary.relationship_count,
        "correlation_count": summary.correlation_count,
        "highest_risk_score": summary.highest_risk_score,
        "highest_risk_severity": summary.highest_risk_severity,
        "blockchain_finding_count": summary.blockchain_finding_count,
        "vasp_finding_count": summary.vasp_finding_count,
        "anchor_record_count": summary.anchor_record_count,
        "generated_at": summary.generated_at,
    }

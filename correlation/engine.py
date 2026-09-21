"""
JOCKY Correlation Engine
========================
Accepts an EvidencePackage and applies the six deterministic correlation rules
to produce a CorrelationResult.

Architecture::

    EvidencePackage
          ↓
    CorrelationEngine.correlate()
          ↓
    Rules 1–5 (parallel, per-domain)
          ↓
    CrossDomainChainRule (uses findings from rules 1–5)
          ↓
    Deduplicate + score
          ↓
    CorrelationResult

Design principles
-----------------
* Deterministic: same package → same findings → same IDs → same scores
* Non-mutating: the original EvidencePackage is never modified
* Evidence-grounded: every finding references evidence IDs; nothing is invented
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from forensic.evidence.models import EvidencePackage, UniversalEvidence

from correlation.models import (
    CorrelationFinding,
    CorrelationResult,
    CorrelationType,
)
from correlation.rules import (
    CrossDomainChainRule,
    NetworkBlockchainMappingRule,
    NetworkDnsRecordRule,
    ProcessNetworkPidRule,
    TransactionVaspRule,
    WalletTransactionRule,
)
from correlation.scoring import weakest_link


class CorrelationEngine:
    """
    Runs all registered correlation rules against a set of evidence items and
    produces a structured CorrelationResult.

    Usage::
        engine = CorrelationEngine()
        result = engine.correlate(package, case_id="INC-001", host="LAB-PC-01")
    """

    def __init__(self) -> None:
        # Rules 1–5 operate independently on evidence items
        self._rules = [
            ProcessNetworkPidRule(),
            NetworkDnsRecordRule(),
            NetworkBlockchainMappingRule(),
            WalletTransactionRule(),
            TransactionVaspRule(),
        ]
        # Rule 6 operates on the findings from rules 1–5
        self._cross_domain_rule = CrossDomainChainRule()

    def correlate(
        self,
        package: EvidencePackage,
        case_id: str,
        host: str,
    ) -> CorrelationResult:
        """
        Apply all correlation rules to the evidence in *package*.

        Parameters
        ----------
        package:
            The EvidencePackage to correlate.  Never mutated.
        case_id:
            Investigation case identifier (copied into CorrelationResult).
        host:
            Target host identifier (copied into CorrelationResult).

        Returns
        -------
        CorrelationResult
            Contains deduplicated, sorted findings and overall confidence.
        """
        evidence_items: List[UniversalEvidence] = list(package.evidence)

        # Apply rules 1–5
        primary_findings: List[CorrelationFinding] = []
        for rule in self._rules:
            try:
                found = rule.correlate(evidence_items)
                primary_findings.extend(found)
            except Exception:
                # Individual rule failure must not abort the entire engine
                pass

        # Deduplicate by ID before cross-domain
        primary_findings = _deduplicate(primary_findings)

        # Apply cross-domain rule (rule 6)
        cross_findings: List[CorrelationFinding] = []
        try:
            cross_findings = self._cross_domain_rule.correlate(
                evidence_items, primary_findings
            )
        except Exception:
            pass

        all_findings = _deduplicate(primary_findings + cross_findings)

        # Overall confidence: weakest link across all findings
        overall_confidence = (
            weakest_link([f.confidence for f in all_findings])
            if all_findings else 0.0
        )

        # Summary
        by_type: Dict[str, int] = {}
        for ct in CorrelationType:
            count = sum(1 for f in all_findings if f.correlation_type == ct)
            if count:
                by_type[ct.value] = count

        summary: Dict[str, Any] = {
            "total_findings": len(all_findings),
            "by_type": by_type,
            "overall_confidence": overall_confidence,
            "rules_applied": len(self._rules) + 1,
        }

        return CorrelationResult(
            case_id=case_id,
            host=host,
            findings=all_findings,
            confidence=overall_confidence,
            summary=summary,
            generated_at=datetime.now(timezone.utc).isoformat(),
        )

    def correlate_from_items(
        self,
        evidence_items: List[UniversalEvidence],
        case_id: str,
        host: str,
    ) -> CorrelationResult:
        """
        Convenience method: correlate from a raw list of evidence items
        rather than a full EvidencePackage.
        """
        from forensic.evidence.models import EvidencePackage
        from forensic.evidence.canonical import canonical_hash

        # Build a minimal throw-away package for the engine
        dummy_pkg_dict: Dict[str, Any] = {
            "case_id": case_id,
            "host": host,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "evidence": evidence_items,
            "relationships": [],
            "metadata": {},
        }
        pkg_hash = canonical_hash({k: v for k, v in dummy_pkg_dict.items()})
        pkg = EvidencePackage(
            case_id=case_id,
            host=host,
            created_at=dummy_pkg_dict["created_at"],
            evidence=evidence_items,
            relationships=[],
            package_hash=pkg_hash,
        )
        return self.correlate(pkg, case_id=case_id, host=host)


# ── Helpers ───────────────────────────────────────────────

def _deduplicate(findings: List[CorrelationFinding]) -> List[CorrelationFinding]:
    """Return findings with duplicates (by id) removed, preserving order."""
    seen: Set[str] = set()
    unique: List[CorrelationFinding] = []
    for f in findings:
        if f.id not in seen:
            seen.add(f.id)
            unique.append(f)
    return unique

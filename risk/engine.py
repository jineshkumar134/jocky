"""
JOCKY Investigation Risk — Risk Engine
======================================
Coordinates evaluation of deterministic risk rules over evidence, correlations,
and investigation graphs.

Rules & Guarantees:
- Capped scoring: score = min(sum(rule_scores), 100).
- Categorical severity bands derived strictly from total capped score.
- Deterministic deduplication: Findings are uniquely keyed by finding ID.
- Grounded: Every finding contains rule_id, evidence_ids, explanation, and confidence.
- Derived view: Never mutates EvidencePackage or alters package_hash.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from forensic.evidence.models import EvidencePackage
from correlation.models import CorrelationResult
from graph.models import InvestigationGraph

from risk.models import RiskAssessment, RiskFinding, RiskSeverity
from risk.rules import (
    BaseRiskRule,
    BlockchainTransactionChainRule,
    CrossDomainCorrelationRule,
    EndpointNetworkActivityRule,
    ExternalNetworkConnectionRule,
    NetworkBlockchainAssociationRule,
    VaspAttributionRule,
)
from risk.scoring import MAX_RISK_SCORE, calculate_severity
from risk.serialization import compute_risk_hash


class RiskEngine:
    """
    Evaluates evidence against explainable rules to produce a deterministic RiskAssessment.
    """

    def __init__(self, rules: Optional[List[BaseRiskRule]] = None):
        self.rules = rules or [
            EndpointNetworkActivityRule(),
            ExternalNetworkConnectionRule(),
            NetworkBlockchainAssociationRule(),
            BlockchainTransactionChainRule(),
            VaspAttributionRule(),
            CrossDomainCorrelationRule(),
        ]

    def assess(
        self,
        package: EvidencePackage,
        graph: Optional[InvestigationGraph] = None,
        correlation_result: Optional[CorrelationResult] = None,
    ) -> RiskAssessment:
        """
        Evaluate all rules against package, graph, and correlation findings.
        """
        all_findings: List[RiskFinding] = []
        seen_ids: set[str] = set()

        for rule in self.rules:
            rule_findings = rule.evaluate(package, graph, correlation_result)
            for f in rule_findings:
                if f.id not in seen_ids:
                    seen_ids.add(f.id)
                    all_findings.append(f)

        # Sort findings deterministically: highest score first, then confidence desc, then ID asc
        all_findings.sort(key=lambda f: (-f.score, -f.confidence, f.id))

        # Sum scores and cap at MAX_RISK_SCORE = 100
        raw_score = sum(f.score for f in all_findings)
        capped_score = min(MAX_RISK_SCORE, raw_score)

        # Calculate overall assessment severity
        overall_severity = calculate_severity(capped_score)

        # Metadata
        meta = {
            "raw_score": raw_score,
            "capped": raw_score > MAX_RISK_SCORE,
            "rules_evaluated": len(self.rules),
            "findings_count": len(all_findings),
        }

        # Build prelim assessment and compute hash
        prelim = RiskAssessment(
            case_id=package.case_id,
            host=package.host,
            score=capped_score,
            severity=overall_severity,
            findings=all_findings,
            evidence_count=len(package.evidence),
            metadata=meta,
        )

        risk_hash = compute_risk_hash(prelim)

        return RiskAssessment(
            case_id=package.case_id,
            host=package.host,
            score=capped_score,
            severity=overall_severity,
            findings=all_findings,
            evidence_count=len(package.evidence),
            generated_at=prelim.generated_at,
            risk_hash=risk_hash,
            metadata=meta,
        )

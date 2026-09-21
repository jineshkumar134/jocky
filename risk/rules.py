"""
JOCKY Investigation Risk — Deterministic Rules
==============================================
Defines the 6 explainable deterministic risk rules.
No machine learning. No arbitrary scores. No guilt or ownership claims.
"""

from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Set

from forensic.evidence.models import (
    EvidencePackage,
    EvidenceType,
    UniversalEvidence,
)
from correlation.models import CorrelationFinding, CorrelationResult, CorrelationType
from graph.models import GraphNodeType, InvestigationGraph

from risk.models import RiskFinding, RiskSeverity
from risk.scoring import (
    SCORE_CROSS_DOMAIN,
    SCORE_ENDPOINT_NETWORK,
    SCORE_EXTERNAL_NETWORK,
    SCORE_NETWORK_BLOCKCHAIN,
    SCORE_TRANSACTION_CHAIN,
    SCORE_VASP_ATTRIBUTION,
    calculate_severity,
)


def generate_risk_finding_id(
    rule_id: str, evidence_ids: List[str], correlation_ids: List[str]
) -> str:
    """
    Deterministic finding ID based on:
      rule_id + sorted evidence_ids + sorted correlation_ids.
    """
    ev_str = ",".join(sorted(evidence_ids))
    corr_str = ",".join(sorted(correlation_ids))
    seed = f"{rule_id}|{ev_str}|{corr_str}"
    digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:10]
    rule_prefix = rule_id.replace("RULE_", "")[:6]
    return f"RISK-{rule_prefix}-{digest}"


class BaseRiskRule(ABC):
    """Abstract base class for deterministic risk rules."""
    rule_id: str
    title: str

    @abstractmethod
    def evaluate(
        self,
        package: EvidencePackage,
        graph: Optional[InvestigationGraph] = None,
        correlation_result: Optional[CorrelationResult] = None,
    ) -> List[RiskFinding]:
        """Evaluate rule and return distinct risk findings."""
        pass


class EndpointNetworkActivityRule(BaseRiskRule):
    """
    RULE_ENDPOINT_NETWORK_ACTIVITY:
    Triggered when an active process has a grounded network connection.
    Score: 15
    """
    rule_id = "RULE_ENDPOINT_NETWORK_ACTIVITY"
    title = "Endpoint-to-Network Process Activity"

    def evaluate(
        self,
        package: EvidencePackage,
        graph: Optional[InvestigationGraph] = None,
        correlation_result: Optional[CorrelationResult] = None,
    ) -> List[RiskFinding]:
        findings: List[RiskFinding] = []
        seen_pairs: Set[str] = set()

        for rel in package.relationships:
            rel_type = rel.type.value if hasattr(rel.type, "value") else str(rel.type)
            if rel_type == "CONNECTS_TO":
                pair_key = f"{rel.source_id}->{rel.target_id}"
                if pair_key in seen_pairs:
                    continue
                seen_pairs.add(pair_key)

                ev_ids = sorted(list(set([rel.source_id, rel.target_id] + list(rel.supporting_evidence))))
                fid = generate_risk_finding_id(self.rule_id, ev_ids, [])
                score = SCORE_ENDPOINT_NETWORK
                findings.append(
                    RiskFinding(
                        id=fid,
                        rule_id=self.rule_id,
                        severity=calculate_severity(score),
                        score=score,
                        confidence=rel.confidence,
                        title=self.title,
                        explanation=(
                            "Observed process-to-network activity was established "
                            "through grounded endpoint/network evidence."
                        ),
                        evidence_ids=ev_ids,
                        correlation_ids=[],
                        metadata={"relationship_id": rel.id},
                    )
                )

        return findings


class ExternalNetworkConnectionRule(BaseRiskRule):
    """
    RULE_EXTERNAL_NETWORK_CONNECTION:
    Triggered when a network connection targets an external remote address.
    Score: 10
    """
    rule_id = "RULE_EXTERNAL_NETWORK_CONNECTION"
    title = "External Network Connection"

    def evaluate(
        self,
        package: EvidencePackage,
        graph: Optional[InvestigationGraph] = None,
        correlation_result: Optional[CorrelationResult] = None,
    ) -> List[RiskFinding]:
        findings: List[RiskFinding] = []
        seen_ev: Set[str] = set()

        for ev in package.evidence:
            if ev.type == EvidenceType.NETWORK_CONNECTION:
                if ev.id in seen_ev:
                    continue
                entity = ev.entity
                rem = getattr(entity, "remote_address", "") or (entity.get("remote_address", "") if isinstance(entity, dict) else "")

                # Exclude loopback and unspecified
                if rem and not rem.startswith("127.") and rem != "0.0.0.0" and rem != "::1":
                    seen_ev.add(ev.id)
                    fid = generate_risk_finding_id(self.rule_id, [ev.id], [])
                    score = SCORE_EXTERNAL_NETWORK
                    findings.append(
                        RiskFinding(
                            id=fid,
                            rule_id=self.rule_id,
                            severity=calculate_severity(score),
                            score=score,
                            confidence=ev.confidence,
                            title=self.title,
                            explanation=f"Network connection established to external remote address '{rem}'.",
                            evidence_ids=[ev.id],
                            correlation_ids=[],
                            metadata={"remote_address": rem},
                        )
                    )

        return findings


class NetworkBlockchainAssociationRule(BaseRiskRule):
    """
    RULE_NETWORK_BLOCKCHAIN_ASSOCIATION:
    Triggered when a network endpoint is associated with a blockchain wallet in curated mapping.
    Score: 20
    Explicit non-ownership statement required.
    """
    rule_id = "RULE_NETWORK_BLOCKCHAIN_ASSOCIATION"
    title = "Network-to-Blockchain Association"

    def evaluate(
        self,
        package: EvidencePackage,
        graph: Optional[InvestigationGraph] = None,
        correlation_result: Optional[CorrelationResult] = None,
    ) -> List[RiskFinding]:
        findings: List[RiskFinding] = []
        corrs = correlation_result.findings if correlation_result else []
        if not corrs and hasattr(package, "correlations"):
            for c_dict in package.correlations:
                try:
                    corrs.append(CorrelationFinding(**c_dict))
                except Exception:
                    pass

        for c in corrs:
            if c.correlation_type == CorrelationType.NETWORK_BLOCKCHAIN:
                ev_ids = sorted(list(set(c.source_evidence_ids + c.target_evidence_ids)))
                fid = generate_risk_finding_id(self.rule_id, ev_ids, [c.id])
                score = SCORE_NETWORK_BLOCKCHAIN
                findings.append(
                    RiskFinding(
                        id=fid,
                        rule_id=self.rule_id,
                        severity=calculate_severity(score),
                        score=score,
                        confidence=c.confidence,
                        title=self.title,
                        explanation=(
                            "Explicit analytical mapping associates network endpoint "
                            "with blockchain wallet; does not establish wallet ownership."
                        ),
                        evidence_ids=ev_ids,
                        correlation_ids=[c.id],
                        metadata={"rule_id": c.rule_id},
                    )
                )

        return findings


class BlockchainTransactionChainRule(BaseRiskRule):
    """
    RULE_BLOCKCHAIN_TRANSACTION_CHAIN:
    Triggered when multiple grounded wallet transactions form a sequence (>= 2 transactions).
    Score: 15
    """
    rule_id = "RULE_BLOCKCHAIN_TRANSACTION_CHAIN"
    title = "Multi-Hop Transaction Chain"

    def evaluate(
        self,
        package: EvidencePackage,
        graph: Optional[InvestigationGraph] = None,
        correlation_result: Optional[CorrelationResult] = None,
    ) -> List[RiskFinding]:
        tx_evs = [ev for ev in package.evidence if ev.type == EvidenceType.TRANSACTION]
        if len(tx_evs) < 2:
            return []

        ev_ids = sorted([ev.id for ev in tx_evs])
        fid = generate_risk_finding_id(self.rule_id, ev_ids, [])
        score = SCORE_TRANSACTION_CHAIN
        # Weakest-link confidence across transactions
        conf = min([ev.confidence for ev in tx_evs]) if tx_evs else 1.0

        return [
            RiskFinding(
                id=fid,
                rule_id=self.rule_id,
                severity=calculate_severity(score),
                score=score,
                confidence=conf,
                title=self.title,
                explanation=(
                    f"Observed {len(tx_evs)} on-chain transactions forming a "
                    "multi-hop sequential transfer sequence."
                ),
                evidence_ids=ev_ids,
                correlation_ids=[],
                metadata={"transaction_count": len(tx_evs)},
            )
        ]


class VaspAttributionRule(BaseRiskRule):
    """
    RULE_VASP_ATTRIBUTION:
    Triggered when a transaction is attributed to a VASP.
    Score: 15
    """
    rule_id = "RULE_VASP_ATTRIBUTION"
    title = "VASP Infrastructure Attribution"

    def evaluate(
        self,
        package: EvidencePackage,
        graph: Optional[InvestigationGraph] = None,
        correlation_result: Optional[CorrelationResult] = None,
    ) -> List[RiskFinding]:
        findings: List[RiskFinding] = []
        vasp_evs = [ev for ev in package.evidence if ev.type == EvidenceType.VASP]
        if not vasp_evs:
            return []

        corrs = correlation_result.findings if correlation_result else []
        if not corrs and hasattr(package, "correlations"):
            for c_dict in package.correlations:
                try:
                    corrs.append(CorrelationFinding(**c_dict))
                except Exception:
                    pass

        # Sort descending by confidence so primary VASP attribution is evaluated first
        sorted_vasps = sorted(vasp_evs, key=lambda ev: (-ev.confidence, ev.id))
        primary_ev = sorted_vasps[0]

        for vasp_ev in sorted_vasps:
            entity = vasp_ev.entity
            name = getattr(entity, "name", "VASP") or (entity.get("name", "VASP") if isinstance(entity, dict) else "VASP")

            matched_corr_ids = sorted([
                c.id for c in corrs
                if c.correlation_type == CorrelationType.TRANSACTION_VASP
                and vasp_ev.id in (c.target_evidence_ids + c.source_evidence_ids)
            ])

            is_primary = (vasp_ev.id == primary_ev.id)
            title = self.title if is_primary else f"Secondary {self.title}"
            tier = "primary" if is_primary else "secondary"
            score = SCORE_VASP_ATTRIBUTION
            fid = generate_risk_finding_id(self.rule_id, [vasp_ev.id], matched_corr_ids)

            if is_primary:
                explanation = (
                    f"Analytical primary VASP attribution for '{name}' based on available evidence "
                    f"and attribution rules (confidence: {vasp_ev.confidence:.2f}); not private KYC confirmation."
                )
            else:
                explanation = (
                    f"Analytical secondary VASP attribution for '{name}' based on available evidence "
                    f"and attribution rules (confidence: {vasp_ev.confidence:.2f}); not private KYC confirmation. "
                    "Preserved as a distinct secondary attribution from primary VASP infrastructure."
                )

            findings.append(
                RiskFinding(
                    id=fid,
                    rule_id=self.rule_id,
                    severity=calculate_severity(score),
                    score=score,
                    confidence=vasp_ev.confidence,
                    title=title,
                    explanation=explanation,
                    evidence_ids=[vasp_ev.id],
                    correlation_ids=matched_corr_ids,
                    metadata={
                        "vasp_name": name,
                        "attribution_tier": tier,
                        "attribution_confidence": vasp_ev.confidence,
                    },
                )
            )

        return findings


class CrossDomainCorrelationRule(BaseRiskRule):
    """
    RULE_CROSS_DOMAIN_CORRELATION:
    Triggered when a valid Phase 8 CROSS_DOMAIN finding or Phase 9 path exists.
    Score: 20
    """
    rule_id = "RULE_CROSS_DOMAIN_CORRELATION"
    title = "Cross-Domain Evidential Correlation"

    def evaluate(
        self,
        package: EvidencePackage,
        graph: Optional[InvestigationGraph] = None,
        correlation_result: Optional[CorrelationResult] = None,
    ) -> List[RiskFinding]:
        findings: List[RiskFinding] = []

        # 1. Resolve investigation graph
        resolved_graph = graph
        if resolved_graph is None:
            try:
                from graph.builder import GraphBuilder
                resolved_graph = GraphBuilder.build_from_package(package, correlation_result)
            except Exception:
                resolved_graph = None

        # 2. If graph is available, query actual cross-domain paths
        if resolved_graph is not None:
            from graph.queries import get_cross_domain_paths
            paths = get_cross_domain_paths(resolved_graph)
            if paths:
                primary_path = paths[0]
                node_ids = sorted(primary_path.node_ids)

                # Trace correlation IDs along the primary path edges
                corr_ids = []
                for edge in primary_path.edges:
                    if edge.correlation_id:
                        corr_ids.append(edge.correlation_id)

                # Also include any matching CROSS_DOMAIN correlation finding ID
                corrs = correlation_result.findings if correlation_result else []
                if not corrs and hasattr(package, "correlations"):
                    for c_dict in package.correlations:
                        try:
                            corrs.append(CorrelationFinding(**c_dict))
                        except Exception:
                            pass
                for c in corrs:
                    if c.correlation_type == CorrelationType.CROSS_DOMAIN:
                        if c.metadata.get("chain_tier") == "primary" or c.confidence == primary_path.confidence:
                            corr_ids.append(c.id)
                corr_ids = sorted(list(set(corr_ids)))

                score = SCORE_CROSS_DOMAIN
                fid = generate_risk_finding_id(self.rule_id, node_ids, corr_ids)
                path_desc = " -> ".join(n.node_type.value for n in primary_path.nodes)
                findings.append(
                    RiskFinding(
                        id=fid,
                        rule_id=self.rule_id,
                        severity=calculate_severity(score),
                        score=score,
                        confidence=primary_path.confidence,
                        title=self.title,
                        explanation=(
                            f"Primary cross-domain investigation path establishes a grounded chain: "
                            f"{path_desc}. Path confidence ({primary_path.confidence:.2f}) is derived from "
                            "the weakest-link edge in the actual selected traversal."
                        ),
                        evidence_ids=node_ids,
                        correlation_ids=corr_ids,
                        metadata={
                            "path_nodes": [n.label for n in primary_path.nodes],
                            "edge_confidences": primary_path.edge_confidences,
                            "weakest_link_confidence": primary_path.confidence,
                            "confidence_type": "WEAKEST_LINK",
                            "chain_tier": "primary",
                        },
                    )
                )
                return findings

        # 3. Fallback to correlation findings if no graph path
        corrs = correlation_result.findings if correlation_result else []
        if not corrs and hasattr(package, "correlations"):
            for c_dict in package.correlations:
                try:
                    corrs.append(CorrelationFinding(**c_dict))
                except Exception:
                    pass

        cross_corrs = [c for c in corrs if c.correlation_type == CorrelationType.CROSS_DOMAIN]
        cross_corrs.sort(key=lambda c: -c.confidence)

        for c in cross_corrs:
            ev_ids = sorted(list(set(c.source_evidence_ids + c.target_evidence_ids)))
            fid = generate_risk_finding_id(self.rule_id, ev_ids, [c.id])
            score = SCORE_CROSS_DOMAIN
            findings.append(
                RiskFinding(
                    id=fid,
                    rule_id=self.rule_id,
                    severity=calculate_severity(score),
                    score=score,
                    confidence=c.confidence,
                    title=self.title,
                    explanation=(
                        "Multiple evidence domains are connected through "
                        "grounded analytical correlations."
                    ),
                    evidence_ids=ev_ids,
                    correlation_ids=[c.id],
                    metadata={"rule_id": c.rule_id, "weakest_link_confidence": c.confidence},
                )
            )

        return findings

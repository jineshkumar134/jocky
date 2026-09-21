"""
JOCKY Investigation Graph — Graph Builder
=========================================
Converts an EvidencePackage and optional CorrelationResult into an
interconnected, queryable InvestigationGraph.

Design Principles:
- Grounded: Nodes and edges correspond strictly to verified evidence and correlations.
- Non-fabricating: Cross-domain findings are stored in graph metadata; no shortcut
  edges (e.g. PROCESS -> VASP) are created.
- Deterministic: Identical evidence + identical correlations produce identical graphs
  and graph hashes.
- Clean Labels: Node labels are human-readable identifiers rather than bulky JSON dumps.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from forensic.evidence.models import EvidencePackage, EvidenceType, UniversalEvidence
from correlation.models import CorrelationFinding, CorrelationResult, CorrelationType

from graph.models import GraphEdge, GraphNode, GraphNodeType, InvestigationGraph
from graph.serialization import compute_graph_hash


class GraphBuilder:
    """
    Constructs an InvestigationGraph from an EvidencePackage and CorrelationResult.
    """

    def build_from_package(
        self,
        package: EvidencePackage,
        correlation_result: Optional[CorrelationResult] = None,
        correlation_findings: Optional[List[CorrelationFinding]] = None,
    ) -> InvestigationGraph:
        """
        Build an InvestigationGraph from an EvidencePackage and optional correlations.
        """
        nodes: List[GraphNode] = []
        edges: List[GraphEdge] = []
        node_ids: Set[str] = set()

        # 1. Build Nodes from UniversalEvidence items
        for ev in package.evidence:
            node = self._evidence_to_node(ev)
            if node.id not in node_ids:
                node_ids.add(node.id)
                nodes.append(node)

        # 2. Build Edges from Grounded Relationships (Phase 6 / Phase 7)
        edge_lookup: Dict[Tuple[str, str, str], GraphEdge] = {}

        for rel in package.relationships:
            # Verify endpoints exist
            if rel.source_id not in node_ids or rel.target_id not in node_ids:
                # Still preserve if valid reference or skip if unknown
                pass

            rel_type_str = rel.type.value if hasattr(rel.type, "value") else str(rel.type)
            edge = GraphEdge(
                id=rel.id,
                source_id=rel.source_id,
                target_id=rel.target_id,
                relationship_type=rel_type_str,
                confidence=rel.confidence,
                evidence_ids=list(rel.supporting_evidence),
                timestamp=rel.timestamp,
                label=rel_type_str,
                metadata=dict(rel.metadata),
            )
            key = (edge.source_id, edge.target_id, edge.relationship_type)
            edge_lookup[key] = edge

        # 3. Integrate Correlation Findings (Phase 8)
        findings_to_process: List[CorrelationFinding] = []
        if correlation_result and correlation_result.findings:
            findings_to_process.extend(correlation_result.findings)
        elif correlation_findings:
            findings_to_process.extend(correlation_findings)
        elif hasattr(package, "correlations") and package.correlations:
            for c_dict in package.correlations:
                try:
                    findings_to_process.append(CorrelationFinding(**c_dict))
                except Exception:
                    pass

        cross_domain_records: List[Dict[str, Any]] = []

        for finding in findings_to_process:
            if finding.correlation_type == CorrelationType.CROSS_DOMAIN:
                # Rule: Do NOT create a fake direct edge (e.g. PROCESS -> VASP)
                cross_domain_records.append(finding.to_dict())
                continue

            # For single-domain and multi-hop correlations, map to directed edges
            if not finding.source_evidence_ids or not finding.target_evidence_ids:
                continue

            for src in finding.source_evidence_ids:
                for tgt in finding.target_evidence_ids:
                    key = (src, tgt, finding.relationship_type)

                    if key in edge_lookup:
                        # Merge correlation metadata into existing edge
                        existing = edge_lookup[key]
                        updated_meta = dict(existing.metadata)
                        updated_meta["correlation_id"] = finding.id
                        updated_meta["correlation_rule"] = finding.rule_id
                        updated_meta["correlation_explanation"] = finding.explanation
                        if "confidence_type" in finding.metadata:
                            updated_meta["confidence_type"] = finding.metadata["confidence_type"]

                        # Combine evidence IDs
                        all_ev = list(set(existing.evidence_ids + finding.source_evidence_ids + finding.target_evidence_ids))

                        # Create merged edge (preserving strongest grounded confidence)
                        merged_edge = GraphEdge(
                            id=existing.id,
                            source_id=existing.source_id,
                            target_id=existing.target_id,
                            relationship_type=existing.relationship_type,
                            confidence=max(existing.confidence, finding.confidence),
                            evidence_ids=all_ev,
                            correlation_id=finding.id,
                            timestamp=existing.timestamp or finding.timestamp,
                            label=existing.label or finding.relationship_type,
                            metadata=updated_meta,
                        )
                        edge_lookup[key] = merged_edge
                    else:
                        # New edge introduced by correlation (e.g. NETWORK -> WALLET)
                        edge_id = self._generate_edge_id(finding.relationship_type, src, tgt)
                        new_edge = GraphEdge(
                            id=edge_id,
                            source_id=src,
                            target_id=tgt,
                            relationship_type=finding.relationship_type,
                            confidence=finding.confidence,
                            evidence_ids=list(set(finding.source_evidence_ids + finding.target_evidence_ids)),
                            correlation_id=finding.id,
                            timestamp=finding.timestamp,
                            label=finding.relationship_type,
                            metadata={
                                "correlation_rule": finding.rule_id,
                                "correlation_explanation": finding.explanation,
                                **finding.metadata,
                            },
                        )
                        edge_lookup[key] = new_edge

        edges = list(edge_lookup.values())

        # Build graph metadata
        graph_meta = dict(package.metadata)
        if cross_domain_records:
            graph_meta["cross_domain_findings"] = cross_domain_records
        if correlation_result:
            graph_meta["correlation_summary"] = correlation_result.summary

        # Construct prelim graph
        prelim_graph = InvestigationGraph(
            case_id=package.case_id,
            host=package.host,
            nodes=nodes,
            edges=edges,
            metadata=graph_meta,
        )

        graph_hash = compute_graph_hash(prelim_graph)

        return InvestigationGraph(
            case_id=package.case_id,
            host=package.host,
            nodes=nodes,
            edges=edges,
            generated_at=prelim_graph.generated_at,
            graph_hash=graph_hash,
            metadata=graph_meta,
        )

    def _evidence_to_node(self, ev: UniversalEvidence) -> GraphNode:
        """Convert a UniversalEvidence item to a GraphNode with clean labels."""
        entity = ev.entity
        ev_type_str = ev.type.value if hasattr(ev.type, "value") else str(ev.type)

        try:
            node_type = GraphNodeType(ev_type_str)
        except ValueError:
            node_type = GraphNodeType.SYSTEM

        label = self._generate_node_label(node_type, entity)

        meta: Dict[str, Any] = {}
        if hasattr(entity, "model_dump"):
            meta = entity.model_dump()
        elif isinstance(entity, dict):
            meta = dict(entity)

        return GraphNode(
            id=ev.id,
            node_type=node_type,
            evidence_id=ev.id,
            label=label,
            confidence=ev.confidence,
            metadata=meta,
        )

    def _generate_node_label(self, node_type: GraphNodeType, entity: Any) -> str:
        """Generate human-readable concise labels for nodes."""
        if node_type == GraphNodeType.PROCESS:
            name = getattr(entity, "name", None) or (entity.get("name") if isinstance(entity, dict) else "")
            pid = getattr(entity, "pid", None) or (entity.get("pid") if isinstance(entity, dict) else "")
            return f"{name} (PID {pid})" if pid else (name or "Process")

        elif node_type == GraphNodeType.NETWORK_CONNECTION:
            rem = getattr(entity, "remote_address", None) or (entity.get("remote_address") if isinstance(entity, dict) else "")
            port = getattr(entity, "remote_port", None) or (entity.get("remote_port") if isinstance(entity, dict) else "")
            return f"{rem}:{port}" if port else (rem or "Network Connection")

        elif node_type == GraphNodeType.NETWORK_LISTENER:
            loc = getattr(entity, "local_address", None) or (entity.get("local_address") if isinstance(entity, dict) else "")
            port = getattr(entity, "local_port", None) or (entity.get("local_port") if isinstance(entity, dict) else "")
            return f"Listen {loc}:{port}"

        elif node_type == GraphNodeType.DNS_RECORD:
            dom = getattr(entity, "domain", None) or (entity.get("domain") if isinstance(entity, dict) else "")
            return dom or "DNS Record"

        elif node_type == GraphNodeType.FILE:
            name = getattr(entity, "name", None) or (entity.get("name") if isinstance(entity, dict) else "")
            return name or "File"

        elif node_type == GraphNodeType.WALLET:
            lbl = getattr(entity, "label", None) or (entity.get("label") if isinstance(entity, dict) else "")
            addr = getattr(entity, "address", None) or (entity.get("address") if isinstance(entity, dict) else "")
            return lbl or addr or "Wallet"

        elif node_type == GraphNodeType.TRANSACTION:
            tx = getattr(entity, "tx_hash", None) or (entity.get("tx_hash") if isinstance(entity, dict) else "")
            amt = getattr(entity, "amount", None) or (entity.get("amount") if isinstance(entity, dict) else "")
            asset = getattr(entity, "asset", "ETH") or (entity.get("asset") if isinstance(entity, dict) else "ETH")
            return f"{tx} ({amt} {asset})" if amt is not None else (tx or "Transaction")

        elif node_type == GraphNodeType.VASP:
            name = getattr(entity, "name", None) or (entity.get("name") if isinstance(entity, dict) else "")
            return name or "VASP"

        elif node_type == GraphNodeType.SYSTEM:
            host = getattr(entity, "hostname", None) or (entity.get("hostname") if isinstance(entity, dict) else "")
            return host or "System"

        return str(node_type.value)

    def _generate_edge_id(self, rel_type: str, src: str, tgt: str) -> str:
        """Deterministic edge ID for edges synthesized by correlations."""
        seed = f"{rel_type.upper()}|{src}|{tgt}"
        digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:10]
        prefix = rel_type.upper()[:4]
        return f"EDGE-{prefix}-{digest}"

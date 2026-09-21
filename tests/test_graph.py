"""
tests/test_graph.py — Phase 9 Investigation Graph Engine Tests
==============================================================
27 deterministic, offline tests covering:
 1. GraphNode model validation
 2. GraphEdge model validation
 3. InvestigationGraph model validation
 4. Deterministic node creation
 5. Deterministic edge IDs
 6. UniversalEvidence -> GraphNode conversion
 7. Relationship -> GraphEdge conversion
 8. Correlation -> edge metadata merge
 9. Duplicate edge merging
10. Cross-domain finding handling (in metadata, not as direct edge)
11. No fabricated direct PROCESS -> VASP edge
12. Neighbor query
13. Incoming edge query
14. Outgoing edge query
15. Path finding
16. Deterministic path ordering
17. Path weakest-link confidence (dynamic minimum, not hardcoded)
18. Graph hash determinism
19. Graph serialization (to_dict, to_json)
20. Runtime BUILD ATTACK GRAPH
21. CLI JSON output
22. Existing evidence integrity
23. Existing correlation IDs unchanged
24. Empty graph handling
25. Unknown evidence reference handling
26. Full regression across all components
27. Proof that building an InvestigationGraph does not change package_hash
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import List

import pytest

from forensic.evidence.canonical import canonical_hash, generate_evidence_id
from forensic.evidence.converters import build_evidence_package
from forensic.evidence.models import (
    DNSRecordEntity,
    EvidenceIntegrity,
    EvidencePackage,
    EvidenceProvenance,
    EvidenceType,
    NetworkConnectionEntity,
    ProcessEntity,
    Relationship,
    RelationshipType,
    TransactionEntity,
    UniversalEvidence,
    VASPEntity,
    WalletEntity,
)
from correlation.engine import CorrelationEngine
from correlation.models import CorrelationFinding, CorrelationResult, CorrelationType

from graph.builder import GraphBuilder
from graph.models import GraphEdge, GraphNode, GraphNodeType, InvestigationGraph
from graph.queries import (
    find_edges_by_relationship,
    find_nodes_by_type,
    find_path,
    get_cross_domain_paths,
    get_high_confidence_edges,
    get_incoming_edges,
    get_neighbors,
    get_outgoing_edges,
)
from graph.serialization import compute_graph_hash, graph_to_dict, graph_to_json

_HOST = "TEST-HOST"
_CASE = "INC-GRAPH-TEST"
_NOW = "2026-09-12T16:00:00Z"


def _make_provenance(collector: str = "TestAdapter") -> EvidenceProvenance:
    return EvidenceProvenance(
        collector=collector,
        adapter=collector,
        source="fixture",
        collection_method="fixture",
        collected_at=_NOW,
        host=_HOST,
        case_id=_CASE,
    )


def _make_evidence(ev_type: EvidenceType, entity, collector: str = "TestAdapter") -> UniversalEvidence:
    entity_dict = entity.model_dump()
    ev_id = generate_evidence_id(ev_type.value, entity_dict, _HOST, collector)
    prelim = UniversalEvidence(
        id=ev_id,
        type=ev_type,
        source=collector,
        timestamp=_NOW,
        entity=entity,
        provenance=_make_provenance(collector),
        integrity=EvidenceIntegrity(value=""),
    )
    real_hash = prelim.compute_integrity_hash()
    return UniversalEvidence(
        id=ev_id,
        type=ev_type,
        source=collector,
        timestamp=_NOW,
        entity=entity,
        provenance=_make_provenance(collector),
        integrity=EvidenceIntegrity(value=real_hash),
    )



def _proc_ev(pid: int = 4821, name: str = "suspicious_miner") -> UniversalEvidence:
    return _make_evidence(
        EvidenceType.PROCESS,
        ProcessEntity(pid=pid, name=name, status="running"),
    )


def _conn_ev(pid: int = 4821, remote_addr: str = "203.0.113.25", port: int = 443) -> UniversalEvidence:
    return _make_evidence(
        EvidenceType.NETWORK_CONNECTION,
        NetworkConnectionEntity(
            local_address="192.168.1.50",
            local_port=49152,
            remote_address=remote_addr,
            remote_port=port,
            pid=pid,
            process_name="suspicious_miner",
        ),
    )


def _wallet_ev(address: str = "0xWALLET001", label: str = "Synthetic Suspicious EOA") -> UniversalEvidence:
    return _make_evidence(
        EvidenceType.WALLET,
        WalletEntity(address=address, label=label, wallet_type="eoa"),
    )


def _tx_ev(tx_hash: str, from_addr: str, to_addr: str, amount: float = 10.5) -> UniversalEvidence:
    return _make_evidence(
        EvidenceType.TRANSACTION,
        TransactionEntity(
            tx_hash=tx_hash,
            from_address=from_addr,
            to_address=to_addr,
            amount=amount,
            timestamp=_NOW,
        ),
    )


def _vasp_ev(vasp_id: str = "VASP-01", name: str = "Example Exchange", matched: list = None) -> UniversalEvidence:
    return _make_evidence(
        EvidenceType.VASP,
        VASPEntity(
            vasp_id=vasp_id,
            name=name,
            confidence=1.0,
            score=1.0,
            matched_wallets=matched or ["0xWALLET003"],
        ),
    )


# ──────────────────────────────────────────────────────────
# 1. GraphNode Validation
# ──────────────────────────────────────────────────────────
class TestGraphNodeModel:
    def test_node_fields_and_confidence(self):
        node = GraphNode(
            id="EVID-PROC-12345",
            node_type=GraphNodeType.PROCESS,
            evidence_id="EVID-PROC-12345",
            label="suspicious_miner",
            confidence=0.95,
        )
        assert node.id == "EVID-PROC-12345"
        assert node.node_type == GraphNodeType.PROCESS
        assert node.label == "suspicious_miner"
        assert node.confidence == 0.95

    def test_node_type_matches_evidence_types_no_host(self):
        # Correction 3: Verify no HOST node type exists
        valid_types = {t.value for t in GraphNodeType}
        assert "HOST" not in valid_types
        assert "PROCESS" in valid_types
        assert "NETWORK_CONNECTION" in valid_types
        assert "WALLET" in valid_types


# ──────────────────────────────────────────────────────────
# 2. GraphEdge Validation
# ──────────────────────────────────────────────────────────
class TestGraphEdgeModel:
    def test_edge_fields_and_clamping(self):
        edge = GraphEdge(
            id="REL-CONN-12345",
            source_id="EVID-PROC-1",
            target_id="EVID-NETC-2",
            relationship_type="CONNECTS_TO",
            confidence=1.5,  # should clamp to 1.0
        )
        assert edge.confidence == 1.0
        assert edge.relationship_type == "CONNECTS_TO"


# ──────────────────────────────────────────────────────────
# 3. InvestigationGraph Validation
# ──────────────────────────────────────────────────────────
class TestInvestigationGraphModel:
    def test_graph_container_properties(self):
        graph = InvestigationGraph(
            case_id=_CASE,
            host=_HOST,
            nodes=[],
            edges=[],
            metadata={"status": "initial"},
        )
        assert graph.case_id == _CASE
        assert graph.host == _HOST
        assert graph.nodes == []
        assert graph.edges == []


# ──────────────────────────────────────────────────────────
# 4. Deterministic Node Creation
# ──────────────────────────────────────────────────────────
class TestDeterministicNodeCreation:
    def test_node_id_is_exact_evidence_id(self):
        ev = _proc_ev(4821, "miner")
        builder = GraphBuilder()
        pkg = build_evidence_package(_CASE, _HOST, [ev])
        graph = builder.build_from_package(pkg)
        assert len(graph.nodes) == 1
        assert graph.nodes[0].id == ev.id
        assert graph.nodes[0].evidence_id == ev.id


# ──────────────────────────────────────────────────────────
# 5. Deterministic Edge IDs
# ──────────────────────────────────────────────────────────
class TestDeterministicEdgeIDs:
    def test_generated_edge_ids_stable(self):
        builder = GraphBuilder()
        id1 = builder._generate_edge_id("ASSOCIATED_WITH", "SRC1", "TGT1")
        id2 = builder._generate_edge_id("ASSOCIATED_WITH", "SRC1", "TGT1")
        assert id1 == id2
        assert id1.startswith("EDGE-ASSO-")


# ──────────────────────────────────────────────────────────
# 6. Evidence -> Node Conversion
# ──────────────────────────────────────────────────────────
class TestEvidenceToNodeConversion:
    def test_all_evidence_types_converted(self):
        items = [
            _proc_ev(4821),
            _conn_ev(4821),
            _wallet_ev("0xWALLET001"),
            _tx_ev("0xTX001", "0xWALLET001", "0xWALLET002"),
            _vasp_ev("V1", "Example Exchange"),
        ]
        pkg = build_evidence_package(_CASE, _HOST, items)
        graph = GraphBuilder().build_from_package(pkg)
        types = {n.node_type for n in graph.nodes}
        assert GraphNodeType.PROCESS in types
        assert GraphNodeType.NETWORK_CONNECTION in types
        assert GraphNodeType.WALLET in types
        assert GraphNodeType.TRANSACTION in types
        assert GraphNodeType.VASP in types


# ──────────────────────────────────────────────────────────
# 7. Relationship -> Edge Conversion
# ──────────────────────────────────────────────────────────
class TestRelationshipToEdgeConversion:
    def test_grounded_relationship_becomes_edge(self):
        p = _proc_ev(4821)
        c = _conn_ev(4821)
        rel = Relationship.create("CONNECTS_TO", p.id, c.id, confidence=0.95)
        pkg = build_evidence_package(_CASE, _HOST, [p, c], relationships=[rel])
        graph = GraphBuilder().build_from_package(pkg)
        assert len(graph.edges) == 1
        assert graph.edges[0].source_id == p.id
        assert graph.edges[0].target_id == c.id
        assert graph.edges[0].relationship_type == "CONNECTS_TO"


# ──────────────────────────────────────────────────────────
# 8. Correlation -> Edge Metadata Merge
# ──────────────────────────────────────────────────────────
class TestCorrelationEdgeMetadataMerge:
    def test_correlation_enriches_existing_edge(self):
        p = _proc_ev(4821)
        c = _conn_ev(4821)
        rel = Relationship.create("CONNECTS_TO", p.id, c.id, confidence=0.90)
        finding = CorrelationFinding(
            id="CORR-PROCNET-01",
            correlation_type=CorrelationType.PROCESS_NETWORK,
            source_evidence_ids=[p.id],
            target_evidence_ids=[c.id],
            relationship_type="CONNECTS_TO",
            confidence=0.95,
            score=0.95,
            explanation="PID 4821 match",
            rule_id="PROCESS_NETWORK_PID_MATCH",
            timestamp=_NOW,
        )
        pkg = build_evidence_package(_CASE, _HOST, [p, c], relationships=[rel])
        graph = GraphBuilder().build_from_package(pkg, correlation_findings=[finding])
        assert len(graph.edges) == 1
        edge = graph.edges[0]
        assert edge.correlation_id == "CORR-PROCNET-01"
        assert edge.confidence == 0.95  # upgraded by correlation
        assert edge.metadata["correlation_rule"] == "PROCESS_NETWORK_PID_MATCH"


# ──────────────────────────────────────────────────────────
# 9. Duplicate Edge Merging
# ──────────────────────────────────────────────────────────
class TestDuplicateEdgeMerging:
    def test_no_duplicate_edge_created(self):
        p = _proc_ev(4821)
        c = _conn_ev(4821)
        rel = Relationship.create("CONNECTS_TO", p.id, c.id)
        finding = CorrelationFinding(
            id="CORR-PROCNET-01",
            correlation_type=CorrelationType.PROCESS_NETWORK,
            source_evidence_ids=[p.id],
            target_evidence_ids=[c.id],
            relationship_type="CONNECTS_TO",
            confidence=0.95,
            score=0.95,
            explanation="PID match",
            rule_id="R1",
            timestamp=_NOW,
        )
        pkg = build_evidence_package(_CASE, _HOST, [p, c], relationships=[rel])
        graph = GraphBuilder().build_from_package(pkg, correlation_findings=[finding])
        assert len(graph.edges) == 1


# ──────────────────────────────────────────────────────────
# 10. Cross-Domain Finding Handling
# ──────────────────────────────────────────────────────────
class TestCrossDomainFindingHandling:
    def test_cross_domain_stored_in_metadata(self):
        cross_finding = CorrelationFinding(
            id="CORR-CROSS-01",
            correlation_type=CorrelationType.CROSS_DOMAIN,
            source_evidence_ids=["A", "B", "C"],
            target_evidence_ids=[],
            relationship_type="CROSS_DOMAIN_CHAIN",
            confidence=0.65,
            score=0.65,
            explanation="Chain found",
            rule_id="CROSS_DOMAIN_CHAIN",
            timestamp=_NOW,
        )
        pkg = build_evidence_package(_CASE, _HOST, [_proc_ev()])
        graph = GraphBuilder().build_from_package(pkg, correlation_findings=[cross_finding])
        assert "cross_domain_findings" in graph.metadata
        assert len(graph.metadata["cross_domain_findings"]) == 1


# ──────────────────────────────────────────────────────────
# 11. No Fabricated Direct PROCESS -> VASP Edge
# ──────────────────────────────────────────────────────────
class TestNoFabricatedDirectEdge:
    def test_no_direct_process_to_vasp_edge(self):
        p = _proc_ev(4821)
        v = _vasp_ev("V1", "Example Exchange")
        cross_finding = CorrelationFinding(
            id="CORR-CROSS-01",
            correlation_type=CorrelationType.CROSS_DOMAIN,
            source_evidence_ids=[p.id, v.id],
            target_evidence_ids=[],
            relationship_type="CROSS_DOMAIN_CHAIN",
            confidence=0.65,
            score=0.65,
            explanation="Chain from process to vasp",
            rule_id="CROSS_DOMAIN_CHAIN",
            timestamp=_NOW,
        )
        pkg = build_evidence_package(_CASE, _HOST, [p, v])
        graph = GraphBuilder().build_from_package(pkg, correlation_findings=[cross_finding])
        # Verify no edge directly connecting p to v
        direct_edges = [e for e in graph.edges if e.source_id == p.id and e.target_id == v.id]
        assert direct_edges == []


# ──────────────────────────────────────────────────────────
# 12. Neighbor Query
# ──────────────────────────────────────────────────────────
class TestNeighborQuery:
    def test_get_neighbors_finds_connected_nodes(self):
        p = _proc_ev(4821)
        c = _conn_ev(4821)
        rel = Relationship.create("CONNECTS_TO", p.id, c.id)
        pkg = build_evidence_package(_CASE, _HOST, [p, c], relationships=[rel])
        graph = GraphBuilder().build_from_package(pkg)
        neighbors = get_neighbors(graph, p.id)
        assert len(neighbors) == 1
        assert neighbors[0].id == c.id


# ──────────────────────────────────────────────────────────
# 13. Incoming Edge Query
# ──────────────────────────────────────────────────────────
class TestIncomingEdgeQuery:
    def test_get_incoming_edges(self):
        p = _proc_ev(4821)
        c = _conn_ev(4821)
        rel = Relationship.create("CONNECTS_TO", p.id, c.id)
        pkg = build_evidence_package(_CASE, _HOST, [p, c], relationships=[rel])
        graph = GraphBuilder().build_from_package(pkg)
        incoming = get_incoming_edges(graph, c.id)
        assert len(incoming) == 1
        assert incoming[0].source_id == p.id


# ──────────────────────────────────────────────────────────
# 14. Outgoing Edge Query
# ──────────────────────────────────────────────────────────
class TestOutgoingEdgeQuery:
    def test_get_outgoing_edges(self):
        p = _proc_ev(4821)
        c = _conn_ev(4821)
        rel = Relationship.create("CONNECTS_TO", p.id, c.id)
        pkg = build_evidence_package(_CASE, _HOST, [p, c], relationships=[rel])
        graph = GraphBuilder().build_from_package(pkg)
        outgoing = get_outgoing_edges(graph, p.id)
        assert len(outgoing) == 1
        assert outgoing[0].target_id == c.id


# ──────────────────────────────────────────────────────────
# 15. Path Finding
# ──────────────────────────────────────────────────────────
class TestPathFinding:
    def test_find_path_direct_and_multi_hop(self):
        n1 = _proc_ev(4821)
        n2 = _conn_ev(4821)
        n3 = _wallet_ev("0xW1")
        e1 = Relationship.create("CONNECTS_TO", n1.id, n2.id, confidence=0.95)
        e2 = Relationship.create("ASSOCIATED_WITH", n2.id, n3.id, confidence=0.65)
        pkg = build_evidence_package(_CASE, _HOST, [n1, n2, n3], relationships=[e1, e2])
        graph = GraphBuilder().build_from_package(pkg)

        path = find_path(graph, n1.id, n3.id)
        assert path is not None
        assert len(path.nodes) == 3
        assert len(path.edges) == 2
        assert path.node_ids == [n1.id, n2.id, n3.id]


# ──────────────────────────────────────────────────────────
# 16. Deterministic Path Ordering
# ──────────────────────────────────────────────────────────
class TestDeterministicPathOrdering:
    def test_path_traversal_is_deterministic(self):
        n1 = _proc_ev(4821)
        n2a = _conn_ev(4821, "203.0.113.25")
        n2b = _conn_ev(4821, "198.51.100.20")
        target = _wallet_ev("0xTARGET")

        e1 = Relationship.create("CONNECTS_TO", n1.id, n2a.id, confidence=0.95)
        e2 = Relationship.create("CONNECTS_TO", n1.id, n2b.id, confidence=0.95)
        e3 = Relationship.create("ASSOCIATED_WITH", n2a.id, target.id, confidence=0.65)
        e4 = Relationship.create("ASSOCIATED_WITH", n2b.id, target.id, confidence=0.65)

        pkg = build_evidence_package(_CASE, _HOST, [n1, n2a, n2b, target], relationships=[e1, e2, e3, e4])
        graph = GraphBuilder().build_from_package(pkg)

        path1 = find_path(graph, n1.id, target.id)
        path2 = find_path(graph, n1.id, target.id)
        assert path1.node_ids == path2.node_ids
        assert path1.edge_ids == path2.edge_ids


# ──────────────────────────────────────────────────────────
# 17. Path Weakest-Link Confidence (Correction 1: Dynamic Calculation)
# ──────────────────────────────────────────────────────────
class TestPathWeakestLinkConfidence:
    def test_path_confidence_is_exact_minimum_of_edges(self):
        """
        Correction 1: Path confidence must be min(confidence of edges in path).
        If edges are [0.95, 0.65, 0.95, 0.95, 1.00], path confidence must be 0.65.
        """
        n1 = _proc_ev()
        n2 = _conn_ev()
        n3 = _wallet_ev("0xW1")
        n4 = _wallet_ev("0xW2")
        n5 = _vasp_ev("V1")

        e1 = Relationship.create("CONNECTS_TO", n1.id, n2.id, confidence=0.95)
        e2 = Relationship.create("ASSOCIATED_WITH", n2.id, n3.id, confidence=0.65)
        e3 = Relationship.create("SENT_TO", n3.id, n4.id, confidence=0.95)
        e4 = Relationship.create("ATTRIBUTED_TO", n4.id, n5.id, confidence=1.00)

        pkg = build_evidence_package(_CASE, _HOST, [n1, n2, n3, n4, n5], relationships=[e1, e2, e3, e4])
        graph = GraphBuilder().build_from_package(pkg)

        path = find_path(graph, n1.id, n5.id)
        assert path is not None
        assert path.confidence == 0.65  # min(0.95, 0.65, 0.95, 1.00)
        assert path.edge_confidences == [0.95, 0.65, 0.95, 1.0]

    def test_custom_edge_confidences_min_reflected(self):
        n1 = _proc_ev()
        n2 = _conn_ev()
        e1 = Relationship.create("CONNECTS_TO", n1.id, n2.id, confidence=0.42)
        pkg = build_evidence_package(_CASE, _HOST, [n1, n2], relationships=[e1])
        graph = GraphBuilder().build_from_package(pkg)
        path = find_path(graph, n1.id, n2.id)
        assert path.confidence == 0.42


# ──────────────────────────────────────────────────────────
# 18. Graph Hash Determinism
# ──────────────────────────────────────────────────────────
class TestGraphHashDeterminism:
    def test_same_package_produces_identical_graph_hash(self):
        p = _proc_ev()
        c = _conn_ev()
        rel = Relationship.create("CONNECTS_TO", p.id, c.id)
        pkg1 = build_evidence_package(_CASE, _HOST, [p, c], relationships=[rel])
        pkg2 = build_evidence_package(_CASE, _HOST, [p, c], relationships=[rel])

        g1 = GraphBuilder().build_from_package(pkg1)
        g2 = GraphBuilder().build_from_package(pkg2)
        assert g1.graph_hash == g2.graph_hash
        assert g1.verify_integrity() is True
        assert g2.verify_integrity() is True


# ──────────────────────────────────────────────────────────
# 19. Graph Serialization
# ──────────────────────────────────────────────────────────
class TestGraphSerialization:
    def test_to_dict_and_to_json(self):
        p = _proc_ev()
        c = _conn_ev()
        rel = Relationship.create("CONNECTS_TO", p.id, c.id)
        pkg = build_evidence_package(_CASE, _HOST, [p, c], relationships=[rel])
        graph = GraphBuilder().build_from_package(pkg)

        d = graph.to_dict()
        assert d["case_id"] == _CASE
        assert len(d["nodes"]) == 2
        assert len(d["edges"]) == 1
        assert "graph_hash" in d

        j = graph.to_json()
        parsed = json.loads(j)
        assert parsed["case_id"] == _CASE


# ──────────────────────────────────────────────────────────
# 20. Runtime BUILD ATTACK GRAPH
# ──────────────────────────────────────────────────────────
class TestRuntimeBuildAttackGraph:
    def test_runtime_executes_build_attack_graph(self):
        from compiler.compiler import compile_source
        from runtime.executor.executor import RuntimeExecutor
        from blockchain.evm.adapter import EVMAdapter
        from forensic.endpoint.fixture import FixtureEndpointAdapter
        from forensic.network.fixture import FixtureNetworkAdapter

        source = """
        CASE "INC-GRAPH-RT"
        HOST "LAB-PC-01"
        ANALYZE PROCESSES
        ANALYZE NETWORK
        BLOCKCHAIN TRACE "0xWALLET001"
        IDENTIFY VASP
        CORRELATE EVIDENCE
        BUILD ATTACK GRAPH
        """
        cres = compile_source(source)
        assert cres.ok and cres.ir is not None

        executor = RuntimeExecutor(
            cres.ir,
            adapter=FixtureEndpointAdapter(host="LAB-PC-01"),
            network_adapter=FixtureNetworkAdapter(host="LAB-PC-01"),
            blockchain_adapter=EVMAdapter(),
        )
        exec_res = executor.execute()

        graph_op = next((r for r in exec_res.results if r.operation == "BUILD_ATTACK_GRAPH"), None)
        assert graph_op is not None
        assert graph_op.status == "SUCCESS"
        assert graph_op.data.__class__.__name__ == "InvestigationGraph"
        assert len(graph_op.data.nodes) > 0
        assert len(graph_op.data.edges) > 0


# ──────────────────────────────────────────────────────────
# 21. CLI JSON Output
# ──────────────────────────────────────────────────────────
class TestCLIJsonOutput:
    def test_cli_json_includes_graph(self, tmp_path):
        from jocky.cli import main
        import io, sys

        demo = tmp_path / "graph_demo.jky"
        demo.write_text(
            'CASE "INC-CLI-GRAPH"\nHOST "LAB-PC-01"\n'
            'ANALYZE PROCESSES\nANALYZE NETWORK\n'
            'BLOCKCHAIN TRACE "0xWALLET001"\nIDENTIFY VASP\nCORRELATE EVIDENCE\nBUILD ATTACK GRAPH\n'
        )

        captured = io.StringIO()
        old_stdout = sys.stdout
        sys.stdout = captured
        try:
            rc = main([str(demo), "--execute", "--fixture", "--json"])
        finally:
            sys.stdout = old_stdout

        assert rc == 0
        data = json.loads(captured.getvalue())
        assert "graph" in data
        assert "nodes" in data["graph"]
        assert "edges" in data["graph"]
        assert "graph_hash" in data["graph"]


# ──────────────────────────────────────────────────────────
# 22. Existing Evidence Integrity
# ──────────────────────────────────────────────────────────
class TestEvidenceIntegrityUnchanged:
    def test_evidence_integrity_remains_valid(self):
        p = _proc_ev()
        c = _conn_ev()
        pkg = build_evidence_package(_CASE, _HOST, [p, c])
        graph = GraphBuilder().build_from_package(pkg)
        for ev in pkg.evidence:
            assert ev.verify_integrity() is True


# ──────────────────────────────────────────────────────────
# 23. Existing Correlation IDs Unchanged
# ──────────────────────────────────────────────────────────
class TestCorrelationIDsUnchanged:
    def test_correlation_id_preserved_on_edge(self):
        p = _proc_ev()
        c = _conn_ev()
        finding = CorrelationFinding(
            id="CORR-SPECIFIC-ID-01",
            correlation_type=CorrelationType.PROCESS_NETWORK,
            source_evidence_ids=[p.id],
            target_evidence_ids=[c.id],
            relationship_type="CONNECTS_TO",
            confidence=0.95,
            score=0.95,
            explanation="test",
            rule_id="R1",
            timestamp=_NOW,
        )
        pkg = build_evidence_package(_CASE, _HOST, [p, c])
        graph = GraphBuilder().build_from_package(pkg, correlation_findings=[finding])
        assert graph.edges[0].correlation_id == "CORR-SPECIFIC-ID-01"


# ──────────────────────────────────────────────────────────
# 24. Empty Graph Handling
# ──────────────────────────────────────────────────────────
class TestEmptyGraphHandling:
    def test_empty_package_yields_empty_graph(self):
        pkg = build_evidence_package(_CASE, _HOST, [])
        graph = GraphBuilder().build_from_package(pkg)
        assert len(graph.nodes) == 0
        assert len(graph.edges) == 0
        assert graph.graph_hash != ""
        assert graph.verify_integrity() is True


# ──────────────────────────────────────────────────────────
# 25. Unknown Evidence Reference Handling
# ──────────────────────────────────────────────────────────
class TestUnknownEvidenceReferenceHandling:
    def test_rel_with_missing_target_does_not_crash(self):
        p = _proc_ev()
        rel = Relationship.create("CONNECTS_TO", p.id, "EVID-UNKNOWN-TARGET")
        pkg = build_evidence_package(_CASE, _HOST, [p], relationships=[rel])
        graph = GraphBuilder().build_from_package(pkg)
        assert len(graph.nodes) == 1
        assert len(graph.edges) == 1


# ──────────────────────────────────────────────────────────
# 26. Full Regression Pipeline
# ──────────────────────────────────────────────────────────
class TestFullRegressionPipeline:
    def test_full_graph_demo_script(self):
        from compiler.compiler import compile_source
        from runtime.executor.executor import RuntimeExecutor
        from blockchain.evm.adapter import EVMAdapter
        from forensic.endpoint.fixture import FixtureEndpointAdapter
        from forensic.network.fixture import FixtureNetworkAdapter

        demo_file = Path(__file__).resolve().parent.parent / "examples" / "graph_demo.jky"
        source = demo_file.read_text(encoding="utf-8")
        cres = compile_source(source)
        assert cres.ok

        executor = RuntimeExecutor(
            cres.ir,
            adapter=FixtureEndpointAdapter(host="LAB-PC-01"),
            network_adapter=FixtureNetworkAdapter(host="LAB-PC-01"),
            blockchain_adapter=EVMAdapter(),
        )
        exec_res = executor.execute()
        graph_res = next(r for r in exec_res.results if r.operation == "BUILD_ATTACK_GRAPH")
        assert graph_res.status == "SUCCESS"
        graph = graph_res.data
        paths = get_cross_domain_paths(graph)
        assert len(paths) >= 1
        top_path = paths[0]
        # Dynamic weakest-link confidence for Process -> Network -> Wallet -> Tx -> VASP:
        assert top_path.confidence == 0.65
        assert len(top_path.nodes) >= 5


# ──────────────────────────────────────────────────────────
# 27. Proof: Building Graph Does Not Change package_hash
# ──────────────────────────────────────────────────────────
class TestPackageHashInvariance:
    def test_building_graph_does_not_alter_package_hash(self):
        """
        Correction 2: Prove that building an InvestigationGraph does not change
        the existing evidence/package integrity or package_hash.
        """
        p = _proc_ev()
        c = _conn_ev()
        rel = Relationship.create("CONNECTS_TO", p.id, c.id)
        pkg = build_evidence_package(_CASE, _HOST, [p, c], relationships=[rel], created_at=_NOW)

        original_hash = pkg.package_hash
        assert pkg.verify_package_integrity() is True

        # Build investigation graph from package
        builder = GraphBuilder()
        graph = builder.build_from_package(pkg)

        # Attach graph to package (derived view)
        pkg_with_graph = build_evidence_package(
            _CASE, _HOST, [p, c], relationships=[rel], created_at=_NOW, graph=graph.to_dict()
        )

        assert pkg_with_graph.package_hash == original_hash
        assert pkg_with_graph.verify_package_integrity() is True


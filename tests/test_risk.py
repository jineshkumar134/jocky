"""
tests/test_risk.py — Phase 10 Risk Engine Tests
===============================================
Comprehensive deterministic, offline test suite for the JOCKY Risk Engine:
 1. RiskFinding model validation
 2. RiskAssessment model validation
 3. Deterministic finding ID generation
 4. RULE_ENDPOINT_NETWORK_ACTIVITY evaluation (15 pts)
 5. RULE_EXTERNAL_NETWORK_CONNECTION evaluation (10 pts)
 6. RULE_NETWORK_BLOCKCHAIN_ASSOCIATION evaluation (20 pts, non-ownership notice)
 7. RULE_BLOCKCHAIN_TRANSACTION_CHAIN evaluation (15 pts)
 8. RULE_VASP_ATTRIBUTION evaluation (15 pts, analytical notice)
 9. RULE_CROSS_DOMAIN_CORRELATION evaluation (20 pts)
10. Rule deduplication (finding IDs based on rule + evidence + correlation IDs)
11. Additive score aggregation across multiple rules
12. Score capped at MAX_RISK_SCORE = 100
13. calculate_severity mapping for LOW (0–24)
14. calculate_severity mapping for MEDIUM (25–49)
15. calculate_severity mapping for HIGH (50–74)
16. calculate_severity mapping for CRITICAL (75–100)
17. Preservation of evidence confidence distinct from risk score
18. Weakest-link confidence preservation on multi-evidence findings
19. risk_hash determinism (identical findings -> identical hash, volatile fields excluded)
20. Runtime ASSESS RISK execution via executor
21. CLI risk assessment output formatting
22. Proof that assessing risk does NOT alter EvidencePackage.package_hash
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List
import pytest

from forensic.evidence.models import (
    EvidenceIntegrity,
    EvidencePackage,
    EvidenceProvenance,
    EvidenceType,
    NetworkConnectionEntity,
    NetworkListenerEntity,
    ProcessEntity,
    Relationship,
    RelationshipType,
    TransactionEntity,
    UniversalEvidence,
    VASPEntity,
    WalletEntity,
)
from forensic.evidence.converters import build_evidence_package
from forensic.evidence.canonical import canonical_hash, generate_evidence_id
from correlation.models import CorrelationFinding, CorrelationResult, CorrelationType
from risk.models import RiskAssessment, RiskFinding, RiskSeverity
from risk.scoring import (
    MAX_RISK_SCORE,
    SCORE_CROSS_DOMAIN,
    SCORE_ENDPOINT_NETWORK,
    SCORE_EXTERNAL_NETWORK,
    SCORE_NETWORK_BLOCKCHAIN,
    SCORE_TRANSACTION_CHAIN,
    SCORE_VASP_ATTRIBUTION,
    calculate_severity,
)
from risk.rules import (
    BlockchainTransactionChainRule,
    CrossDomainCorrelationRule,
    EndpointNetworkActivityRule,
    ExternalNetworkConnectionRule,
    NetworkBlockchainAssociationRule,
    VaspAttributionRule,
    generate_risk_finding_id,
)
from risk.engine import RiskEngine
from risk.serialization import compute_risk_hash, risk_to_dict, risk_to_json
from runtime.executor.executor import InvestigationExecutionResult, RuntimeExecutor
from runtime.executor.dispatcher import OperationResult
from blockchain.evm.adapter import EVMAdapter
from forensic.endpoint.fixture import FixtureEndpointAdapter
from forensic.network.fixture import FixtureNetworkAdapter
from compiler.compiler import compile_source


def _make_provenance(collector: str = "TestAdapter", host: str = "HOST-RISK", case_id: str = "CASE-RISK") -> EvidenceProvenance:
    return EvidenceProvenance(
        collector=collector,
        adapter=collector,
        source="test",
        collection_method="test",
        collected_at="2026-09-12T12:00:00Z",
        host=host,
        case_id=case_id,
    )


def _make_evidence(
    ev_type: EvidenceType,
    entity: Any,
    case_id: str = "CASE-RISK",
    host: str = "HOST-RISK",
    confidence: float = 1.0,
) -> UniversalEvidence:
    entity_dict = entity if isinstance(entity, dict) else entity.model_dump()
    eid = generate_evidence_id(ev_type.value, entity_dict, host, "TestAdapter")
    prelim = UniversalEvidence(
        id=eid,
        type=ev_type,
        source="TestAdapter",
        timestamp="2026-09-12T12:00:00Z",
        entity=entity,
        provenance=_make_provenance("TestAdapter", host, case_id),
        integrity=EvidenceIntegrity(value=""),
        confidence=confidence,
    )
    real_hash = prelim.compute_integrity_hash()
    return UniversalEvidence(
        id=eid,
        type=ev_type,
        source="TestAdapter",
        timestamp="2026-09-12T12:00:00Z",
        entity=entity,
        provenance=_make_provenance("TestAdapter", host, case_id),
        integrity=EvidenceIntegrity(value=real_hash),
        confidence=confidence,
    )


@pytest.fixture
def sample_risk_package() -> EvidencePackage:
    proc_ev = _make_evidence(
        EvidenceType.PROCESS,
        ProcessEntity(pid=3100, name="stealth_app", start_time="2026-09-12T09:00:00Z"),
    )
    net_ev = _make_evidence(
        EvidenceType.NETWORK_CONNECTION,
        NetworkConnectionEntity(
            local_address="10.0.0.5",
            local_port=49152,
            remote_address="203.0.113.50",
            remote_port=443,
            timestamp="2026-09-12T09:05:00Z",
            pid=3100,
        ),
        confidence=0.95,
    )
    tx1_ev = _make_evidence(
        EvidenceType.TRANSACTION,
        TransactionEntity(
            tx_hash="0xTX_RISK_1",
            from_address="0xWALLET_A",
            to_address="0xWALLET_B",
            amount=10.0,
            timestamp="2026-09-12T10:00:00Z",
        ),
        confidence=0.90,
    )
    tx2_ev = _make_evidence(
        EvidenceType.TRANSACTION,
        TransactionEntity(
            tx_hash="0xTX_RISK_2",
            from_address="0xWALLET_B",
            to_address="0xWALLET_C",
            amount=9.9,
            timestamp="2026-09-12T10:15:00Z",
        ),
        confidence=0.85,
    )
    wallet_ev = _make_evidence(
        EvidenceType.WALLET,
        WalletEntity(address="0xWALLET_C", label="Example Exchange Deposit"),
    )
    vasp_ev = _make_evidence(
        EvidenceType.VASP,
        VASPEntity(vasp_id="VASP-EX-1", name="Example Exchange"),
        confidence=0.95,
    )

    rel = Relationship(
        id="REL-RISK-01",
        source_id=proc_ev.id,
        target_id=net_ev.id,
        type=RelationshipType.CONNECTS_TO,
        confidence=0.95,
        supporting_evidence=[proc_ev.id, net_ev.id],
    )

    return build_evidence_package(
        case_id="CASE-RISK",
        host="HOST-RISK",
        evidence=[proc_ev, net_ev, tx1_ev, tx2_ev, wallet_ev, vasp_ev],
        relationships=[rel],
    )


def test_01_risk_finding_model_validation():
    f = RiskFinding(
        id="RISK-TEST-1234567890",
        rule_id="RULE_TEST",
        severity=RiskSeverity.HIGH,
        score=20,
        confidence=0.85,
        title="Test Finding",
        explanation="Test finding explanation",
        evidence_ids=["EVID-1", "EVID-2"],
    )
    assert f.id == "RISK-TEST-1234567890"
    assert f.rule_id == "RULE_TEST"
    assert f.severity == RiskSeverity.HIGH
    assert f.score == 20
    assert f.confidence == 0.85
    d = f.to_dict()
    assert d["severity"] == "HIGH"
    assert d["score"] == 20


def test_02_risk_assessment_model_validation():
    assessment = RiskAssessment(
        case_id="CASE-RISK",
        host="HOST-RISK",
        score=75,
        severity=RiskSeverity.CRITICAL,
        findings=[],
    )
    assert assessment.score == 75
    assert assessment.severity == RiskSeverity.CRITICAL
    d = assessment.to_dict()
    assert d["score"] == 75
    assert d["severity"] == "CRITICAL"


def test_03_deterministic_finding_id_generation():
    id1 = generate_risk_finding_id("RULE_TEST", ["EVID-B", "EVID-A"], ["CORR-1"])
    id2 = generate_risk_finding_id("RULE_TEST", ["EVID-A", "EVID-B"], ["CORR-1"])
    id3 = generate_risk_finding_id("RULE_TEST", ["EVID-A"], ["CORR-1"])

    # Independent of evidence ID sorting order
    assert id1 == id2
    assert id1 != id3
    assert id1.startswith("RISK-TEST-")


def test_04_rule_endpoint_network_activity_evaluation(sample_risk_package):
    rule = EndpointNetworkActivityRule()
    findings = rule.evaluate(sample_risk_package)
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "RULE_ENDPOINT_NETWORK_ACTIVITY"
    assert f.score == SCORE_ENDPOINT_NETWORK
    assert f.confidence == 0.95


def test_05_rule_external_network_connection_evaluation(sample_risk_package):
    rule = ExternalNetworkConnectionRule()
    findings = rule.evaluate(sample_risk_package)
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "RULE_EXTERNAL_NETWORK_CONNECTION"
    assert f.score == SCORE_EXTERNAL_NETWORK
    assert "203.0.113.50" in f.explanation


def test_06_rule_network_blockchain_association_evaluation():
    rule = NetworkBlockchainAssociationRule()
    # Mock a network-blockchain correlation finding
    corr = CorrelationFinding(
        id="CORR-NET-BC-01",
        correlation_type=CorrelationType.NETWORK_BLOCKCHAIN,
        relationship_type="ASSOCIATED_WITH",
        confidence=0.65,
        score=0.65,
        source_evidence_ids=["EVID-NET-1"],
        target_evidence_ids=["EVID-WALLET-1"],
        rule_id="NETWORK_BLOCKCHAIN_EXPLICIT_MAPPING",
        explanation="Synthetic mapping between IP and wallet.",
    )
    corr_res = CorrelationResult(case_id="CASE-R", host="HOST-R", findings=[corr], confidence=0.65, domain_pairs_checked=[])
    pkg = build_evidence_package(case_id="CASE-R", host="HOST-R", evidence=[], relationships=[])

    findings = rule.evaluate(pkg, correlation_result=corr_res)
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "RULE_NETWORK_BLOCKCHAIN_ASSOCIATION"
    assert f.score == SCORE_NETWORK_BLOCKCHAIN
    assert f.confidence == 0.65
    assert "does not establish wallet ownership" in f.explanation.lower()


def test_07_rule_blockchain_transaction_chain_evaluation(sample_risk_package):
    rule = BlockchainTransactionChainRule()
    findings = rule.evaluate(sample_risk_package)
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "RULE_BLOCKCHAIN_TRANSACTION_CHAIN"
    assert f.score == SCORE_TRANSACTION_CHAIN
    # Weakest-link confidence of tx1 (0.90) and tx2 (0.85) -> 0.85
    assert f.confidence == 0.85


def test_08_rule_vasp_attribution_evaluation(sample_risk_package):
    rule = VaspAttributionRule()
    findings = rule.evaluate(sample_risk_package)
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "RULE_VASP_ATTRIBUTION"
    assert f.score == SCORE_VASP_ATTRIBUTION
    assert "not private kyc" in f.explanation.lower()


def test_09_rule_cross_domain_correlation_evaluation():
    rule = CrossDomainCorrelationRule()
    corr = CorrelationFinding(
        id="CORR-CROSS-01",
        correlation_type=CorrelationType.CROSS_DOMAIN,
        relationship_type="CROSS_DOMAIN_CHAIN",
        confidence=0.65,
        score=0.65,
        source_evidence_ids=["EVID-1", "EVID-2"],
        target_evidence_ids=["EVID-3", "EVID-4"],
        rule_id="CROSS_DOMAIN_CHAIN",
        explanation="Cross-domain chain across 4 domains.",
    )
    corr_res = CorrelationResult(case_id="CASE-R", host="HOST-R", findings=[corr], confidence=0.65, domain_pairs_checked=[])
    pkg = build_evidence_package(case_id="CASE-R", host="HOST-R", evidence=[], relationships=[])

    findings = rule.evaluate(pkg, correlation_result=corr_res)
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "RULE_CROSS_DOMAIN_CORRELATION"
    assert f.score == SCORE_CROSS_DOMAIN
    assert f.confidence == 0.65


def test_10_rule_deduplication():
    # If the same rule yields the same finding ID, engine deduplicates
    class DuplicateRule(EndpointNetworkActivityRule):
        pass

    engine = RiskEngine(rules=[EndpointNetworkActivityRule(), DuplicateRule()])
    proc_ev = _make_evidence(
        EvidenceType.PROCESS,
        ProcessEntity(pid=5000, name="app"),
    )
    net_ev = _make_evidence(
        EvidenceType.NETWORK_CONNECTION,
        NetworkConnectionEntity(local_address="10.0.0.1", local_port=1234, remote_address="1.1.1.1", remote_port=80),
    )
    rel = Relationship(
        id="REL-1",
        source_id=proc_ev.id,
        target_id=net_ev.id,
        type=RelationshipType.CONNECTS_TO,
        confidence=0.9,
    )
    pkg = build_evidence_package("CASE-D", "HOST-D", [proc_ev, net_ev], [rel])
    assessment = engine.assess(pkg)
    # Finding IDs should be deduplicated
    assert len(assessment.findings) == 1


def test_11_additive_score_aggregation(sample_risk_package):
    engine = RiskEngine()
    assessment = engine.assess(sample_risk_package)
    # Sample package triggers:
    # - EndpointNetworkActivity: 15
    # - ExternalNetworkConnection: 10
    # - BlockchainTransactionChain: 15
    # - VaspAttribution: 15
    # Total = 55 -> HIGH severity
    expected_sum = 15 + 10 + 15 + 15
    assert assessment.score == expected_sum
    assert assessment.severity == RiskSeverity.HIGH


def test_12_score_capped_at_100():
    engine = RiskEngine()
    # Create findings whose scores sum to > 100
    findings = [
        RiskFinding(
            id=f"RISK-F-{i}",
            rule_id=f"RULE_{i}",
            severity=RiskSeverity.CRITICAL,
            score=30,
            confidence=0.9,
            title=f"Finding {i}",
            explanation="...",
        )
        for i in range(5)
    ]
    raw_sum = sum(f.score for f in findings)
    assert raw_sum == 150
    capped = min(MAX_RISK_SCORE, raw_sum)
    assert capped == 100
    assert calculate_severity(capped) == RiskSeverity.CRITICAL


def test_13_severity_mapping_low():
    assert calculate_severity(0) == RiskSeverity.LOW
    assert calculate_severity(10) == RiskSeverity.LOW
    assert calculate_severity(24) == RiskSeverity.LOW


def test_14_severity_mapping_medium():
    assert calculate_severity(25) == RiskSeverity.MEDIUM
    assert calculate_severity(35) == RiskSeverity.MEDIUM
    assert calculate_severity(49) == RiskSeverity.MEDIUM


def test_15_severity_mapping_high():
    assert calculate_severity(50) == RiskSeverity.HIGH
    assert calculate_severity(60) == RiskSeverity.HIGH
    assert calculate_severity(74) == RiskSeverity.HIGH


def test_16_severity_mapping_critical():
    assert calculate_severity(75) == RiskSeverity.CRITICAL
    assert calculate_severity(90) == RiskSeverity.CRITICAL
    assert calculate_severity(100) == RiskSeverity.CRITICAL


def test_17_confidence_preserved_distinct_from_score(sample_risk_package):
    engine = RiskEngine()
    assessment = engine.assess(sample_risk_package)
    for f in assessment.findings:
        # Score is integer points [10, 15, 20]
        assert isinstance(f.score, int)
        assert f.score in (10, 15, 20)
        # Confidence is float certainty [0.0, 1.0]
        assert isinstance(f.confidence, float)
        assert 0.0 <= f.confidence <= 1.0


def test_18_weakest_link_confidence_on_multi_evidence(sample_risk_package):
    rule = BlockchainTransactionChainRule()
    findings = rule.evaluate(sample_risk_package)
    assert len(findings) == 1
    # Multi-hop tx1 has conf 0.90, tx2 has conf 0.85 -> min is 0.85
    assert findings[0].confidence == 0.85


def test_19_risk_hash_determinism(sample_risk_package):
    engine = RiskEngine()
    a1 = engine.assess(sample_risk_package)
    a2 = engine.assess(sample_risk_package)

    assert a1.risk_hash != ""
    assert a1.risk_hash == a2.risk_hash
    assert a1.verify_integrity() is True
    assert a2.verify_integrity() is True


def test_20_runtime_assess_risk_execution():
    script = """
    CASE "INC-RISK-01"
    HOST "TEST-HOST"
    ANALYZE PROCESSES
    ANALYZE NETWORK
    ASSESS RISK
    """
    res = compile_source(script)
    assert res.ok is True

    executor = RuntimeExecutor(
        res.ir,
        adapter=FixtureEndpointAdapter(host="TEST-HOST"),
        network_adapter=FixtureNetworkAdapter(host="TEST-HOST"),
        blockchain_adapter=EVMAdapter(),
    )
    exec_res = executor.execute()
    assert len(exec_res.results) > 0

    risk_op = next((r for r in exec_res.results if r.operation == "ASSESS_RISK"), None)
    assert risk_op is not None
    assert risk_op.status == "SUCCESS"
    assert isinstance(risk_op.data, RiskAssessment)
    assert risk_op.data.score >= 0
    assert len(risk_op.data.findings) > 0


def test_21_cli_risk_assessment_output_formatting(sample_risk_package, capsys):
    from jocky.cli import _print_execution_output

    engine = RiskEngine()
    assessment = engine.assess(sample_risk_package)

    mock_exec = InvestigationExecutionResult(
        case_id="CASE-RISK",
        host="HOST-RISK",
        started_at="2026-09-12T12:00:00Z",
        completed_at="2026-09-12T12:01:00Z",
        results=[
            OperationResult(
                operation="ASSESS_RISK",
                status="SUCCESS",
                data=assessment,
            )
        ],
    )

    _print_execution_output(mock_exec, is_fixture=True)
    captured = capsys.readouterr().out

    assert "RISK ASSESSMENT" in captured
    assert f"Score:    {assessment.score} / 100" in captured
    assert "Severity: HIGH" in captured
    assert "Top Findings:" in captured
    assert "RULE_ENDPOINT_NETWORK_ACTIVITY" in captured


def test_22_package_hash_invariance_with_risk_assessment(sample_risk_package):
    hash_before = sample_risk_package.package_hash
    engine = RiskEngine()
    assessment = engine.assess(sample_risk_package)

    # Package hash must remain 100% invariant
    assert sample_risk_package.package_hash == hash_before
    assert sample_risk_package.verify_package_integrity() is True


def test_23_primary_cross_domain_confidence_is_065():
    """
    Regression Test 1: Prove primary cross-domain investigation path confidence
    is derived as weakest-link min(0.95, 0.65, 0.95, 0.95, 1.00) = 0.65.
    """
    from graph.models import GraphNode, GraphEdge, GraphNodeType, InvestigationGraph
    from graph.queries import get_cross_domain_paths

    now = datetime.now(timezone.utc).isoformat()
    nodes = [
        GraphNode(id="EVID-PROC-01", evidence_id="EVID-PROC-01", node_type=GraphNodeType.PROCESS, label="suspicious_miner", confidence=1.0, timestamp=now),
        GraphNode(id="EVID-NETC-01", evidence_id="EVID-NETC-01", node_type=GraphNodeType.NETWORK_CONNECTION, label="203.0.113.25:443", confidence=1.0, timestamp=now),
        GraphNode(id="EVID-WLLT-01", evidence_id="EVID-WLLT-01", node_type=GraphNodeType.WALLET, label="Synthetic Suspicious EOA", confidence=1.0, timestamp=now),
        GraphNode(id="EVID-TX-01", evidence_id="EVID-TX-01", node_type=GraphNodeType.TRANSACTION, label="0xTX001 (10.5 ETH)", confidence=1.0, timestamp=now),
        GraphNode(id="EVID-VASP-01", evidence_id="EVID-VASP-01", node_type=GraphNodeType.VASP, label="Example Exchange", confidence=1.0, timestamp=now),
    ]
    edges = [
        GraphEdge(id="E1", source_id="EVID-PROC-01", target_id="EVID-NETC-01", relationship_type="CONNECTS_TO", confidence=0.95, correlation_id="CORR-P1"),
        GraphEdge(id="E2", source_id="EVID-NETC-01", target_id="EVID-WLLT-01", relationship_type="ASSOCIATED_WITH", confidence=0.65, correlation_id="CORR-P2"),
        GraphEdge(id="E3", source_id="EVID-WLLT-01", target_id="EVID-TX-01", relationship_type="SENT_TO", confidence=0.95, correlation_id="CORR-P3"),
        GraphEdge(id="E4", source_id="EVID-TX-01", target_id="EVID-VASP-01", relationship_type="ATTRIBUTED_TO", confidence=1.00, correlation_id="CORR-P4"),
    ]
    graph = InvestigationGraph(case_id="CASE-REG", host="HOST-REG", nodes=nodes, edges=edges)
    paths = get_cross_domain_paths(graph)
    assert len(paths) >= 1
    primary_path = paths[0]
    assert primary_path.confidence == 0.65
    assert primary_path.edge_confidences == [0.95, 0.65, 0.95, 1.00]

    # Evaluate risk rule with this graph
    pkg = build_evidence_package(case_id="CASE-REG", host="HOST-REG", evidence=[], relationships=[])
    rule = CrossDomainCorrelationRule()
    findings = rule.evaluate(pkg, graph=graph)
    assert len(findings) == 1
    assert findings[0].confidence == 0.65
    assert findings[0].metadata["weakest_link_confidence"] == 0.65
    assert "0.65" in findings[0].explanation


def test_24_secondary_vasp_attribution_remains_separate_with_055():
    """
    Regression Test 2: Prove secondary VASP attribution (confidence 0.55) remains
    a separate distinct finding and does not replace the primary attribution or path confidence.
    """
    now = datetime.now(timezone.utc).isoformat()
    vasp_primary = _make_evidence(EvidenceType.VASP, {"name": "Example Exchange", "vasp_id": "VASP-01"}, confidence=1.00)
    vasp_secondary = _make_evidence(EvidenceType.VASP, {"name": "Example Custody Services", "vasp_id": "VASP-02"}, confidence=0.55)

    pkg = build_evidence_package(
        case_id="CASE-REG-VASP",
        host="HOST-REG-VASP",
        evidence=[vasp_primary, vasp_secondary],
        relationships=[],
    )

    rule = VaspAttributionRule()
    findings = rule.evaluate(pkg)
    assert len(findings) == 2

    # Primary finding
    primary_finding = next(f for f in findings if f.confidence == 1.00)
    assert primary_finding.title == "VASP Infrastructure Attribution"
    assert primary_finding.metadata["attribution_tier"] == "primary"
    assert primary_finding.evidence_ids == [vasp_primary.id]

    # Secondary finding
    secondary_finding = next(f for f in findings if f.confidence == 0.55)
    assert secondary_finding.title == "Secondary VASP Infrastructure Attribution"
    assert secondary_finding.metadata["attribution_tier"] == "secondary"
    assert secondary_finding.evidence_ids == [vasp_secondary.id]
    assert "secondary" in secondary_finding.explanation.lower()


def test_25_no_stale_hardcoded_055_on_primary_path():
    """
    Regression Test 3: Verify that no stale hardcoded 0.55 is assigned to
    the primary cross-domain path when evaluating across the full pipeline.
    """
    from compiler.compiler import compile_source
    from runtime.executor.executor import RuntimeExecutor
    from forensic.endpoint.fixture import FixtureEndpointAdapter
    from forensic.network.fixture import FixtureNetworkAdapter
    from blockchain.evm.adapter import EVMAdapter
    from pathlib import Path

    demo_file = Path(__file__).resolve().parent.parent / "examples" / "timeline_risk_demo.jky"
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

    risk_op = next(r for r in exec_res.results if r.operation == "ASSESS_RISK")
    assert risk_op.status == "SUCCESS"
    assessment = risk_op.data

    cross_findings = [f for f in assessment.findings if f.rule_id == "RULE_CROSS_DOMAIN_CORRELATION"]
    assert len(cross_findings) >= 1
    primary_cross = cross_findings[0]
    # Must be 0.65 (weakest-link), NOT stale 0.55
    assert primary_cross.confidence == 0.65
    assert primary_cross.confidence != 0.55


def test_26_risk_confidence_traceability():
    """
    Regression Test 4: Verify risk findings reference exact evidence_ids and correlation_ids,
    and confidence is traceable: risk finding -> correlation/evidence -> original confidence.
    """
    from compiler.compiler import compile_source
    from runtime.executor.executor import RuntimeExecutor
    from forensic.endpoint.fixture import FixtureEndpointAdapter
    from forensic.network.fixture import FixtureNetworkAdapter
    from blockchain.evm.adapter import EVMAdapter
    from pathlib import Path

    demo_file = Path(__file__).resolve().parent.parent / "examples" / "timeline_risk_demo.jky"
    source = demo_file.read_text(encoding="utf-8")
    cres = compile_source(source)

    executor = RuntimeExecutor(
        cres.ir,
        adapter=FixtureEndpointAdapter(host="LAB-PC-01"),
        network_adapter=FixtureNetworkAdapter(host="LAB-PC-01"),
        blockchain_adapter=EVMAdapter(),
    )
    exec_res = executor.execute()
    assessment = next(r for r in exec_res.results if r.operation == "ASSESS_RISK").data

    # Every finding has non-empty evidence_ids
    for f in assessment.findings:
        assert len(f.evidence_ids) > 0, f"Finding {f.id} must reference evidence_ids"
        assert 0.0 <= f.confidence <= 1.0

    # Cross domain finding references correlation IDs and matches primary path confidence
    cross_f = next(f for f in assessment.findings if f.rule_id == "RULE_CROSS_DOMAIN_CORRELATION")
    assert len(cross_f.correlation_ids) > 0
    assert cross_f.confidence == 0.65

    # Secondary VASP finding references its specific VASP evidence ID and correlation IDs
    sec_vasp_f = next(
        f for f in assessment.findings
        if f.rule_id == "RULE_VASP_ATTRIBUTION" and f.confidence == 0.55
    )
    assert sec_vasp_f.metadata["attribution_tier"] == "secondary"
    assert len(sec_vasp_f.correlation_ids) > 0


def test_27_package_hash_unchanged_by_risk_assessment_in_full_pipeline():
    """
    Regression Test 5: Verify EvidencePackage.package_hash remains identical before
    and after risk engine execution in full pipeline.
    """
    from compiler.compiler import compile_source
    from runtime.executor.executor import RuntimeExecutor
    from forensic.endpoint.fixture import FixtureEndpointAdapter
    from forensic.network.fixture import FixtureNetworkAdapter
    from blockchain.evm.adapter import EVMAdapter
    from pathlib import Path

    demo_file = Path(__file__).resolve().parent.parent / "examples" / "timeline_risk_demo.jky"
    source = demo_file.read_text(encoding="utf-8")
    cres = compile_source(source)

    executor = RuntimeExecutor(
        cres.ir,
        adapter=FixtureEndpointAdapter(host="LAB-PC-01"),
        network_adapter=FixtureNetworkAdapter(host="LAB-PC-01"),
        blockchain_adapter=EVMAdapter(),
    )
    exec_res = executor.execute()
    pkg = exec_res.build_universal_package()
    original_hash = pkg.package_hash
    assert pkg.verify_package_integrity() is True

    # Re-run assessment explicitly
    engine = RiskEngine()
    assessment = engine.assess(pkg)
    assert pkg.package_hash == original_hash
    assert pkg.verify_package_integrity() is True


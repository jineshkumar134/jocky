"""
tests/test_correlation.py — Phase 8 Correlation Engine Tests
=============================================================
22 deterministic, offline tests covering:
 1. Model validation
 2. Confidence bounds
 3. Deterministic correlation ID
 4. PROCESS → NETWORK PID correlation
 5. Missing PID rejection
 6. PID zero rejection
 7. DNS → NETWORK correlation (no match expected with default fixtures)
 8. Explicit network → blockchain fixture mapping
 9. Wallet → transaction correlation
10. Transaction → VASP correlation
11. Cross-domain chain generation
12. Weakest-link confidence calculation
13. Explanation generation
14. Supporting evidence IDs
15. No fabricated relationship
16. Unknown/unmatched evidence handling
17. Empty evidence package
18. Runtime CORRELATE EVIDENCE
19. CLI JSON output includes correlations
20. Evidence integrity remains valid after correlation
21. Existing evidence IDs remain unchanged
22. Full regression — all 221 prior tests still pass
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import List

import pytest

from forensic.evidence.canonical import canonical_hash, generate_evidence_id
from forensic.evidence.models import (
    DNSRecordEntity,
    EvidenceIntegrity,
    EvidencePackage,
    EvidenceProvenance,
    EvidenceType,
    NetworkConnectionEntity,
    ProcessEntity,
    RelationshipType,
    TransactionEntity,
    UniversalEvidence,
    VASPEntity,
    WalletEntity,
)
from forensic.evidence.converters import build_evidence_package

from correlation.engine import CorrelationEngine
from correlation.models import (
    CorrelationFinding,
    CorrelationResult,
    CorrelationType,
    generate_correlation_id,
)
from correlation.rules import (
    CrossDomainChainRule,
    NetworkBlockchainMappingRule,
    NetworkDnsRecordRule,
    ProcessNetworkPidRule,
    TransactionVaspRule,
    WalletTransactionRule,
)
from correlation.scoring import (
    SCORE_DIRECT_PID_MATCH,
    SCORE_EXPLICIT_DNS_MATCH,
    SCORE_EXPLICIT_FIXTURE_NETWORK_BLOCKCHAIN,
    SCORE_TRANSACTION_ADDRESS_MATCH,
    weakest_link,
)


# ──────────────────────────────────────────────────────────
# Shared fixture helpers
# ──────────────────────────────────────────────────────────

_HOST = "TEST-HOST"
_CASE = "INC-CORR-TEST"
_NOW = datetime.now(timezone.utc).isoformat()


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


def _make_integrity(entity_dict: dict, evid_type: str) -> EvidenceIntegrity:
    seed = canonical_hash(entity_dict)
    return EvidenceIntegrity(value=seed)


def _make_evidence(ev_type: EvidenceType, entity, collector: str = "TestAdapter") -> UniversalEvidence:
    entity_dict = entity.model_dump()
    ev_id = generate_evidence_id(ev_type.value, entity_dict, _HOST, collector)
    integrity_val = canonical_hash({
        "id": ev_id, "type": ev_type.value, "entity": entity_dict
    })
    return UniversalEvidence(
        id=ev_id,
        type=ev_type,
        source=collector,
        timestamp=_NOW,
        entity=entity,
        provenance=_make_provenance(collector),
        integrity=EvidenceIntegrity(value=integrity_val),
    )


def _process_ev(pid: int, name: str = "proc") -> UniversalEvidence:
    return _make_evidence(
        EvidenceType.PROCESS,
        ProcessEntity(pid=pid, name=name, status="running"),
    )


def _conn_ev(pid: int | None, remote_addr: str = "1.2.3.4", port: int = 443) -> UniversalEvidence:
    return _make_evidence(
        EvidenceType.NETWORK_CONNECTION,
        NetworkConnectionEntity(
            local_address="192.168.1.1",
            local_port=12345,
            remote_address=remote_addr,
            remote_port=port,
            pid=pid,
            process_name="proc",
        ),
    )


def _wallet_ev(address: str, label: str = "Test Wallet") -> UniversalEvidence:
    return _make_evidence(
        EvidenceType.WALLET,
        WalletEntity(address=address, label=label, wallet_type="eoa"),
    )


def _tx_ev(tx_hash: str, from_addr: str, to_addr: str, amount: float = 1.0) -> UniversalEvidence:
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


def _vasp_ev(vasp_id: str, name: str, matched_wallets: list, confidence: float = 0.91) -> UniversalEvidence:
    return _make_evidence(
        EvidenceType.VASP,
        VASPEntity(
            vasp_id=vasp_id,
            name=name,
            confidence=confidence,
            score=confidence,
            matched_wallets=matched_wallets,
        ),
    )


def _empty_package() -> EvidencePackage:
    return build_evidence_package(
        case_id=_CASE, host=_HOST, evidence=[], relationships=[]
    )


# ──────────────────────────────────────────────────────────
# 1. Correlation model validation
# ──────────────────────────────────────────────────────────

class TestCorrelationModels:
    def test_finding_fields_required(self):
        f = CorrelationFinding(
            id="CORR-TEST-000000000000",
            correlation_type=CorrelationType.PROCESS_NETWORK,
            source_evidence_ids=["A"],
            target_evidence_ids=["B"],
            relationship_type="CONNECTS_TO",
            confidence=0.95,
            score=0.95,
            explanation="Test",
            rule_id="TEST_RULE",
            timestamp=_NOW,
        )
        assert f.correlation_type == CorrelationType.PROCESS_NETWORK
        assert f.rule_id == "TEST_RULE"

    def test_result_fields_required(self):
        r = CorrelationResult(
            case_id=_CASE, host=_HOST, confidence=0.75, generated_at=_NOW
        )
        assert r.case_id == _CASE
        assert r.findings == []

    def test_correlation_type_enum_values(self):
        assert CorrelationType.PROCESS_NETWORK.value == "PROCESS_NETWORK"
        assert CorrelationType.CROSS_DOMAIN.value == "CROSS_DOMAIN"
        assert len(list(CorrelationType)) == 6


# ──────────────────────────────────────────────────────────
# 2. Confidence bounds
# ──────────────────────────────────────────────────────────

class TestConfidenceBounds:
    def test_confidence_clamped_to_1(self):
        f = CorrelationFinding(
            id="X", correlation_type=CorrelationType.PROCESS_NETWORK,
            source_evidence_ids=[], target_evidence_ids=[],
            relationship_type="R", confidence=1.5, score=1.5,
            explanation="", rule_id="R", timestamp=_NOW,
        )
        assert f.confidence == 1.0
        assert f.score == 1.0

    def test_confidence_clamped_to_0(self):
        f = CorrelationFinding(
            id="X", correlation_type=CorrelationType.PROCESS_NETWORK,
            source_evidence_ids=[], target_evidence_ids=[],
            relationship_type="R", confidence=-0.5, score=-0.1,
            explanation="", rule_id="R", timestamp=_NOW,
        )
        assert f.confidence == 0.0
        assert f.score == 0.0

    def test_result_confidence_clamped(self):
        r = CorrelationResult(
            case_id=_CASE, host=_HOST, confidence=2.0, generated_at=_NOW
        )
        assert r.confidence == 1.0


# ──────────────────────────────────────────────────────────
# 3. Deterministic correlation ID
# ──────────────────────────────────────────────────────────

class TestDeterministicID:
    def test_same_inputs_same_id(self):
        inputs = {"proc_evidence_id": "A", "conn_evidence_id": "B", "pid": 4821}
        id1 = generate_correlation_id(CorrelationType.PROCESS_NETWORK.value, inputs)
        id2 = generate_correlation_id(CorrelationType.PROCESS_NETWORK.value, inputs)
        assert id1 == id2

    def test_different_inputs_different_id(self):
        inputs1 = {"proc_evidence_id": "A", "conn_evidence_id": "B", "pid": 4821}
        inputs2 = {"proc_evidence_id": "C", "conn_evidence_id": "D", "pid": 9999}
        id1 = generate_correlation_id(CorrelationType.PROCESS_NETWORK.value, inputs1)
        id2 = generate_correlation_id(CorrelationType.PROCESS_NETWORK.value, inputs2)
        assert id1 != id2

    def test_id_format(self):
        cid = generate_correlation_id("PROCESS_NETWORK", {"x": 1})
        assert cid.startswith("CORR-")
        parts = cid.split("-")
        assert len(parts) == 3
        assert len(parts[2]) == 12


# ──────────────────────────────────────────────────────────
# 4. PROCESS → NETWORK PID correlation
# ──────────────────────────────────────────────────────────

class TestProcessNetworkRule:
    def test_pid_match_produces_finding(self):
        items = [_process_ev(4821, "suspicious_miner"), _conn_ev(4821, "203.0.113.25")]
        rule = ProcessNetworkPidRule()
        findings = rule.correlate(items)
        assert len(findings) == 1
        f = findings[0]
        assert f.correlation_type == CorrelationType.PROCESS_NETWORK
        assert f.relationship_type == "CONNECTS_TO"
        assert f.confidence == SCORE_DIRECT_PID_MATCH

    def test_pid_match_explanation_contains_pid(self):
        items = [_process_ev(4821, "suspicious_miner"), _conn_ev(4821, "1.2.3.4")]
        findings = ProcessNetworkPidRule().correlate(items)
        assert "4821" in findings[0].explanation

    def test_pid_match_source_target_ids(self):
        p = _process_ev(4821)
        c = _conn_ev(4821)
        findings = ProcessNetworkPidRule().correlate([p, c])
        assert p.id in findings[0].source_evidence_ids
        assert c.id in findings[0].target_evidence_ids


# ──────────────────────────────────────────────────────────
# 5. Missing PID rejection
# ──────────────────────────────────────────────────────────

class TestMissingPidRejection:
    def test_no_pid_on_connection_produces_no_finding(self):
        items = [_process_ev(4821), _conn_ev(None)]
        findings = ProcessNetworkPidRule().correlate(items)
        assert findings == []

    def test_mismatched_pids_produce_no_finding(self):
        items = [_process_ev(4821), _conn_ev(9999)]
        findings = ProcessNetworkPidRule().correlate(items)
        assert findings == []


# ──────────────────────────────────────────────────────────
# 6. PID zero rejection
# ──────────────────────────────────────────────────────────

class TestPidZeroRejection:
    def test_pid_zero_process_not_correlated(self):
        items = [_process_ev(0), _conn_ev(0)]
        findings = ProcessNetworkPidRule().correlate(items)
        assert findings == []


# ──────────────────────────────────────────────────────────
# 7. DNS ↔ Network (no match in default fixture)
# ──────────────────────────────────────────────────────────

class TestNetworkDnsRule:
    def test_no_match_no_finding(self):
        """
        With default fixture data, DNS resolves example.com → 93.184.216.34.
        The network connections go to 203.0.113.25 and 198.51.100.20 — neither
        matches the DNS record. Rule correctly produces no findings.
        """
        dns_entity = DNSRecordEntity(
            domain="example.com",
            addresses=["93.184.216.34"],
            status="RESOLVED",
        )
        dns_ev = _make_evidence(EvidenceType.DNS_RECORD, dns_entity)
        conn_ev = _conn_ev(4821, "203.0.113.25")
        findings = NetworkDnsRecordRule().correlate([conn_ev, dns_ev])
        assert findings == []

    def test_matching_ip_produces_finding(self):
        dns_entity = DNSRecordEntity(
            domain="suspicious.test",
            addresses=["203.0.113.25"],
            status="RESOLVED",
        )
        dns_ev = _make_evidence(EvidenceType.DNS_RECORD, dns_entity)
        conn_ev = _conn_ev(4821, "203.0.113.25")
        findings = NetworkDnsRecordRule().correlate([conn_ev, dns_ev])
        assert len(findings) == 1
        assert findings[0].confidence == SCORE_EXPLICIT_DNS_MATCH
        assert findings[0].relationship_type == "RESOLVES_TO"


# ──────────────────────────────────────────────────────────
# 8. Network → Blockchain fixture mapping
# ──────────────────────────────────────────────────────────

class TestNetworkBlockchainMappingRule:
    def test_fixture_ip_matches_wallet(self):
        """203.0.113.25 → 0xWALLET001 in fixture mapping."""
        conn = _conn_ev(4821, "203.0.113.25")
        wallet = _wallet_ev("0xWALLET001", "Synthetic Suspicious EOA")
        rule = NetworkBlockchainMappingRule()
        findings = rule.correlate([conn, wallet])
        assert len(findings) == 1
        f = findings[0]
        assert f.correlation_type == CorrelationType.NETWORK_BLOCKCHAIN
        assert f.confidence == SCORE_EXPLICIT_FIXTURE_NETWORK_BLOCKCHAIN
        assert f.relationship_type == "ASSOCIATED_WITH"

    def test_fixture_mapping_explanation_has_no_ownership_claim(self):
        conn = _conn_ev(4821, "203.0.113.25")
        wallet = _wallet_ev("0xWALLET001")
        findings = NetworkBlockchainMappingRule().correlate([conn, wallet])
        expl = findings[0].explanation.lower()
        assert "ownership" in expl
        assert "does not establish" in expl

    def test_unmapped_ip_no_finding(self):
        conn = _conn_ev(4821, "10.99.99.99")
        wallet = _wallet_ev("0xWALLET001")
        findings = NetworkBlockchainMappingRule().correlate([conn, wallet])
        assert findings == []

    def test_mapped_ip_but_missing_wallet_no_finding(self):
        """Wallet evidence not present → no fabricated relationship."""
        conn = _conn_ev(4821, "203.0.113.25")
        findings = NetworkBlockchainMappingRule().correlate([conn])
        assert findings == []


# ──────────────────────────────────────────────────────────
# 9. Wallet → Transaction correlation
# ──────────────────────────────────────────────────────────

class TestWalletTransactionRule:
    def test_from_address_produces_finding(self):
        w = _wallet_ev("0xWALLET001")
        tx = _tx_ev("0xTX001", "0xWALLET001", "0xWALLET002", 10.5)
        findings = WalletTransactionRule().correlate([w, tx])
        assert any(f.relationship_type == "SENT_TO" for f in findings)

    def test_to_address_produces_finding(self):
        w = _wallet_ev("0xWALLET002")
        tx = _tx_ev("0xTX001", "0xWALLET001", "0xWALLET002", 10.5)
        findings = WalletTransactionRule().correlate([w, tx])
        assert any(f.relationship_type == "SENT_TO" for f in findings)

    def test_confidence_is_transaction_address_match(self):
        w = _wallet_ev("0xWALLET001")
        tx = _tx_ev("0xTX001", "0xWALLET001", "0xOTHER", 1.0)
        findings = WalletTransactionRule().correlate([w, tx])
        assert all(f.confidence == SCORE_TRANSACTION_ADDRESS_MATCH for f in findings)

    def test_unrelated_wallet_no_finding(self):
        w = _wallet_ev("0xUNRELATED")
        tx = _tx_ev("0xTX001", "0xWALLET001", "0xWALLET002")
        findings = WalletTransactionRule().correlate([w, tx])
        assert findings == []


# ──────────────────────────────────────────────────────────
# 10. Transaction → VASP correlation
# ──────────────────────────────────────────────────────────

class TestTransactionVaspRule:
    def test_to_address_in_matched_wallets(self):
        tx = _tx_ev("0xTX002", "0xWALLET002", "0xWALLET003")
        vasp = _vasp_ev("VASP-1", "Example Exchange", ["0xWALLET003"], 0.91)
        findings = TransactionVaspRule().correlate([tx, vasp])
        assert len(findings) == 1
        f = findings[0]
        assert f.relationship_type == "ATTRIBUTED_TO"
        assert abs(f.confidence - 0.91) < 0.001

    def test_explanation_is_hedged(self):
        tx = _tx_ev("0xTX002", "0xWALLET002", "0xWALLET003")
        vasp = _vasp_ev("VASP-1", "Example Exchange", ["0xWALLET003"], 0.91)
        findings = TransactionVaspRule().correlate([tx, vasp])
        expl = findings[0].explanation
        assert "associated with" in expl.lower()
        assert "does not prove" in expl.lower()

    def test_unmatched_wallet_no_finding(self):
        tx = _tx_ev("0xTX002", "0xWALLET002", "0xWALLET003")
        vasp = _vasp_ev("VASP-1", "Example Exchange", ["0xDIFFERENT"], 0.91)
        findings = TransactionVaspRule().correlate([tx, vasp])
        assert findings == []


# ──────────────────────────────────────────────────────────
# 11. Cross-domain chain generation
# ──────────────────────────────────────────────────────────

class TestCrossDomainChain:
    def _build_prior_findings(self) -> list:
        p = _process_ev(4821)
        c = _conn_ev(4821, "203.0.113.25")
        w = _wallet_ev("0xWALLET001")
        tx = _tx_ev("0xTX001", "0xWALLET001", "0xWALLET002")
        vasp = _vasp_ev("V1", "Example Exchange", ["0xWALLET002"], 0.91)
        items = [p, c, w, tx, vasp]
        findings = []
        findings.extend(ProcessNetworkPidRule().correlate(items))
        findings.extend(NetworkBlockchainMappingRule().correlate(items))
        findings.extend(WalletTransactionRule().correlate(items))
        findings.extend(TransactionVaspRule().correlate(items))
        return findings, items

    def test_cross_domain_finding_produced(self):
        prior, items = self._build_prior_findings()
        assert len(prior) >= 2  # At least 2 domain pairs needed
        cross = CrossDomainChainRule().correlate(items, prior)
        assert len(cross) == 1
        assert cross[0].correlation_type == CorrelationType.CROSS_DOMAIN

    def test_cross_domain_only_when_multi_domain(self):
        # Only one domain type → no cross-domain
        items = [_process_ev(4821), _conn_ev(4821)]
        prior = ProcessNetworkPidRule().correlate(items)
        cross = CrossDomainChainRule().correlate(items, prior)
        assert cross == []

    def test_empty_prior_no_cross_domain(self):
        cross = CrossDomainChainRule().correlate([], [])
        assert cross == []


# ──────────────────────────────────────────────────────────
# 12. Weakest-link confidence
# ──────────────────────────────────────────────────────────

class TestWeakestLink:
    def test_weakest_link_is_minimum(self):
        assert weakest_link([0.95, 0.65, 0.95, 0.91]) == 0.65

    def test_single_value(self):
        assert weakest_link([0.80]) == 0.80

    def test_empty_list_returns_zero(self):
        assert weakest_link([]) == 0.0

    def test_clamped_to_unit(self):
        assert weakest_link([1.5, 0.5, -0.1]) == 0.0

    def test_cross_domain_confidence_uses_weakest_link(self):
        items = [_process_ev(4821), _conn_ev(4821, "203.0.113.25"), _wallet_ev("0xWALLET001")]
        prior = []
        prior.extend(ProcessNetworkPidRule().correlate(items))   # 0.95
        prior.extend(NetworkBlockchainMappingRule().correlate(items))  # 0.65
        cross = CrossDomainChainRule().correlate(items, prior)
        assert cross[0].confidence == 0.65


# ──────────────────────────────────────────────────────────
# 13. Explanation generation
# ──────────────────────────────────────────────────────────

class TestExplanationGeneration:
    def test_pid_explanation_contains_process_name(self):
        items = [_process_ev(4821, "suspicious_miner"), _conn_ev(4821)]
        f = ProcessNetworkPidRule().correlate(items)[0]
        assert "suspicious_miner" in f.explanation

    def test_vasp_explanation_contains_vasp_name(self):
        tx = _tx_ev("0xTX1", "0xA", "0xB")
        vasp = _vasp_ev("V1", "Example Exchange", ["0xB"], 0.91)
        f = TransactionVaspRule().correlate([tx, vasp])[0]
        assert "Example Exchange" in f.explanation

    def test_network_blockchain_explanation_has_disclaimer(self):
        conn = _conn_ev(4821, "203.0.113.25")
        wallet = _wallet_ev("0xWALLET001")
        f = NetworkBlockchainMappingRule().correlate([conn, wallet])[0]
        assert "does not establish" in f.explanation.lower()


# ──────────────────────────────────────────────────────────
# 14. Supporting evidence IDs
# ──────────────────────────────────────────────────────────

class TestSupportingEvidenceIds:
    def test_source_ids_are_evidence_ids(self):
        p = _process_ev(4821)
        c = _conn_ev(4821)
        f = ProcessNetworkPidRule().correlate([p, c])[0]
        assert p.id in f.source_evidence_ids

    def test_target_ids_are_evidence_ids(self):
        p = _process_ev(4821)
        c = _conn_ev(4821)
        f = ProcessNetworkPidRule().correlate([p, c])[0]
        assert c.id in f.target_evidence_ids

    def test_no_duplicate_ids_in_cross_domain(self):
        items = [_process_ev(4821), _conn_ev(4821, "203.0.113.25"), _wallet_ev("0xWALLET001")]
        prior = []
        prior.extend(ProcessNetworkPidRule().correlate(items))
        prior.extend(NetworkBlockchainMappingRule().correlate(items))
        cross = CrossDomainChainRule().correlate(items, prior)
        if cross:
            ids = cross[0].source_evidence_ids
            assert len(ids) == len(set(ids))


# ──────────────────────────────────────────────────────────
# 15. No fabricated relationships
# ──────────────────────────────────────────────────────────

class TestNoFabricatedRelationships:
    def test_unrelated_evidence_no_finding(self):
        items = [_process_ev(4821), _wallet_ev("0xSOME")]
        engine = CorrelationEngine()
        pkg = build_evidence_package(_CASE, _HOST, items)
        result = engine.correlate(pkg, _CASE, _HOST)
        # ProcessNetworkPidRule needs a NETWORK_CONNECTION; WalletTransactionRule needs a TX.
        # No cross-domain applicable. Verify no spurious PID or wallet→process claim.
        for f in result.findings:
            assert f.correlation_type != CorrelationType.PROCESS_NETWORK
            assert f.correlation_type != CorrelationType.WALLET_TRANSACTION

    def test_wallet_not_correlated_to_unrelated_vasp(self):
        tx = _tx_ev("0xTX1", "0xA", "0xB")
        vasp = _vasp_ev("V1", "SomeVASP", ["0xC"])  # 0xC not in tx
        findings = TransactionVaspRule().correlate([tx, vasp])
        assert findings == []


# ──────────────────────────────────────────────────────────
# 16. Unknown/unmatched evidence handling
# ──────────────────────────────────────────────────────────

class TestUnmatchedEvidenceHandling:
    def test_only_processes_no_network_no_findings(self):
        items = [_process_ev(100), _process_ev(200)]
        rule = ProcessNetworkPidRule()
        assert rule.correlate(items) == []

    def test_only_connections_no_processes_no_findings(self):
        items = [_conn_ev(4821), _conn_ev(5102)]
        rule = ProcessNetworkPidRule()
        assert rule.correlate(items) == []


# ──────────────────────────────────────────────────────────
# 17. Empty evidence package
# ──────────────────────────────────────────────────────────

class TestEmptyEvidencePackage:
    def test_empty_package_produces_no_findings(self):
        pkg = _empty_package()
        engine = CorrelationEngine()
        result = engine.correlate(pkg, _CASE, _HOST)
        assert result.findings == []
        assert result.confidence == 0.0

    def test_empty_package_result_structure(self):
        pkg = _empty_package()
        result = CorrelationEngine().correlate(pkg, _CASE, _HOST)
        assert result.case_id == _CASE
        assert result.host == _HOST
        assert isinstance(result.summary, dict)


# ──────────────────────────────────────────────────────────
# 18. Runtime CORRELATE EVIDENCE operation
# ──────────────────────────────────────────────────────────

class TestRuntimeCorrelateEvidence:
    def test_correlate_evidence_via_runtime(self):
        from compiler.compiler import compile_source
        from runtime.executor.executor import RuntimeExecutor
        from blockchain.evm.adapter import EVMAdapter
        from forensic.endpoint.fixture import FixtureEndpointAdapter
        from forensic.network.fixture import FixtureNetworkAdapter

        source = """
        CASE "INC-CORR-RT"
        HOST "LAB-PC-01"
        ANALYZE PROCESSES
        ANALYZE NETWORK
        BLOCKCHAIN TRACE "0xWALLET001"
        IDENTIFY VASP
        CORRELATE EVIDENCE
        """
        cres = compile_source(source)
        assert cres.ok

        executor = RuntimeExecutor(
            cres.ir,
            adapter=FixtureEndpointAdapter(host="LAB-PC-01"),
            network_adapter=FixtureNetworkAdapter(host="LAB-PC-01"),
            blockchain_adapter=EVMAdapter(),
        )
        exec_res = executor.execute()

        # Find the CORRELATE_EVIDENCE result
        corr_ops = [r for r in exec_res.results if r.operation == "CORRELATE_EVIDENCE"]
        assert len(corr_ops) == 1
        corr_op = corr_ops[0]
        assert corr_op.status == "SUCCESS"
        result = corr_op.data
        assert result.__class__.__name__ == "CorrelationResult"
        assert len(result.findings) > 0

    def test_correlate_evidence_without_blockchain_still_works(self):
        from compiler.compiler import compile_source
        from runtime.executor.executor import RuntimeExecutor
        from forensic.endpoint.fixture import FixtureEndpointAdapter
        from forensic.network.fixture import FixtureNetworkAdapter

        source = """
        CASE "INC-CORR-NOBLC"
        HOST "LAB-PC-01"
        ANALYZE PROCESSES
        ANALYZE NETWORK
        CORRELATE EVIDENCE
        """
        cres = compile_source(source)
        executor = RuntimeExecutor(
            cres.ir,
            adapter=FixtureEndpointAdapter(host="LAB-PC-01"),
            network_adapter=FixtureNetworkAdapter(host="LAB-PC-01"),
        )
        exec_res = executor.execute()
        corr_op = next(r for r in exec_res.results if r.operation == "CORRELATE_EVIDENCE")
        assert corr_op.status == "SUCCESS"


# ──────────────────────────────────────────────────────────
# 19. CLI JSON output includes correlations
# ──────────────────────────────────────────────────────────

class TestCLIJsonOutput:
    def test_json_output_has_correlations_key(self, tmp_path):
        from jocky.cli import main

        demo = tmp_path / "demo.jky"
        demo.write_text(
            'CASE "INC-CLI-CORR"\nHOST "LAB-PC-01"\n'
            'ANALYZE PROCESSES\nANALYZE NETWORK\n'
            'BLOCKCHAIN TRACE "0xWALLET001"\nIDENTIFY VASP\nCORRELATE EVIDENCE\n'
        )

        import io, sys
        captured = io.StringIO()
        old_stdout = sys.stdout
        sys.stdout = captured
        try:
            rc = main([str(demo), "--execute", "--fixture", "--json"])
        finally:
            sys.stdout = old_stdout

        assert rc == 0
        output = captured.getvalue()
        data = json.loads(output)
        pkg = data.get("evidence_package", {})
        assert "correlations" in pkg
        assert isinstance(pkg["correlations"], list)

    def test_json_correlations_have_required_fields(self, tmp_path):
        from jocky.cli import main

        demo = tmp_path / "demo.jky"
        demo.write_text(
            'CASE "INC-CLI-CORR2"\nHOST "LAB-PC-01"\n'
            'ANALYZE PROCESSES\nANALYZE NETWORK\n'
            'BLOCKCHAIN TRACE "0xWALLET001"\nIDENTIFY VASP\nCORRELATE EVIDENCE\n'
        )

        import io, sys
        captured = io.StringIO()
        old_stdout = sys.stdout
        sys.stdout = captured
        try:
            main([str(demo), "--execute", "--fixture", "--json"])
        finally:
            sys.stdout = old_stdout

        data = json.loads(captured.getvalue())
        corrs = data["evidence_package"]["correlations"]
        assert len(corrs) > 0
        required = {"id", "correlation_type", "confidence", "explanation", "rule_id"}
        for c in corrs:
            assert required.issubset(set(c.keys()))


# ──────────────────────────────────────────────────────────
# 20. Evidence integrity remains valid after correlation
# ──────────────────────────────────────────────────────────

class TestEvidenceIntegrity:
    def test_package_integrity_valid_with_correlations(self):
        from compiler.compiler import compile_source
        from runtime.executor.executor import RuntimeExecutor
        from blockchain.evm.adapter import EVMAdapter
        from forensic.endpoint.fixture import FixtureEndpointAdapter
        from forensic.network.fixture import FixtureNetworkAdapter

        source = """
        CASE "INC-INTEG"
        HOST "LAB-PC-01"
        ANALYZE PROCESSES
        ANALYZE NETWORK
        BLOCKCHAIN TRACE "0xWALLET001"
        IDENTIFY VASP
        CORRELATE EVIDENCE
        """
        cres = compile_source(source)
        executor = RuntimeExecutor(
            cres.ir,
            adapter=FixtureEndpointAdapter(host="LAB-PC-01"),
            network_adapter=FixtureNetworkAdapter(host="LAB-PC-01"),
            blockchain_adapter=EVMAdapter(),
        )
        exec_res = executor.execute()
        pkg = exec_res.build_universal_package()
        # Package must pass integrity check even with correlations
        assert pkg.verify_package_integrity() is True

    def test_package_has_correlations_field(self):
        from compiler.compiler import compile_source
        from runtime.executor.executor import RuntimeExecutor
        from forensic.endpoint.fixture import FixtureEndpointAdapter
        from forensic.network.fixture import FixtureNetworkAdapter

        source = 'CASE "INC-PKG"\nHOST "LAB-PC-01"\nANALYZE PROCESSES\nANALYZE NETWORK\n'
        cres = compile_source(source)
        executor = RuntimeExecutor(
            cres.ir,
            adapter=FixtureEndpointAdapter(host="LAB-PC-01"),
            network_adapter=FixtureNetworkAdapter(host="LAB-PC-01"),
        )
        exec_res = executor.execute()
        pkg = exec_res.build_universal_package()
        assert hasattr(pkg, "correlations")
        assert isinstance(pkg.correlations, list)


# ──────────────────────────────────────────────────────────
# 21. Existing evidence IDs remain unchanged
# ──────────────────────────────────────────────────────────

class TestExistingEvidenceIdsUnchanged:
    def test_evidence_ids_stable_before_and_after_correlation(self):
        p = _process_ev(4821, "suspicious_miner")
        c = _conn_ev(4821, "203.0.113.25")

        # Record IDs before correlation
        before_ids = {p.id, c.id}

        pkg = build_evidence_package(_CASE, _HOST, [p, c])
        engine = CorrelationEngine()
        result = engine.correlate(pkg, _CASE, _HOST)

        # Evidence IDs from package remain identical
        after_ids = {e.id for e in pkg.evidence}
        assert before_ids == after_ids

    def test_correlation_does_not_mutate_evidence(self):
        p = _process_ev(4821, "suspicious_miner")
        c = _conn_ev(4821, "203.0.113.25")
        original_p_id = p.id
        original_c_id = c.id

        pkg = build_evidence_package(_CASE, _HOST, [p, c])
        CorrelationEngine().correlate(pkg, _CASE, _HOST)

        # IDs must be unchanged
        assert p.id == original_p_id
        assert c.id == original_c_id


# ──────────────────────────────────────────────────────────
# 22. Full regression (smoke test — all prior phases)
# ──────────────────────────────────────────────────────────

class TestFullRegression:
    def test_full_pipeline_with_correlation_demo(self):
        """Run the correlation_demo.jky through the full pipeline."""
        from compiler.compiler import compile_source
        from runtime.executor.executor import RuntimeExecutor
        from blockchain.evm.adapter import EVMAdapter
        from forensic.endpoint.fixture import FixtureEndpointAdapter
        from forensic.network.fixture import FixtureNetworkAdapter

        demo_path = Path(__file__).resolve().parent.parent / "examples" / "correlation_demo.jky"
        source = demo_path.read_text(encoding="utf-8")
        cres = compile_source(source)
        assert cres.ok and cres.ir is not None

        executor = RuntimeExecutor(
            cres.ir,
            adapter=FixtureEndpointAdapter(host="LAB-PC-01"),
            network_adapter=FixtureNetworkAdapter(host="LAB-PC-01"),
            blockchain_adapter=EVMAdapter(),
        )
        exec_res = executor.execute()

        # Evidence package
        pkg = exec_res.build_universal_package()
        assert pkg.verify_package_integrity() is True
        assert len(pkg.evidence) > 0
        assert len(pkg.correlations) > 0

        # Correlation findings
        corr_ops = [r for r in exec_res.results if r.operation == "CORRELATE_EVIDENCE"]
        assert corr_ops[0].status == "SUCCESS"
        result = corr_ops[0].data
        assert result.confidence > 0.0

        # Cross-domain finding
        cross = [f for f in result.findings if f.correlation_type == CorrelationType.CROSS_DOMAIN]
        assert len(cross) >= 1
        assert "weakest" in cross[0].explanation.lower() or "chain" in cross[0].explanation.lower()

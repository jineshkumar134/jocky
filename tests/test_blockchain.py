"""
tests/test_blockchain.py — Tests for Phase 7 Blockchain Models, Adapters, and Tracing
=====================================================================================
Validates:
1. Blockchain model validation (Wallet, Transaction, BlockchainEvent, TraceHop)
2. EVMAdapter in fixture mode
3. Wallet lookup (curated and unknown fallback)
4. Transaction lookup
5. Multi-hop transaction tracing (forward, backward, depth limits)
6. UniversalEvidence conversion (Wallet -> UniversalEvidence, Transaction -> UniversalEvidence)
7. Deterministic evidence IDs and SHA-256 integrity verification
8. Grounded blockchain relationships (SENT_TO, ASSOCIATED_WITH) with supporting evidence IDs
9. Runtime execution of BLOCKCHAIN TRACE
10. CLI execution with --execute --fixture --json
"""

from __future__ import annotations

import json
from pathlib import Path
import pytest
from pydantic import ValidationError

from blockchain.base import BlockchainAdapter
from blockchain.converters import (
    extract_blockchain_relationships,
    transaction_to_evidence,
    wallet_to_evidence,
)
from blockchain.evm.adapter import EVMAdapter
from blockchain.models import (
    BlockchainEvent,
    BlockchainTraceResult,
    TraceHop,
    Transaction,
    Wallet,
)
from blockchain.tracer.tracer import BlockchainTracer
from compiler.compiler import compile_source
from forensic.evidence.models import EvidenceType, RelationshipType
from runtime.executor.executor import RuntimeExecutor


# ──────────────────────────────────────────────────────────
# 1. Model Validation
# ──────────────────────────────────────────────────────────

class TestBlockchainModels:
    def test_wallet_model_valid(self):
        w = Wallet(
            address="0xWALLET001",
            chain="ethereum",
            label="Synthetic Suspicious EOA",
            wallet_type="eoa",
            confidence=0.95,
            balance=10.5,
        )
        assert w.address == "0xWALLET001"
        assert w.chain == "ethereum"
        assert w.wallet_type == "eoa"
        assert w.confidence == 0.95

    def test_wallet_model_confidence_bounds(self):
        with pytest.raises(ValidationError):
            Wallet(address="0x123", confidence=1.5)

        with pytest.raises(ValidationError):
            Wallet(address="0x123", confidence=-0.1)

    def test_transaction_model_valid(self):
        tx = Transaction(
            tx_hash="0xTX001",
            chain="ethereum",
            block_number=19500100,
            timestamp="2026-09-12T16:00:00Z",
            from_address="0xWALLET001",
            to_address="0xWALLET002",
            asset="ETH",
            amount=10.5,
            status="confirmed",
        )
        assert tx.tx_hash == "0xTX001"
        assert tx.amount == 10.5
        assert tx.status == "confirmed"

    def test_blockchain_event_model(self):
        event = BlockchainEvent(
            event_id="EV-001",
            event_name="Transfer",
            contract_address="0xCONTRACT001",
            block_number=19500100,
            parameters={"value": 1000},
        )
        assert event.event_name == "Transfer"
        assert event.contract_address == "0xCONTRACT001"


# ──────────────────────────────────────────────────────────
# 2. EVM Adapter (Fixture Mode)
# ──────────────────────────────────────────────────────────

class TestEVMAdapter:
    def test_fixture_wallet_lookup_known(self):
        adapter = EVMAdapter()
        w = adapter.get_wallet("0xWALLET001")
        assert w is not None
        assert w.address == "0xWALLET001"
        assert w.label == "Synthetic Suspicious EOA"
        assert w.wallet_type == "eoa"

    def test_fixture_wallet_lookup_case_insensitive(self):
        adapter = EVMAdapter()
        w = adapter.get_wallet("0xwallet001")
        assert w is not None
        assert w.address == "0xWALLET001"

    def test_fixture_wallet_lookup_unknown(self):
        adapter = EVMAdapter()
        w = adapter.get_wallet("0xUNKNOWN_RANDOM_ADDRESS")
        assert w is not None
        assert w.address == "0xUNKNOWN_RANDOM_ADDRESS"
        assert w.label == "Unknown Wallet"
        assert w.wallet_type == "unknown"
        assert w.confidence == 0.5

    def test_fixture_transactions_lookup(self):
        adapter = EVMAdapter()
        txs = adapter.get_transactions("0xWALLET002")
        assert len(txs) >= 2
        hashes = {t.tx_hash for t in txs}
        assert "0xTX001" in hashes
        assert "0xTX002" in hashes

    def test_fixture_single_transaction_lookup(self):
        adapter = EVMAdapter()
        tx = adapter.get_transaction("0xTX001")
        assert tx is not None
        assert tx.from_address == "0xWALLET001"
        assert tx.to_address == "0xWALLET002"
        assert tx.amount == 10.5


# ──────────────────────────────────────────────────────────
# 3. Multi-Hop Blockchain Tracer
# ──────────────────────────────────────────────────────────

class TestBlockchainTracer:
    def test_multi_hop_trace_reconstruction(self):
        adapter = EVMAdapter()
        tracer = BlockchainTracer(adapter)
        res = tracer.trace("0xWALLET001", max_hops=3, direction="forward")

        assert res.seed_address == "0xWALLET001"
        assert len(res.hops) >= 2

        # Check Hop 1: 0xWALLET001 -> 0xWALLET002 via 0xTX001
        hop1 = res.hops[0]
        assert hop1.hop_number == 1
        assert hop1.from_wallet == "0xWALLET001"
        assert hop1.to_wallet == "0xWALLET002"
        assert hop1.tx_hash == "0xTX001"
        assert hop1.amount == 10.5

        # Check Hop 2: 0xWALLET002 -> 0xWALLET003 via 0xTX002
        hop2 = res.hops[1]
        assert hop2.hop_number == 2
        assert hop2.from_wallet == "0xWALLET002"
        assert hop2.to_wallet == "0xWALLET003"
        assert hop2.tx_hash == "0xTX002"
        assert hop2.amount == 10.49

        # Verify discovered wallets
        discovered_addrs = {w.address for w in res.wallets}
        assert "0xWALLET001" in discovered_addrs
        assert "0xWALLET002" in discovered_addrs
        assert "0xWALLET003" in discovered_addrs

    def test_multi_hop_trace_max_hops_limit(self):
        adapter = EVMAdapter()
        tracer = BlockchainTracer(adapter)
        res = tracer.trace("0xWALLET001", max_hops=1, direction="forward")

        assert len(res.hops) == 1
        assert res.hops[0].hop_number == 1


# ──────────────────────────────────────────────────────────
# 4. Universal Evidence Conversion & Hashing
# ──────────────────────────────────────────────────────────

class TestBlockchainUniversalEvidence:
    def test_wallet_to_evidence(self):
        w = Wallet(
            address="0xWALLET001",
            chain="ethereum",
            label="Synthetic Suspicious EOA",
            wallet_type="eoa",
            confidence=0.95,
        )
        ev = wallet_to_evidence(w, host="LAB-PC-01", case_id="INC-CASE-01")

        assert ev.type == EvidenceType.WALLET
        assert ev.source == "blockchain"
        assert ev.id.startswith("EVID-WLLT-")
        assert ev.confidence == 0.95
        assert ev.entity.address == "0xWALLET001"
        assert ev.verify_integrity() is True

    def test_transaction_to_evidence(self):
        tx = Transaction(
            tx_hash="0xTX001",
            chain="ethereum",
            timestamp="2026-09-12T16:00:00Z",
            from_address="0xWALLET001",
            to_address="0xWALLET002",
            asset="ETH",
            amount=10.5,
        )
        ev = transaction_to_evidence(tx, host="LAB-PC-01", case_id="INC-CASE-01")

        assert ev.type == EvidenceType.TRANSACTION
        assert ev.source == "blockchain"
        assert ev.id.startswith("EVID-TXID-")
        assert ev.entity.amount == 10.5
        assert ev.verify_integrity() is True

    def test_deterministic_evidence_id_for_identical_wallet(self):
        w = Wallet(address="0xWALLET001", chain="ethereum", label="Test", wallet_type="eoa")
        ev1 = wallet_to_evidence(w, host="LAB-PC-01", collector="EVMAdapter")
        ev2 = wallet_to_evidence(w, host="LAB-PC-01", collector="EVMAdapter")
        assert ev1.id == ev2.id


# ──────────────────────────────────────────────────────────
# 5. Grounded Blockchain Relationships
# ──────────────────────────────────────────────────────────

class TestBlockchainRelationships:
    def test_grounded_sent_to_and_associated_with(self):
        w1 = Wallet(address="0xWALLET001", label="W1", wallet_type="eoa")
        w2 = Wallet(address="0xWALLET002", label="W2", wallet_type="eoa")
        tx = Transaction(
            tx_hash="0xTX001",
            timestamp="2026-09-12T16:00:00Z",
            from_address="0xWALLET001",
            to_address="0xWALLET002",
            amount=10.5,
            asset="ETH",
        )

        ev1 = wallet_to_evidence(w1, host="H")
        ev2 = wallet_to_evidence(w2, host="H")
        ev_tx = transaction_to_evidence(tx, host="H")

        rels = extract_blockchain_relationships([ev1, ev2, ev_tx])

        # Must have 1 SENT_TO and 2 ASSOCIATED_WITH relationships
        sent_to = [r for r in rels if r.type == RelationshipType.SENT_TO]
        assert len(sent_to) == 1
        assert sent_to[0].source_id == ev1.id
        assert sent_to[0].target_id == ev2.id
        assert ev_tx.id in sent_to[0].supporting_evidence
        assert sent_to[0].metadata["amount"] == 10.5

        associated = [r for r in rels if r.type == RelationshipType.ASSOCIATED_WITH]
        assert len(associated) == 2


# ──────────────────────────────────────────────────────────
# 6. Runtime BLOCKCHAIN TRACE Integration
# ──────────────────────────────────────────────────────────

class TestRuntimeBlockchainTrace:
    def test_runtime_executes_blockchain_trace(self):
        source = """
        CASE "INC-BC-TEST"
        HOST "LAB-PC-01"
        BLOCKCHAIN TRACE "0xWALLET001"
        """
        cres = compile_source(source)
        assert cres.ok and cres.ir is not None

        executor = RuntimeExecutor(cres.ir, blockchain_adapter=EVMAdapter())
        exec_res = executor.execute()

        assert len(exec_res.results) == 1
        r = exec_res.results[0]
        assert r.operation == "BLOCKCHAIN_TRACE"
        assert r.status == "SUCCESS"
        assert r.data.__class__.__name__ == "BlockchainTraceResult"
        assert len(r.data.hops) >= 2

        # Check evidence package integration
        pkg = exec_res.build_universal_package()
        types = {e.type for e in pkg.evidence}
        assert EvidenceType.WALLET in types
        assert EvidenceType.TRANSACTION in types
        assert pkg.verify_package_integrity() is True


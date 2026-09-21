"""
tests/test_vasp.py — Tests for Phase 7 Explainable VASP Attribution Engine
========================================================================
Validates:
1. VASP profile loading from fixtures
2. Strict additive scoring model:
     direct_label_match (0.45)
   + wallet_type_match  (0.30)
   + address_cluster    (0.20)
   + base_confidence    (0.05)
   = Max 1.00 (bounded within [0.0, 1.0])
3. Detailed explainability reasons
4. Unknown wallet handling
5. UniversalEvidence conversion & integrity
6. Grounded WALLET -> ATTRIBUTED_TO -> VASP relationship
7. Runtime execution of IDENTIFY VASP
8. CLI execution of examples/blockchain_demo.jky
"""

from __future__ import annotations

import json
from pathlib import Path
import pytest

from blockchain.converters import (
    extract_blockchain_relationships,
    vasp_attribution_to_evidence,
    wallet_to_evidence,
)
from blockchain.evm.adapter import EVMAdapter
from blockchain.models import (
    Transaction,
    VASPAttributionResult,
    VASPResult,
    Wallet,
)
from blockchain.vasp.attribution import (
    SCORE_ADDRESS_CLUSTER_MATCH,
    SCORE_BASE_CONFIDENCE,
    SCORE_DIRECT_LABEL_MATCH,
    SCORE_WALLET_TYPE_MATCH,
    VASPAttributionEngine,
)
from compiler.compiler import compile_source
from forensic.evidence.models import EvidenceType, RelationshipType
from runtime.executor.executor import RuntimeExecutor


# ──────────────────────────────────────────────────────────
# 1. Scoring Formula & Breakdown Verification
# ──────────────────────────────────────────────────────────

class TestVASPAttributionScoring:
    def test_additive_scoring_formula_constants(self):
        assert SCORE_DIRECT_LABEL_MATCH == 0.45
        assert SCORE_WALLET_TYPE_MATCH == 0.30
        assert SCORE_ADDRESS_CLUSTER_MATCH == 0.20
        assert SCORE_BASE_CONFIDENCE == 0.05
        assert round(
            SCORE_DIRECT_LABEL_MATCH + SCORE_WALLET_TYPE_MATCH + SCORE_ADDRESS_CLUSTER_MATCH + SCORE_BASE_CONFIDENCE, 2
        ) == 1.00

    def test_full_match_achieves_1_0_score(self):
        engine = VASPAttributionEngine()
        # Wallet 0xWALLET003 has label "Example Exchange Deposit", type "exchange_deposit", and is in VASP-EXCHANGE-01 pattern
        w = Wallet(
            address="0xWALLET003",
            label="Example Exchange Deposit",
            wallet_type="exchange_deposit",
        )
        res = engine.attribute(wallets=[w])
        assert len(res.attributions) > 0
        top = res.attributions[0]
        assert top.vasp_id == "VASP-EXCHANGE-01"
        assert top.score == 1.00
        assert top.confidence == 1.00

        # Verify breakdown
        bd = top.scoring_breakdown
        assert bd["direct_label_match"] == 0.45
        assert bd["wallet_type_match"] == 0.30
        assert bd["address_cluster_match"] == 0.20
        assert bd["base_confidence"] == 0.05

        # Verify explainable reasons
        assert len(top.reasons) >= 4
        assert any("+0.45" in r for r in top.reasons)
        assert any("+0.3" in r for r in top.reasons)
        assert any("+0.2" in r for r in top.reasons)
        assert any("+0.05" in r for r in top.reasons)

    def test_partial_match_score_bounded(self):
        engine = VASPAttributionEngine()
        # Only wallet_type match, no direct label or cluster match
        w = Wallet(
            address="0xSOME_RANDOM_ADDR",
            label="Random Node",
            wallet_type="exchange_deposit",
        )
        res = engine.attribute(wallets=[w])
        assert len(res.attributions) > 0
        top = res.attributions[0]
        expected_score = round(SCORE_WALLET_TYPE_MATCH + SCORE_BASE_CONFIDENCE, 2)
        assert top.score == expected_score
        assert 0.0 <= top.score <= 1.0

    def test_unknown_wallet_produces_no_false_attribution(self):
        engine = VASPAttributionEngine()
        w = Wallet(
            address="0xSAFE_INDIVIDUAL_EOA",
            label="Personal Wallet",
            wallet_type="eoa",
        )
        res = engine.attribute(wallets=[w])
        assert len(res.attributions) == 0
        assert res.summary["candidate_count"] == 0


# ──────────────────────────────────────────────────────────
# 2. Universal Evidence Conversion & Grounded Relationships
# ──────────────────────────────────────────────────────────

class TestVASPEvidenceIntegration:
    def test_vasp_attribution_to_evidence(self):
        attr = VASPAttributionResult(
            vasp_id="VASP-EXCHANGE-01",
            name="Example Exchange",
            score=1.00,
            confidence=1.00,
            reasons=["Label matches", "Cluster matches"],
            matched_wallets=["0xWALLET003"],
            supporting_tx_hashes=["0xTX002"],
            scoring_breakdown={"direct_label_match": 0.45},
        )
        ev = vasp_attribution_to_evidence(attr, host="LAB-PC-01", case_id="INC-CASE-01")

        assert ev.type == EvidenceType.VASP
        assert ev.source == "blockchain"
        assert ev.id.startswith("EVID-VASP-")
        assert ev.confidence == 1.00
        assert ev.entity.name == "Example Exchange"
        assert ev.verify_integrity() is True

    def test_grounded_wallet_attributed_to_vasp_relationship(self):
        w = Wallet(address="0xWALLET003", label="Example Exchange Deposit", wallet_type="exchange_deposit")
        attr = VASPAttributionResult(
            vasp_id="VASP-EXCHANGE-01",
            name="Example Exchange",
            score=1.00,
            confidence=1.00,
            reasons=["Label match"],
            matched_wallets=["0xWALLET003"],
        )

        w_ev = wallet_to_evidence(w, host="H")
        vasp_ev = vasp_attribution_to_evidence(attr, host="H")

        rels = extract_blockchain_relationships([w_ev, vasp_ev])
        attr_rels = [r for r in rels if r.type == RelationshipType.ATTRIBUTED_TO]

        assert len(attr_rels) == 1
        rel = attr_rels[0]
        assert rel.source_id == w_ev.id
        assert rel.target_id == vasp_ev.id
        assert rel.metadata["vasp_name"] == "Example Exchange"
        assert w_ev.id in rel.supporting_evidence
        assert vasp_ev.id in rel.supporting_evidence


# ──────────────────────────────────────────────────────────
# 3. Runtime & CLI Integration
# ──────────────────────────────────────────────────────────

class TestRuntimeVASPIntegration:
    def test_runtime_executes_blockchain_and_vasp_pipeline(self):
        source = """
        CASE "INC-FULL-BC"
        HOST "LAB-PC-01"
        BLOCKCHAIN TRACE "0xWALLET001"
        IDENTIFY VASP
        """
        cres = compile_source(source)
        assert cres.ok and cres.ir is not None

        executor = RuntimeExecutor(cres.ir, blockchain_adapter=EVMAdapter())
        exec_res = executor.execute()

        assert len(exec_res.results) == 2
        trace_op = exec_res.results[0]
        vasp_op = exec_res.results[1]

        assert trace_op.operation == "BLOCKCHAIN_TRACE"
        assert trace_op.status == "SUCCESS"

        assert vasp_op.operation == "IDENTIFY_VASP"
        assert vasp_op.status == "SUCCESS"
        assert vasp_op.data.__class__.__name__ == "VASPResult"
        assert len(vasp_op.data.attributions) > 0

        # Check Universal Evidence Package
        pkg = exec_res.build_universal_package()
        types = {e.type for e in pkg.evidence}
        assert EvidenceType.WALLET in types
        assert EvidenceType.TRANSACTION in types
        assert EvidenceType.VASP in types

        # Check relationships
        rel_types = {r.type for r in pkg.relationships}
        assert RelationshipType.SENT_TO in rel_types
        assert RelationshipType.ATTRIBUTED_TO in rel_types
        assert pkg.verify_package_integrity() is True

    def test_cli_blockchain_demo_execution_and_json(self, capsys):
        from jocky.cli import main

        script_path = Path("examples/blockchain_demo.jky")
        exit_code = main([str(script_path), "--execute", "--fixture", "--json"])
        assert exit_code == 0

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert data["case_id"] == "INC-2026-BLOCKCHAIN"
        assert "evidence_package" in data
        assert "blockchain" in data
        assert "vasp" in data

        pkg = data["evidence_package"]
        assert len(pkg["evidence"]) >= 5
        assert len(pkg["relationships"]) >= 3
        assert pkg["package_hash"] != ""

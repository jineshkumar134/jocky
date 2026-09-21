"""
JOCKY Phase 11 — Anchoring Tests
==================================
~20 focused tests covering IPFS, EVM, Engine, and serialization.
"""

import pytest
from forensic.evidence.models import (
    EvidencePackage,
    UniversalEvidence,
    Relationship,
    RelationshipType,
    EvidenceType,
    EvidenceProvenance,
    EvidenceIntegrity,
)
from forensic.evidence.canonical import canonical_json
from anchoring.models import EvidenceAnchor, AnchorRecord, VerificationResult
from anchoring.evidence import (
    serialize_evidence_package,
    compute_package_hash_from_bytes,
    verify_package_bytes_hash,
)
from anchoring.ipfs.mock import MockIPFSAdapter
from anchoring.evm.mock import MockEVMAdapter
from anchoring.engine import EvidenceAnchorEngine


def _make_prov(case_id="TEST", host="host1"):
    return EvidenceProvenance(
        collector="test_collector",
        adapter="test_adapter",
        source="memory",
        collection_method="test_method",
        collected_at="2023-10-27T10:00:00Z",
        host=host,
        case_id=case_id,
    )


def _make_evidence(ev_id="EVID-P11-001", pid=1234):
    return UniversalEvidence(
        id=ev_id,
        type=EvidenceType.PROCESS,
        source="memory",
        timestamp="2023-10-27T10:00:00Z",
        entity={"pid": pid, "name": "test.exe"},
        provenance=_make_prov(),
        integrity=EvidenceIntegrity(algorithm="SHA-256", value="placeholder"),
    )


def _make_rel(rel_id="REL-P11-001", src="EVID-P11-001", tgt="EVID-P11-002"):
    return Relationship(
        id=rel_id,
        type=RelationshipType.SPAWNED,
        source_id=src,
        target_id=tgt,
        confidence=0.9,
    )


def _make_package(case_id="TEST", host="host1"):
    ev = _make_evidence()
    rel = _make_rel()
    pkg = EvidencePackage(
        case_id=case_id,
        host=host,
        created_at="2023-10-27T10:00:00Z",
        evidence=[ev],
        relationships=[rel],
        correlations=[],
        graph=None,
    )
    pkg = pkg.model_copy(update={"package_hash": pkg.compute_package_hash()})
    return pkg


@pytest.fixture
def sample_package():
    return _make_package()


# ──────────────────────────────────────────────────────────
# 1. Serialization
# ──────────────────────────────────────────────────────────

class TestEvidenceSerialization:
    def test_01_serialization_is_deterministic(self, sample_package):
        bytes1 = serialize_evidence_package(sample_package)
        bytes2 = serialize_evidence_package(sample_package)
        assert bytes1 == bytes2

    def test_02_serialization_hashes_to_package_hash(self, sample_package):
        raw_bytes = serialize_evidence_package(sample_package)
        computed_hash = compute_package_hash_from_bytes(raw_bytes)
        assert computed_hash == sample_package.package_hash
        assert verify_package_bytes_hash(raw_bytes, sample_package.package_hash)

    def test_03_serialization_excludes_graph_field(self, sample_package):
        raw_bytes = serialize_evidence_package(sample_package)
        # 'graph' should be excluded from the canonical representation
        assert b'"graph"' not in raw_bytes

    def test_04_different_packages_produce_different_hashes(self):
        pkg1 = _make_package(case_id="CASE-A")
        pkg2 = _make_package(case_id="CASE-B")
        assert pkg1.package_hash != pkg2.package_hash
        b1 = serialize_evidence_package(pkg1)
        b2 = serialize_evidence_package(pkg2)
        assert b1 != b2

# ──────────────────────────────────────────────────────────
# 2. Mock IPFS
# ──────────────────────────────────────────────────────────

class TestMockIPFS:
    def test_05_ipfs_add_and_retrieve(self):
        ipfs = MockIPFSAdapter()
        content = b"hello forensic world"
        cid = ipfs.add_bytes(content)
        assert cid.startswith("bafk")
        retrieved = ipfs.cat_bytes(cid)
        assert retrieved == content

    def test_06_ipfs_missing_cid_raises(self):
        ipfs = MockIPFSAdapter()
        with pytest.raises(ValueError):
            ipfs.cat_bytes("bafk-does-not-exist")

    def test_07_ipfs_cid_is_deterministic(self):
        ipfs = MockIPFSAdapter()
        cid1 = ipfs.add_bytes(b"same-content")
        cid2 = ipfs.add_bytes(b"same-content")
        assert cid1 == cid2

    def test_08_ipfs_different_content_yields_different_cid(self):
        ipfs = MockIPFSAdapter()
        cid1 = ipfs.add_bytes(b"content-alpha")
        cid2 = ipfs.add_bytes(b"content-beta")
        assert cid1 != cid2

    def test_09_ipfs_pin_success_and_failure(self):
        ipfs = MockIPFSAdapter()
        cid = ipfs.add_bytes(b"pin-me")
        assert ipfs.pin(cid) is True
        assert ipfs.pin("bafk-not-there") is False


# ──────────────────────────────────────────────────────────
# 3. Mock EVM
# ──────────────────────────────────────────────────────────

class TestMockEVM:
    def test_10_evm_anchor_creates_record(self):
        evm = MockEVMAdapter(chain_id=31337)
        record = evm.anchor_hash("pkg_hash_abc", "bafkcid123")
        assert record.package_hash == "pkg_hash_abc"
        assert record.ipfs_cid == "bafkcid123"
        assert record.chain_id == 31337
        assert record.tx_hash.startswith("0x")
        assert record.block_number >= 1000001

    def test_11_evm_anchor_is_idempotent(self):
        evm = MockEVMAdapter()
        r1 = evm.anchor_hash("idempotent_hash", "cid_idem")
        r2 = evm.anchor_hash("idempotent_hash", "cid_idem")
        assert r1.tx_hash == r2.tx_hash
        assert r1.block_number == r2.block_number

    def test_12_evm_verify_anchor_found(self):
        evm = MockEVMAdapter()
        evm.anchor_hash("verify_hash", "cid_ver")
        assert evm.verify_anchor("verify_hash") is True
        assert evm.verify_anchor("verify_hash", "cid_ver") is True

    def test_13_evm_verify_wrong_cid_fails(self):
        evm = MockEVMAdapter()
        evm.anchor_hash("real_hash", "real_cid")
        assert evm.verify_anchor("real_hash", "wrong_cid") is False

    def test_14_evm_verify_missing_hash_fails(self):
        evm = MockEVMAdapter()
        assert evm.verify_anchor("not_anchored") is False

    def test_15_evm_get_anchor_record(self):
        evm = MockEVMAdapter()
        record = evm.anchor_hash("h1", "c1")
        fetched = evm.get_anchor_record("h1")
        assert fetched == record
        assert evm.get_anchor_record("missing") is None


# ──────────────────────────────────────────────────────────
# 4. Engine Integration
# ──────────────────────────────────────────────────────────

class TestEvidenceAnchorEngine:
    def test_16_engine_anchor_produces_valid_anchor(self, sample_package):
        engine = EvidenceAnchorEngine()
        anchor = engine.anchor(sample_package, metadata={"phase": "11"})

        assert isinstance(anchor, EvidenceAnchor)
        assert anchor.package_hash == sample_package.package_hash
        assert anchor.ipfs_cid.startswith("bafk")
        assert anchor.tx_hash.startswith("0x")
        assert anchor.chain_id == 31337
        assert anchor.metadata == {"phase": "11"}

    def test_17_engine_verify_success_with_anchor(self, sample_package):
        engine = EvidenceAnchorEngine()
        anchor = engine.anchor(sample_package)
        result = engine.verify(sample_package, anchor)

        assert result.is_valid is True
        assert result.package_hash_match is True
        assert result.ipfs_match is True
        assert result.evm_match is True
        assert result.errors == []

    def test_18_engine_verify_success_without_anchor_arg(self, sample_package):
        """verify() with no anchor arg should still work if package was previously anchored."""
        engine = EvidenceAnchorEngine()
        engine.anchor(sample_package)
        result = engine.verify(sample_package)

        assert result.is_valid is True
        assert result.ipfs_match is True
        assert result.evm_match is True

    def test_19_engine_verify_fails_when_never_anchored(self, sample_package):
        """verify() should fail clearly when package was never anchored."""
        engine = EvidenceAnchorEngine()
        result = engine.verify(sample_package)

        assert result.is_valid is False
        assert result.evm_match is False
        assert any("No EVM anchor found" in e for e in result.errors)

    def test_20_engine_verify_detects_evm_record_mismatch(self, sample_package):
        """If an anchor's tx_hash/cid doesn't match what's on-chain, verification fails."""
        engine = EvidenceAnchorEngine()
        real_anchor = engine.anchor(sample_package)

        # Fabricate a tampered anchor object
        bad_anchor = EvidenceAnchor(
            package_hash=real_anchor.package_hash,
            ipfs_cid="bafk-tampered-cid",
            chain_id=real_anchor.chain_id,
            tx_hash="0xdeadbeef",
            block_number=real_anchor.block_number,
            contract_address=real_anchor.contract_address,
            anchored_at=real_anchor.anchored_at,
        )
        result = engine.verify(sample_package, bad_anchor)
        assert result.is_valid is False
        assert result.evm_match is False
        assert any("EVM anchor mismatch" in e for e in result.errors)

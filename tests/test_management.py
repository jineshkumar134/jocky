"""
Unit and integration tests for Phase 13 Central Investigation Management.
"""

import json
import pytest

from compiler.compiler import compile_source
from compiler.lexer.lexer import Lexer, TokenType
from compiler.parser.parser import Parser
from compiler.ir.lowering import lower
from forensic.evidence.models import EvidencePackage
from forensic.evidence.canonical import canonical_hash
from forensic.endpoint.fixture import FixtureEndpointAdapter
from forensic.network.fixture import FixtureNetworkAdapter
from management.models import (
    CaseStatus,
    HostStatus,
    HostRecord,
    InvestigationCase,
    CaseSummary,
)
from management.registry import HostRegistry
from management.manager import CentralInvestigationManager, _make_host_id
from management.serialization import case_to_dict, compute_case_hash, case_summary_to_dict
from runtime.executor.executor import RuntimeExecutor


@pytest.fixture(autouse=True)
def reset_manager():
    """Ensure clean manager state before and after each test."""
    CentralInvestigationManager.reset_global()
    yield
    CentralInvestigationManager.reset_global()


# ==============================================================================
# 1. Models & Registry Tests
# ==============================================================================

def test_host_record_creation():
    rec = HostRecord(
        host_id="HOST-1234",
        hostname="TEST-PC",
        status=HostStatus.ONLINE,
        platform_info={"os": "linux"},
    )
    assert rec.host_id == "HOST-1234"
    assert rec.hostname == "TEST-PC"
    assert rec.status == HostStatus.ONLINE
    assert rec.platform_info == {"os": "linux"}


def test_host_registry_operations():
    reg = HostRegistry()
    assert len(reg) == 0

    rec1 = HostRecord(host_id="H1", hostname="HOST-A", status=HostStatus.ONLINE)
    rec2 = HostRecord(host_id="H2", hostname="HOST-B", status=HostStatus.UNKNOWN)

    reg.add(rec1)
    reg.add(rec2)

    assert len(reg) == 2
    assert "H1" in reg
    assert "H3" not in reg
    assert reg.get("H1") == rec1
    assert reg.get_by_hostname("HOST-B") == rec2
    assert reg.ids() == ["H1", "H2"]
    assert len(reg.all()) == 2


def test_case_lifecycle():
    mgr = CentralInvestigationManager()
    case = mgr.create_case("CASE-101", "Ransomware Outbreak")
    assert case.case_id == "CASE-101"
    assert case.title == "Ransomware Outbreak"
    assert case.status == CaseStatus.OPEN
    assert len(case.hosts) == 0
    assert len(case.evidence_packages) == 0

    # Test duplicate creation raises ValueError
    with pytest.raises(ValueError, match="already exists"):
        mgr.create_case("CASE-101", "Duplicate")


# ==============================================================================
# 2. Host ID Determinism & Duplicate Registration
# ==============================================================================

def test_deterministic_host_id():
    id1 = _make_host_id("LAB-PC-01", "CASE-001")
    id2 = _make_host_id("LAB-PC-01", "CASE-001")
    id3 = _make_host_id("LAB-PC-02", "CASE-001")
    assert id1 == id2
    assert id1 != id3
    assert id1.startswith("HOST-")


def test_duplicate_host_registration():
    mgr = CentralInvestigationManager()
    mgr.create_case("CASE-001", "Investigation")
    rec1 = mgr.register_host("CASE-001", "LAB-PC-01", HostStatus.ONLINE)
    rec2 = mgr.register_host("CASE-001", "LAB-PC-01", HostStatus.ONLINE)
    assert rec1.host_id == rec2.host_id
    case = mgr.get_case("CASE-001")
    assert case.hosts.count(rec1.host_id) == 1


# ==============================================================================
# 3. Evidence Package Attachment & Hash Invariance
# ==============================================================================

def test_package_hash_invariance():
    mgr = CentralInvestigationManager()
    mgr.create_case("CASE-INV", "Hash Test")

    # Construct mock EvidencePackage
    pkg = EvidencePackage(
        case_id="CASE-INV",
        host="LAB-PC-01",
        created_at="2026-09-18T00:00:00Z",
        evidence=[],
        relationships=[],
        correlations=[],
    )
    # Compute package hash
    computed_hash = pkg.compute_package_hash()
    pkg_with_hash = EvidencePackage(
        case_id="CASE-INV",
        host="LAB-PC-01",
        created_at="2026-09-18T00:00:00Z",
        evidence=[],
        relationships=[],
        correlations=[],
        package_hash=computed_hash,
    )

    initial_hash = pkg_with_hash.package_hash
    mgr.register_package(pkg_with_hash.package_hash, pkg_with_hash)
    mgr.attach_evidence("CASE-INV", "LAB-PC-01", pkg_with_hash.package_hash)

    # Verify package_hash is strictly unchanged
    assert pkg_with_hash.package_hash == initial_hash
    assert pkg_with_hash.verify_package_integrity() is True

    # Check case recorded the package
    case = mgr.get_case("CASE-INV")
    assert initial_hash in case.evidence_packages


# ==============================================================================
# 4. Deterministic Case Hash & Separation from Package Hash
# ==============================================================================

def test_deterministic_case_hash_and_separation():
    mgr = CentralInvestigationManager()
    case = mgr.create_case("CASE-HASH-TEST", "Case Hash Test")
    mgr.register_host("CASE-HASH-TEST", "HOST-A")
    mgr.register_host("CASE-HASH-TEST", "HOST-B")

    pkg_hash_dummy = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    mgr.attach_evidence("CASE-HASH-TEST", "HOST-A", pkg_hash_dummy)

    hash1 = mgr.compute_case_hash("CASE-HASH-TEST")
    hash2 = mgr.compute_case_hash("CASE-HASH-TEST")

    # Deterministic
    assert hash1 == hash2
    assert len(hash1) == 64

    # Completely separate and distinct from package hash
    assert hash1 != pkg_hash_dummy

    # Excludes mutable updated_at
    case.touch()
    hash3 = mgr.compute_case_hash("CASE-HASH-TEST")
    assert hash1 == hash3


# ==============================================================================
# 5. Compiler Integration (Lexer, Parser, AST, IR, Lowering)
# ==============================================================================

def test_compiler_lexer_and_parser():
    src = """
    CASE "CASE-LANG"
    HOST "PRIMARY-HOST"

    REGISTER HOST "SEC-HOST"
    ATTACH EVIDENCE
    """
    tokens = Lexer(src).tokenize()
    token_types = [t.type for t in tokens]
    assert TokenType.REGISTER in token_types
    assert TokenType.ATTACH in token_types

    prog = Parser(tokens).parse()
    assert len(prog.body) == 4

    reg_cmd = prog.body[2]
    att_cmd = prog.body[3]
    assert reg_cmd.__class__.__name__ == "RegisterHostCommand"
    assert reg_cmd.hostname == "SEC-HOST"
    assert att_cmd.__class__.__name__ == "AttachEvidenceCommand"


def test_compiler_ir_and_lowering():
    src = """
    CASE "CASE-IR"
    HOST "H1"
    REGISTER HOST "H2"
    ATTACH EVIDENCE
    """
    res = compile_source(src)
    assert res.ok is True
    assert res.ir is not None
    assert len(res.ir.operations) == 2
    op1 = res.ir.operations[0]
    op2 = res.ir.operations[1]
    assert op1.kind == "REGISTER_HOST"
    assert op1.hostname == "H2"
    assert op2.kind == "ATTACH_EVIDENCE"


# ==============================================================================
# 6. End-to-End Runtime & Summary Aggregation
# ==============================================================================

def test_runtime_execution_central_management():
    src = """
    CASE "INC-E2E-2026"
    HOST "LAB-PC-01"

    REGISTER HOST "LAB-PC-01"
    REGISTER HOST "LAB-PC-02"
    REGISTER HOST "LAB-PC-03"

    ANALYZE FILES
    ANALYZE PROCESSES
    ANALYZE NETWORK
    CORRELATE EVIDENCE
    ATTACH EVIDENCE
    ASSESS RISK
    """
    res = compile_source(src)
    assert res.ok is True

    ea = FixtureEndpointAdapter(host="LAB-PC-01")
    na = FixtureNetworkAdapter(host="LAB-PC-01")
    executor = RuntimeExecutor(res.ir, adapter=ea, network_adapter=na)
    exec_result = executor.execute()

    d = exec_result.to_dict()
    assert "case_management" in d
    cm = d["case_management"]

    # 1. 3 synthetic hosts registered
    assert cm["summary"]["host_count"] == 3
    assert len(cm["case"]["hosts"]) == 3

    # 2. Only 1 evidence package attached
    assert cm["summary"]["evidence_package_count"] == 1
    assert len(cm["case"]["evidence_packages"]) == 1

    # 3. Grounded computed counts
    assert cm["summary"]["evidence_item_count"] == 14
    assert cm["summary"]["correlation_count"] == 4
    assert cm["summary"]["relationship_count"] == 5
    assert cm["summary"]["highest_risk_score"] == 60
    assert cm["summary"]["highest_risk_severity"] == "HIGH"

    # 4. Deterministic separate case hash
    assert cm["case_hash"] is not None
    attached_pkg_hash = cm["case"]["evidence_packages"][0]
    assert cm["case_hash"] != attached_pkg_hash

    # 5. Package hash invariance
    assert attached_pkg_hash == d["evidence_package"]["package_hash"]


# ==============================================================================
# 7. Serialization Helpers
# ==============================================================================

def test_serialization_helpers():
    case = InvestigationCase(case_id="C1", title="Title")
    d_case = case_to_dict(case)
    assert d_case["case_id"] == "C1"
    assert d_case["status"] == "OPEN"

    summary = CaseSummary(
        case_id="C1",
        status=CaseStatus.OPEN,
        host_count=2,
        evidence_package_count=1,
        highest_risk_score=50,
    )
    d_summary = case_summary_to_dict(summary)
    assert d_summary["case_id"] == "C1"
    assert d_summary["host_count"] == 2
    assert d_summary["highest_risk_score"] == 50

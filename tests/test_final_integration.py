"""
Phase 16 — End-to-End Final Integration & Pipeline Validation.
Validates the complete JOCKY system flow:
Script -> Lexer -> Parser -> AST -> IR -> LLVM -> Runtime -> Forensics
-> Blockchain -> VASP -> Correlation -> Graph -> Timeline -> Risk
-> Anchoring -> Verification -> Research Lab -> Central Management -> Integrity Invariants.
"""

import pytest
from compiler.compiler import compile_source
from compiler.lexer.lexer import Lexer
from compiler.parser.parser import Parser
from compiler.ir.lowering import lower
from compiler.llvm.backend import JockyLLVMBackend
from forensic.endpoint.fixture import FixtureEndpointAdapter
from forensic.network.fixture import FixtureNetworkAdapter
from blockchain.evm.adapter import EVMAdapter
from forensic.platform.factory import PlatformAdapterFactory
from management.manager import CentralInvestigationManager
from runtime.executor.executor import RuntimeExecutor


@pytest.fixture(autouse=True)
def reset_manager():
    CentralInvestigationManager.reset_global()
    yield
    CentralInvestigationManager.reset_global()


def test_final_demo_compilation_and_lowering():
    with open("examples/final_demo.jky") as f:
        src = f.read()

    # 1. Lexing
    tokens = Lexer(src).tokenize()
    assert len(tokens) > 20

    # 2. Parsing
    prog = Parser(tokens).parse()
    assert len(prog.body) >= 15

    # 3. Lowering
    lowered = lower(prog)
    assert lowered.ok is True
    assert lowered.ir is not None
    assert lowered.ir.case_id == "JOCKY-FINAL-2026"
    assert lowered.ir.host.hostname == "LAB-PC-01"

    # 4. LLVM Generation
    llvm_gen = JockyLLVMBackend(lowered.ir)
    llvm_res = llvm_gen.generate()
    assert llvm_res.ok is True
    assert "target triple" in llvm_res.ir_text


def test_final_demo_runtime_execution_and_integrity():
    with open("examples/final_demo.jky") as f:
        src = f.read()

    res = compile_source(src)
    assert res.ok is True

    executor = RuntimeExecutor(
        res.ir,
        adapter=FixtureEndpointAdapter(host="LAB-PC-01"),
        network_adapter=FixtureNetworkAdapter(host="LAB-PC-01"),
        blockchain_adapter=EVMAdapter(),
        platform_adapter=PlatformAdapterFactory.get_adapter(),
    )
    exec_result = executor.execute()
    d = exec_result.to_dict()

    # 1. Case & Host Management
    assert d["case_id"] == "JOCKY-FINAL-2026"
    assert d["host"] == "LAB-PC-01"
    assert "case_management" in d
    cm = d["case_management"]
    assert cm["summary"]["host_count"] == 3
    assert cm["summary"]["evidence_package_count"] == 1
    case_hash = cm["case_hash"]
    assert case_hash is not None
    assert len(case_hash) == 64

    # 2. Platform & Security Precheck
    assert "platform_info" in d
    assert "security_status" in d
    assert d["security_status"]["hvci"]["applicable"] in (True, False)

    # 3. Universal Evidence Package (from build_universal_package)
    assert "evidence_package" in d
    universal_pkg = d["evidence_package"]
    universal_package_hash = universal_pkg["package_hash"]
    assert len(universal_package_hash) == 64
    assert len(universal_pkg["evidence"]) >= 8
    assert len(universal_pkg["relationships"]) >= 9

    # 4. Blockchain & VASP Results
    assert "blockchain" in d
    assert len(d["blockchain"]["hops"]) >= 2
    assert "vasp" in d
    assert len(d["vasp"]["attributions"]) >= 1

    # 5. Correlations
    assert len(universal_pkg["correlations"]) >= 5

    # 6. Graph & Timeline
    assert "graph" in d
    assert len(d["graph"]["nodes"]) >= 8
    assert len(d["graph"]["edges"]) >= 10

    from graph.queries import get_cross_domain_paths
    paths = get_cross_domain_paths(exec_result.context["last_graph"])
    assert len(paths) >= 1
    primary_path = paths[0]
    path_types = [n.node_type.value for n in primary_path.nodes]
    assert "PROCESS" in path_types
    assert "NETWORK_CONNECTION" in path_types
    assert "WALLET" in path_types
    assert "TRANSACTION" in path_types
    assert "VASP" in path_types
    assert primary_path.confidence == 0.65

    assert "timeline" in d
    assert len(d["timeline"]["events"]) >= 10

    # 7. Risk Assessment
    assert "risk_assessment" in d
    risk = d["risk_assessment"]
    assert risk["score"] > 50
    assert risk["severity"] in ("HIGH", "CRITICAL")
    assert len(risk["findings"]) >= 5

    # 8. Anchoring & Verification
    anchor_op = next(op for op in d["operations"] if op["operation"] == "ANCHOR_EVIDENCE")
    assert anchor_op["status"] == "SUCCESS"
    anchor_data = anchor_op["data"]
    # anchor_data["package_hash"] is the hash of the ANCHOR package (built at anchor time)
    anchored_package_hash = anchor_data["package_hash"]
    assert len(anchored_package_hash) == 64
    assert anchor_data["ipfs_cid"].startswith("bafk")
    assert anchor_data["tx_hash"].startswith("0x")
    # Anchor metadata contains independently computed hashes
    assert "metadata" in anchor_data
    assert "graph_hash" in anchor_data["metadata"]
    assert "timeline_hash" in anchor_data["metadata"]
    assert "risk_hash" in anchor_data["metadata"]

    verify_op = next(op for op in d["operations"] if op["operation"] == "VERIFY_EVIDENCE")
    assert verify_op["status"] == "SUCCESS"
    verify_data = verify_op["data"]
    assert verify_data["is_valid"] is True
    assert verify_data["package_hash_match"] is True
    assert verify_data["ipfs_match"] is True
    assert verify_data["evm_match"] is True

    # 9. Security Research Lab Results
    assert "research_results" in d
    assert len(d["research_results"]) == 5
    for r in d["research_results"]:
        assert r["scenario"]["simulated"] is True
        assert r["result_hash"] != ""
        # Isolation invariant: research result_hash != anchored package_hash
        assert r["result_hash"] != anchored_package_hash

    # 10. Hash Isolation & Invariance Check
    # case_hash, graph_hash, timeline_hash, risk_hash must all be distinct from each other
    graph_hash = anchor_data["metadata"]["graph_hash"]
    timeline_hash = anchor_data["metadata"]["timeline_hash"]
    risk_hash = anchor_data["metadata"]["risk_hash"]

    assert case_hash != anchored_package_hash
    assert graph_hash != anchored_package_hash
    assert timeline_hash != anchored_package_hash
    assert risk_hash != anchored_package_hash
    # They should all be distinct from each other (6 distinct hashes)
    all_hashes = {anchored_package_hash, case_hash, graph_hash, timeline_hash, risk_hash}
    assert len(all_hashes) == 5, f"Expected 5 distinct hashes, got {len(all_hashes)}: {all_hashes}"

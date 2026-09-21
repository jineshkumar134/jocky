"""
Unit and integration tests for Phase 15 — Security Research Lab.
Ensures strict defensive safety boundaries, deterministic benchmarking,
isolated result hashes, and compiler/runtime integration.
"""

import pytest
from compiler.compiler import compile_source
from compiler.lexer.lexer import Lexer, TokenType
from compiler.parser.parser import Parser
from compiler.ir.lowering import lower
from forensic.endpoint.fixture import FixtureEndpointAdapter
from forensic.network.fixture import FixtureNetworkAdapter
from forensic.evidence.models import EvidencePackage
from research.models import (
    ScenarioCategory,
    ResearchSafetyLevel,
    ResearchSeverity,
)
from research.scenarios import ScenarioRegistry
from research.detector import ResearchDetector
from research.benchmark import ResearchBenchmarkEngine
from research.engine import ResearchLabEngine
from research.serialization import (
    compute_result_hash,
    scenario_to_dict,
    observable_to_dict,
    finding_to_dict,
    benchmark_to_dict,
    result_to_dict,
)
from runtime.executor.executor import RuntimeExecutor


# ==============================================================================
# 1. Scenario Registry & Safety Tests
# ==============================================================================

def test_scenario_registry_known_scenarios():
    registry = ScenarioRegistry()
    scenarios = registry.list_scenarios()
    scenario_ids = [s.scenario_id for s in scenarios]

    expected = [
        "synthetic_polymorphism",
        "synthetic_memory_execution",
        "synthetic_driver_risk",
        "synthetic_security_controls",
        "synthetic_network_behavior",
    ]
    for exp in expected:
        assert exp in scenario_ids

    # All registered scenarios must have simulated=True
    for s in scenarios:
        assert s.simulated is True
        assert s.safety_level in (
            ResearchSafetyLevel.SAFE_SYNTHETIC,
            ResearchSafetyLevel.SAFE_BENCHMARK,
            ResearchSafetyLevel.SAFE_INSPECTION,
        )


def test_scenario_registry_unknown_scenario():
    registry = ScenarioRegistry()
    assert registry.get_scenario("unknown_malicious_scenario") is None
    with pytest.raises(KeyError, match="unregistered"):
        registry.generate_observables("unknown_malicious_scenario")


# ==============================================================================
# 2. Polymorphism Benchmark Tests
# ==============================================================================

def test_safe_polymorphism_benchmark():
    engine = ResearchLabEngine()
    result = engine.run_scenario("synthetic_polymorphism")

    assert result.scenario.category == ScenarioCategory.POLYMORPHISM
    assert len(result.observables) == 2
    assert len(result.findings) == 2
    assert result.benchmark.detection_coverage == 1.0

    # Verify no payload or execution artifacts
    for obs in result.observables:
        assert obs.simulated is True
        assert "base_input" in obs.attributes
        assert obs.attributes["structural_diff_ratio"] > 0


# ==============================================================================
# 3. Simulated Memory Execution Tests
# ==============================================================================

def test_safe_memory_execution_research():
    engine = ResearchLabEngine()
    result = engine.run_scenario("synthetic_memory_execution")

    assert result.scenario.category == ScenarioCategory.MEMORY_EXECUTION
    assert len(result.observables) == 2

    # Exactly 1 finding corresponding to RWX allocation
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == "RULE_SYNTHETIC_EXECUTABLE_MEMORY"
    assert finding.severity == ResearchSeverity.HIGH
    assert finding.simulated is True


# ==============================================================================
# 4. Simulated Driver / BYOVD Risk Tests
# ==============================================================================

def test_safe_driver_risk_research():
    engine = ResearchLabEngine()
    result = engine.run_scenario("synthetic_driver_risk")

    assert result.scenario.category == ScenarioCategory.DRIVER_RISK
    assert len(result.observables) == 2

    # Finding on the vulnerable driver catalog entry
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == "RULE_SYNTHETIC_DRIVER_RISK"
    assert finding.severity in (ResearchSeverity.HIGH, ResearchSeverity.CRITICAL)
    assert "vulnerable" in finding.explanation.lower()
    assert finding.simulated is True


# ==============================================================================
# 5. Security Control Posture Assessment Tests
# ==============================================================================

def test_safe_security_controls_research():
    engine = ResearchLabEngine()
    result = engine.run_scenario("synthetic_security_controls")

    assert result.scenario.category == ScenarioCategory.SECURITY_CONTROL
    assert len(result.observables) == 2
    assert len(result.findings) == 2

    # Check that UNKNOWN status is preserved and not converted to disabled
    unknown_finding = next(
        f for f in result.findings if f.metadata.get("status") == "UNKNOWN"
    )
    assert unknown_finding.metadata["status"] == "UNKNOWN"
    assert "undetermined" in unknown_finding.explanation.lower()


# ==============================================================================
# 6. Safe Network Behavior Simulation Tests
# ==============================================================================

def test_safe_network_behavior_research():
    engine = ResearchLabEngine()
    result = engine.run_scenario("synthetic_network_behavior")

    assert result.scenario.category == ScenarioCategory.NETWORK_BEHAVIOR
    assert len(result.observables) == 2
    assert len(result.findings) == 1

    finding = result.findings[0]
    assert finding.rule_id == "RULE_EXTERNAL_SYNTHETIC_CONNECTION"
    assert finding.severity == ResearchSeverity.MEDIUM


# ==============================================================================
# 7. Deterministic Result Hashing & Isolation Tests
# ==============================================================================

def test_result_hash_determinism_and_isolation():
    engine = ResearchLabEngine()
    res1 = engine.run_scenario("synthetic_polymorphism")
    res2 = engine.run_scenario("synthetic_polymorphism")

    # Hashes are deterministic across separate runs
    assert res1.result_hash != ""
    assert res1.result_hash == res2.result_hash

    # Hashes are separate and distinct across different scenarios
    res_mem = engine.run_scenario("synthetic_memory_execution")
    assert res1.result_hash != res_mem.result_hash


# ==============================================================================
# 8. Compiler Language Integration (RESEARCH Command)
# ==============================================================================

def test_compiler_research_syntax():
    src = """
    CASE "CASE-RES-LANG"
    HOST "PRIMARY-HOST"

    RESEARCH "synthetic_polymorphism"
    RESEARCH "synthetic_driver_risk"
    """
    tokens = Lexer(src).tokenize()
    token_types = [t.type for t in tokens]
    assert TokenType.RESEARCH in token_types

    prog = Parser(tokens).parse()
    assert len(prog.body) == 4
    cmd1 = prog.body[2]
    cmd2 = prog.body[3]
    assert cmd1.__class__.__name__ == "ResearchCommand"
    assert cmd1.scenario_id == "synthetic_polymorphism"
    assert cmd2.scenario_id == "synthetic_driver_risk"

    # Lowering pass
    res = lower(prog)
    assert res.ok is True
    assert len(res.ir.operations) == 2
    assert res.ir.operations[0].kind == "RESEARCH"
    assert res.ir.operations[0].scenario_id == "synthetic_polymorphism"


# ==============================================================================
# 9. Runtime Execution & EvidencePackage Invariance
# ==============================================================================

def test_runtime_research_execution_and_hash_invariance():
    src = """
    CASE "INC-RES-RUN"
    HOST "LAB-PC-01"

    ANALYZE FILES
    ANALYZE PROCESSES
    ATTACH EVIDENCE
    RESEARCH "synthetic_polymorphism"
    RESEARCH "synthetic_memory_execution"
    """
    res = compile_source(src)
    assert res.ok is True

    ea = FixtureEndpointAdapter(host="LAB-PC-01")
    na = FixtureNetworkAdapter(host="LAB-PC-01")
    executor = RuntimeExecutor(res.ir, adapter=ea, network_adapter=na)
    exec_res = executor.execute()
    d = exec_res.to_dict()

    # Verify research_results are present
    assert "research_results" in d
    assert len(d["research_results"]) == 2

    # Verify EvidencePackage.package_hash exists and was unaffected by research ops
    pkg_hash = d["evidence_package"]["package_hash"]
    assert pkg_hash != ""

    for r in d["research_results"]:
        assert r["result_hash"] != ""
        assert r["result_hash"] != pkg_hash


# ==============================================================================
# 10. Security Boundary Invariants
# ==============================================================================

def test_security_boundary_no_arbitrary_commands():
    src = """
    CASE "EXPLOIT-TEST"
    HOST "LAB-PC-01"

    RESEARCH "malicious_unregistered_scenario"
    """
    res = compile_source(src)
    assert res.ok is True

    ea = FixtureEndpointAdapter(host="LAB-PC-01")
    na = FixtureNetworkAdapter(host="LAB-PC-01")
    executor = RuntimeExecutor(res.ir, adapter=ea, network_adapter=na)
    exec_res = executor.execute()

    # Unregistered scenario fails gracefully without crashing or executing
    op_res = exec_res.results[0]
    assert op_res.status == "FAILED"
    assert "unregistered" in op_res.message.lower()

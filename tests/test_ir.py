"""
tests/test_ir.py
-----------------
Comprehensive tests for the JOCKY IR:
  - AST → IR lowering for every command
  - Default parameter values
  - Invalid AST handling (missing CASE / HOST, duplicates)
  - Determinism
  - JSON serialisation / deserialisation round-trip
  - IR printer smoke-test
"""

import json
import pytest
from compiler.lexer    import Lexer
from compiler.parser   import Parser
from compiler.ast      import Program
from compiler.ir       import (
    lower,
    LoweringResult,
    InvestigationIR,
    HostTarget,
    AnalyzeFilesOp,
    AnalyzeProcessesOp,
    AnalyzeNetworkOp,
    AnalyzeSystemOp,
    TraceConnectionsOp,
    BlockchainTraceOp,
    IdentifyVaspOp,
    CorrelateEvidenceOp,
    BuildTimelineOp,
    BuildAttackGraphOp,
    AnchorEvidenceOp,
    GenerateReportOp,
    CheckSecurityOp,
)
from compiler.ir.printer import render as render_ir


# ──────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────

def compile_to_ir(src: str) -> LoweringResult:
    tokens  = Lexer(src).tokenize()
    program = Parser(tokens).parse()
    return lower(program)


def get_ir(src: str) -> InvestigationIR:
    result = compile_to_ir(src)
    assert result.ok, f"Lowering failed: {result.errors}"
    assert result.ir is not None
    return result.ir


# ──────────────────────────────────────────────────────────
# Full reference source (used in multiple tests)
# ──────────────────────────────────────────────────────────

FULL_SRC = """
CASE "INC-2026-001"
HOST "LAB-PC-01"
ANALYZE FILES
ANALYZE PROCESSES
ANALYZE NETWORK
TRACE SUSPICIOUS CONNECTIONS
BLOCKCHAIN TRACE "0xABC123"
IDENTIFY VASP
CORRELATE EVIDENCE
BUILD TIMELINE
BUILD ATTACK GRAPH
ANCHOR EVIDENCE
GENERATE REPORT
"""


# ──────────────────────────────────────────────────────────
# 1. CASE / HOST extraction
# ──────────────────────────────────────────────────────────

class TestCaseAndHost:
    def test_case_id_extracted(self):
        ir = get_ir('CASE "INC-2026-001"\nHOST "LAB-PC-01"')
        assert ir.case_id == "INC-2026-001"

    def test_host_extracted(self):
        ir = get_ir('CASE "INC-2026-001"\nHOST "LAB-PC-01"')
        assert isinstance(ir.host, HostTarget)
        assert ir.host.hostname == "LAB-PC-01"

    def test_case_source_line_preserved(self):
        ir = get_ir('CASE "X"\nHOST "Y"')
        assert ir.source_line == 1

    def test_host_source_line_preserved(self):
        ir = get_ir('CASE "X"\nHOST "Y"')
        assert ir.host.source_line == 2

    def test_no_operations_for_declarations_only(self):
        ir = get_ir('CASE "X"\nHOST "Y"')
        assert ir.operations == []


# ──────────────────────────────────────────────────────────
# 2. AST → IR for every command
# ──────────────────────────────────────────────────────────

class TestOperationLowering:
    """Covers the mapping for every Phase-1 command."""

    def _single_op(self, cmd_src: str):
        src = f'CASE "X"\nHOST "Y"\n{cmd_src}'
        ir  = get_ir(src)
        assert len(ir.operations) == 1
        return ir.operations[0]

    def test_analyze_files(self):
        op = self._single_op("ANALYZE FILES")
        assert isinstance(op, AnalyzeFilesOp)
        assert op.kind == "ANALYZE_FILES"

    def test_analyze_processes(self):
        op = self._single_op("ANALYZE PROCESSES")
        assert isinstance(op, AnalyzeProcessesOp)
        assert op.kind == "ANALYZE_PROCESSES"

    def test_analyze_network(self):
        op = self._single_op("ANALYZE NETWORK")
        assert isinstance(op, AnalyzeNetworkOp)
        assert op.kind == "ANALYZE_NETWORK"

    def test_analyze_system(self):
        op = self._single_op("ANALYZE SYSTEM")
        assert isinstance(op, AnalyzeSystemOp)
        assert op.kind == "ANALYZE_SYSTEM"

    def test_trace_connections(self):
        op = self._single_op("TRACE SUSPICIOUS CONNECTIONS")
        assert isinstance(op, TraceConnectionsOp)
        assert op.kind == "TRACE_CONNECTIONS"

    def test_blockchain_trace(self):
        op = self._single_op('BLOCKCHAIN TRACE "0xABC123"')
        assert isinstance(op, BlockchainTraceOp)
        assert op.kind   == "BLOCKCHAIN_TRACE"
        assert op.wallet == "0xABC123"

    def test_identify_vasp(self):
        op = self._single_op("IDENTIFY VASP")
        assert isinstance(op, IdentifyVaspOp)
        assert op.kind == "IDENTIFY_VASP"

    def test_correlate_evidence(self):
        op = self._single_op("CORRELATE EVIDENCE")
        assert isinstance(op, CorrelateEvidenceOp)
        assert op.kind == "CORRELATE_EVIDENCE"

    def test_build_timeline(self):
        op = self._single_op("BUILD TIMELINE")
        assert isinstance(op, BuildTimelineOp)
        assert op.kind == "BUILD_TIMELINE"

    def test_build_attack_graph(self):
        op = self._single_op("BUILD ATTACK GRAPH")
        assert isinstance(op, BuildAttackGraphOp)
        assert op.kind == "BUILD_ATTACK_GRAPH"

    def test_anchor_evidence(self):
        op = self._single_op("ANCHOR EVIDENCE")
        assert isinstance(op, AnchorEvidenceOp)
        assert op.kind == "ANCHOR_EVIDENCE"

    def test_generate_report(self):
        op = self._single_op("GENERATE REPORT")
        assert isinstance(op, GenerateReportOp)
        assert op.kind == "GENERATE_REPORT"

    def test_check_security(self):
        op = self._single_op("CHECK SECURITY")
        assert isinstance(op, CheckSecurityOp)
        assert op.kind == "CHECK_SECURITY"

    def test_operation_order_preserved(self):
        ir = get_ir(FULL_SRC)
        kinds = [op.kind for op in ir.operations]
        assert kinds == [
            "ANALYZE_FILES",
            "ANALYZE_PROCESSES",
            "ANALYZE_NETWORK",
            "TRACE_CONNECTIONS",
            "BLOCKCHAIN_TRACE",
            "IDENTIFY_VASP",
            "CORRELATE_EVIDENCE",
            "BUILD_TIMELINE",
            "BUILD_ATTACK_GRAPH",
            "ANCHOR_EVIDENCE",
            "GENERATE_REPORT",
        ]


# ──────────────────────────────────────────────────────────
# 3. Default parameter values
# ──────────────────────────────────────────────────────────

class TestDefaultValues:
    def _op(self, cmd_src: str):
        src = f'CASE "X"\nHOST "Y"\n{cmd_src}'
        return get_ir(src).operations[0]

    def test_blockchain_trace_defaults_to_ethereum(self):
        op = self._op('BLOCKCHAIN TRACE "0xABC123"')
        assert isinstance(op, BlockchainTraceOp)
        assert op.chain == "ethereum"

    def test_non_0x_address_chain_is_unknown(self):
        op = self._op('BLOCKCHAIN TRACE "bc1qxyz"')
        assert isinstance(op, BlockchainTraceOp)
        assert op.chain == "unknown"

    def test_anchor_evidence_default_algorithm(self):
        op = self._op("ANCHOR EVIDENCE")
        assert isinstance(op, AnchorEvidenceOp)
        assert op.algorithm == "sha256"

    def test_anchor_evidence_default_backend(self):
        op = self._op("ANCHOR EVIDENCE")
        assert isinstance(op, AnchorEvidenceOp)
        assert op.backend == "ipfs"

    def test_generate_report_default_format(self):
        op = self._op("GENERATE REPORT")
        assert isinstance(op, GenerateReportOp)
        assert op.format == "json"


# ──────────────────────────────────────────────────────────
# 4. Source-line traceability
# ──────────────────────────────────────────────────────────

class TestSourceLines:
    def test_operation_source_line_set(self):
        src = "CASE \"X\"\nHOST \"Y\"\nANALYZE FILES"
        ir  = get_ir(src)
        assert ir.operations[0].source_line == 3

    def test_multiple_ops_have_correct_lines(self):
        src = "CASE \"X\"\nHOST \"Y\"\nANALYZE FILES\nANALYZE NETWORK"
        ir  = get_ir(src)
        assert ir.operations[0].source_line == 3
        assert ir.operations[1].source_line == 4


# ──────────────────────────────────────────────────────────
# 5. Invalid AST / lowering errors
# ──────────────────────────────────────────────────────────

class TestLoweringErrors:
    def test_missing_case_returns_error(self):
        result = compile_to_ir('HOST "Y"\nANALYZE FILES')
        assert result.ok is False
        assert any("CASE" in e for e in result.errors)

    def test_missing_host_returns_error(self):
        result = compile_to_ir('CASE "X"\nANALYZE FILES')
        assert result.ok is False
        assert any("HOST" in e for e in result.errors)

    def test_missing_both_returns_two_errors(self):
        result = compile_to_ir("ANALYZE FILES")
        assert result.ok is False
        assert len(result.errors) == 2

    def test_empty_program_returns_errors(self):
        result = compile_to_ir("// empty")
        assert result.ok is False
        assert not result.ok

    def test_duplicate_case_returns_error(self):
        src = 'CASE "X"\nCASE "Y"\nHOST "Z"'
        result = compile_to_ir(src)
        assert result.ok is False
        assert any("Duplicate CASE" in e for e in result.errors)

    def test_duplicate_host_returns_error(self):
        src = 'CASE "X"\nHOST "A"\nHOST "B"'
        result = compile_to_ir(src)
        assert result.ok is False
        assert any("Duplicate HOST" in e for e in result.errors)

    def test_error_result_has_no_ir(self):
        result = compile_to_ir("ANALYZE FILES")
        assert result.ir is None

    def test_warnings_empty_on_clean_program(self):
        result = compile_to_ir(FULL_SRC)
        assert result.ok is True
        assert result.warnings == []


# ──────────────────────────────────────────────────────────
# 6. Determinism
# ──────────────────────────────────────────────────────────

class TestDeterminism:
    def test_same_source_produces_identical_ir(self):
        ir1 = get_ir(FULL_SRC)
        ir2 = get_ir(FULL_SRC)
        assert ir1 == ir2

    def test_ir_dict_is_identical_on_repeated_calls(self):
        ir1 = get_ir(FULL_SRC).model_dump()
        ir2 = get_ir(FULL_SRC).model_dump()
        assert ir1 == ir2

    def test_operation_count_is_stable(self):
        for _ in range(5):
            ir = get_ir(FULL_SRC)
            assert len(ir.operations) == 11


# ──────────────────────────────────────────────────────────
# 7. Serialisation / deserialisation
# ──────────────────────────────────────────────────────────

class TestSerialisation:
    def test_ir_serialises_to_dict(self):
        ir = get_ir(FULL_SRC)
        d  = ir.model_dump()
        assert isinstance(d, dict)
        assert d["case_id"] == "INC-2026-001"
        assert d["host"]["hostname"] == "LAB-PC-01"
        assert len(d["operations"]) == 11

    def test_ir_serialises_to_json_string(self):
        ir   = get_ir(FULL_SRC)
        blob = ir.model_dump_json()
        assert isinstance(blob, str)
        parsed = json.loads(blob)
        assert parsed["case_id"] == "INC-2026-001"

    def test_blockchain_op_serialises_wallet_and_chain(self):
        src = 'CASE "X"\nHOST "Y"\nBLOCKCHAIN TRACE "0xABC123"'
        ir  = get_ir(src)
        d   = ir.model_dump()
        op  = d["operations"][0]
        assert op["kind"]   == "BLOCKCHAIN_TRACE"
        assert op["wallet"] == "0xABC123"
        assert op["chain"]  == "ethereum"

    def test_ir_round_trips_via_json(self):
        """Serialise → JSON → deserialise should give back the same IR."""
        ir      = get_ir(FULL_SRC)
        json_str = ir.model_dump_json()
        ir2     = InvestigationIR.model_validate_json(json_str)
        assert ir == ir2

    def test_all_operations_have_kind_field(self):
        ir = get_ir(FULL_SRC)
        d  = ir.model_dump()
        for op_dict in d["operations"]:
            assert "kind" in op_dict, f"Operation missing 'kind': {op_dict}"

    def test_operation_kinds_match_expected(self):
        ir    = get_ir(FULL_SRC)
        d     = ir.model_dump()
        kinds = [op["kind"] for op in d["operations"]]
        assert "ANALYZE_FILES"     in kinds
        assert "BLOCKCHAIN_TRACE"  in kinds
        assert "ANCHOR_EVIDENCE"   in kinds
        assert "GENERATE_REPORT"   in kinds


# ──────────────────────────────────────────────────────────
# 8. IR Printer smoke-tests
# ──────────────────────────────────────────────────────────

class TestIRPrinter:
    def test_render_returns_string(self):
        ir  = get_ir(FULL_SRC)
        out = render_ir(ir)
        assert isinstance(out, str)
        assert len(out) > 0

    def test_render_contains_case_id(self):
        ir  = get_ir(FULL_SRC)
        out = render_ir(ir)
        assert "INC-2026-001" in out

    def test_render_contains_host(self):
        ir  = get_ir(FULL_SRC)
        out = render_ir(ir)
        assert "LAB-PC-01" in out

    def test_render_contains_all_kinds(self):
        ir  = get_ir(FULL_SRC)
        out = render_ir(ir)
        for kind in [
            "ANALYZE_FILES", "ANALYZE_PROCESSES", "ANALYZE_NETWORK",
            "TRACE_CONNECTIONS", "BLOCKCHAIN_TRACE", "IDENTIFY_VASP",
            "CORRELATE_EVIDENCE", "BUILD_TIMELINE", "BUILD_ATTACK_GRAPH",
            "ANCHOR_EVIDENCE", "GENERATE_REPORT",
        ]:
            assert kind in out, f"Kind {kind!r} not found in IR render"

    def test_render_contains_blockchain_wallet(self):
        ir  = get_ir(FULL_SRC)
        out = render_ir(ir)
        assert "0xABC123" in out

    def test_render_contains_default_params(self):
        ir  = get_ir(FULL_SRC)
        out = render_ir(ir)
        assert "sha256"   in out
        assert "ipfs"     in out
        assert "ethereum" in out
        assert "json"     in out

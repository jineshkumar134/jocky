"""
tests/test_llvm.py
------------------
Comprehensive unit and regression tests for JOCKY LLVM IR generation:
  - LLVM IR generation from minimal JOCKY program
  - Structural validity verification via LLVM binding
  - Verification of function signatures, extern declarations, and caller blocks
  - String constants and memory addressing (GEP)
  - Handling of individual operations in isolation
  - Full program lowering to valid LLVM module
"""

import pytest
import llvmlite.binding as llvm

from compiler.compiler import compile_source
from compiler.ir import lower
from compiler.lexer import Lexer
from compiler.parser import Parser
from compiler.llvm import JockyLLVMBackend, generate_llvm


def parse_and_get_ir(src: str):
    tokens = Lexer(src).tokenize()
    program = Parser(tokens).parse()
    res = lower(program)
    assert res.ok, f"Lowering failed: {res.errors}"
    return res.ir


class TestLLVMMinimal:
    def test_minimal_program_generates_valid_llvm(self):
        src = 'CASE "INC-MINIMAL"\nHOST "LOCAL-PC"'
        ir = parse_and_get_ir(src)
        llvm_res = generate_llvm(ir)

        assert llvm_res.ok is True
        assert llvm_res.ir_text
        assert "jocky_INC_MINIMAL" in llvm_res.module_name

        # Verify LLVM assembly structurally
        mod = llvm.parse_assembly(llvm_res.ir_text)
        mod.verify()

        # Check function exists and returns 0
        assert "define i32 @\"jocky_investigate_INC_MINIMAL\"" in llvm_res.ir_text
        assert "ret i32 0" in llvm_res.ir_text

    def test_compiler_facade_emit_llvm_flag(self):
        src = 'CASE "INC-01"\nHOST "HOST-01"\nANALYZE FILES'
        res = compile_source(src, emit_llvm=True)
        assert res.ok is True
        assert res.llvm_ir is not None
        assert "jocky_analyze_files" in res.llvm_ir

        # Structurally verify
        mod = llvm.parse_assembly(res.llvm_ir)
        mod.verify()


class TestLLVMOperations:
    def test_all_endpoint_operations(self):
        src = """
CASE "CASE-OPS"
HOST "ENDPOINT-01"
ANALYZE FILES
ANALYZE PROCESSES
ANALYZE NETWORK
TRACE SUSPICIOUS CONNECTIONS
"""
        ir = parse_and_get_ir(src)
        res = generate_llvm(ir)
        assert res.ok is True

        text = res.ir_text
        assert "call i32 @\"jocky_analyze_files\"" in text
        assert "call i32 @\"jocky_analyze_processes\"" in text
        assert "call i32 @\"jocky_analyze_network\"" in text
        assert "call i32 @\"jocky_trace_connections\"" in text

        mod = llvm.parse_assembly(text)
        mod.verify()

    def test_blockchain_and_vasp_operations(self):
        src = """
CASE "CASE-CRYPTO"
HOST "ANALYSIS-RIG"
BLOCKCHAIN TRACE "0x1234567890abcdef"
IDENTIFY VASP
"""
        ir = parse_and_get_ir(src)
        res = generate_llvm(ir)
        assert res.ok is True

        text = res.ir_text
        assert "call i32 @\"jocky_blockchain_trace\"" in text
        assert "call i32 @\"jocky_identify_vasp\"" in text
        assert "0x1234567890abcdef" in text
        assert "ethereum" in text

        mod = llvm.parse_assembly(text)
        mod.verify()

    def test_correlation_graph_and_reporting(self):
        src = """
CASE "CASE-SYNTH"
HOST "SYNTH-NODE"
CORRELATE EVIDENCE
BUILD TIMELINE
BUILD ATTACK GRAPH
ANCHOR EVIDENCE
GENERATE REPORT
"""
        ir = parse_and_get_ir(src)
        res = generate_llvm(ir)
        assert res.ok is True

        text = res.ir_text
        assert "call i32 @\"jocky_correlate_evidence\"" in text
        assert "call i32 @\"jocky_build_timeline\"" in text
        assert "call i32 @\"jocky_build_attack_graph\"" in text
        assert "call i32 @\"jocky_anchor_evidence\"" in text
        assert "call i32 @\"jocky_generate_report\"" in text
        assert "sha256" in text
        assert "ipfs" in text
        assert "json" in text

        mod = llvm.parse_assembly(text)
        mod.verify()


class TestLLVMFullProgram:
    def test_full_hello_program_llvm(self):
        with open("examples/hello.jky", "r", encoding="utf-8") as f:
            src = f.read()

        res = compile_source(src, emit_llvm=True)
        assert res.ok is True
        assert res.llvm_ir is not None

        # Verify through LLVM engine
        mod = llvm.parse_assembly(res.llvm_ir)
        mod.verify()

        # Check total calls count equals operations count (11 operations)
        call_count = res.llvm_ir.count("call i32 @\"jocky_")
        assert call_count == 11

    def test_special_characters_in_case_id_sanitized(self):
        src = 'CASE "INC/2026:001@CRITICAL!"\nHOST "SERVER-01"'
        ir = parse_and_get_ir(src)
        res = generate_llvm(ir)
        assert res.ok is True
        # Check module and function names are sanitized
        assert "jocky_INC_2026_001_CRITICAL_" in res.module_name
        assert "jocky_investigate_INC_2026_001_CRITICAL_" in res.ir_text

        mod = llvm.parse_assembly(res.ir_text)
        mod.verify()

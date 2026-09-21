"""
tests/test_compiler.py
----------------------
Integration tests for the compile_source() facade.
Phase 2: covers Lex → Parse → IR lowering.
"""

import pytest
from compiler.compiler import compile_source, CompileResult


class TestCompileSource:
    def test_valid_full_program_returns_ok(self):
        src = 'CASE "X"\nHOST "Y"\nANALYZE FILES'
        result = compile_source(src)
        assert result.ok is True
        assert result.program is not None
        assert result.ir is not None
        assert not result.errors

    def test_valid_program_has_tokens(self):
        result = compile_source('CASE "X"\nHOST "Y"')
        # tokens include the EOF
        assert len(result.tokens) >= 3

    def test_lex_error_returns_not_ok(self):
        result = compile_source('@INVALID')
        assert result.ok is False
        assert result.errors
        assert "Lex error" in result.errors[0]

    def test_parse_error_returns_not_ok(self):
        result = compile_source("ANALYZEE FILES")
        assert result.ok is False
        assert result.errors
        assert "Parse error" in result.errors[0]

    def test_ir_lowering_error_missing_case(self):
        """Program without CASE should fail at IR lowering, not parsing."""
        result = compile_source('HOST "Y"\nANALYZE FILES')
        assert result.ok is False
        # program should still be set (parsing succeeded)
        assert result.program is not None
        assert any("CASE" in e for e in result.errors)

    def test_ir_lowering_error_missing_host(self):
        result = compile_source('CASE "X"\nANALYZE FILES')
        assert result.ok is False
        assert result.program is not None
        assert any("HOST" in e for e in result.errors)

    def test_source_name_appears_in_error(self):
        result = compile_source("BADWORD", source_name="my_script.jky")
        assert result.ok is False
        assert "my_script.jky" in result.errors[0]

    def test_skip_ir_flag_bypasses_lowering(self):
        """skip_ir=True should return ok=True even without CASE/HOST."""
        result = compile_source("// just a comment", skip_ir=True)
        assert result.ok is True
        assert result.program is not None
        assert result.ir is None

    def test_empty_program_fails_ir_missing_case_host(self):
        """An empty .jky (comments only) is syntactically valid but
        semantically invalid: IR requires CASE and HOST."""
        result = compile_source("// just a comment")
        assert result.ok is False
        assert result.ir is None

    def test_warnings_are_exposed(self):
        """A valid program should have no warnings from the lowering pass."""
        src = 'CASE "X"\nHOST "Y"\nANALYZE NETWORK'
        result = compile_source(src)
        assert result.ok is True
        assert result.warnings == []

"""
tests/test_parser.py
--------------------
Unit tests for the JOCKY parser covering all 12 required test cases:

 1. Valid CASE declaration
 2. Valid HOST declaration
 3. ANALYZE FILES
 4. ANALYZE PROCESSES
 5. ANALYZE NETWORK
 6. BLOCKCHAIN TRACE
 7. IDENTIFY VASP
 8. CORRELATE EVIDENCE
 9. BUILD commands (TIMELINE & ATTACK GRAPH)
10. Invalid / unknown keyword
11. Unknown command keyword
12. Missing string argument
"""

import pytest
from compiler.lexer import Lexer
from compiler.parser import Parser, ParseError
from compiler.ast import (
    Program,
    CaseDeclaration,
    HostDeclaration,
    AnalyzeCommand,
    TraceCommand,
    BlockchainTraceCommand,
    IdentifyVaspCommand,
    CorrelateEvidenceCommand,
    BuildTimelineCommand,
    BuildAttackGraphCommand,
    AnchorEvidenceCommand,
    CheckSecurityCommand,
    GenerateReportCommand,
)


# ──────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────

def parse(src: str) -> Program:
    """Lex + parse; return the Program AST or propagate ParseError."""
    tokens = Lexer(src).tokenize()
    return Parser(tokens).parse()


def parse_one(src: str):
    """Parse a single-statement source and return that one node."""
    program = parse(src)
    assert len(program.body) == 1, (
        f"Expected 1 node, got {len(program.body)}: {program.body}"
    )
    return program.body[0]


# ──────────────────────────────────────────────────────────
# 1. Valid CASE declaration
# ──────────────────────────────────────────────────────────

class TestCaseDeclaration:
    def test_basic_case(self):
        node = parse_one('CASE "INC-2026-001"')
        assert isinstance(node, CaseDeclaration)
        assert node.case_id == "INC-2026-001"

    def test_case_location(self):
        node = parse_one('CASE "INC-2026-001"')
        assert node.loc.line == 1
        assert node.loc.column == 1

    def test_case_with_whitespace(self):
        node = parse_one('CASE    "INC-2026-001"')
        assert isinstance(node, CaseDeclaration)
        assert node.case_id == "INC-2026-001"

    def test_case_with_comment_above(self):
        src = "// case declaration\nCASE \"INC-2026-001\""
        node = parse_one(src)
        assert isinstance(node, CaseDeclaration)


# ──────────────────────────────────────────────────────────
# 2. Valid HOST declaration
# ──────────────────────────────────────────────────────────

class TestHostDeclaration:
    def test_basic_host(self):
        node = parse_one('HOST "LAB-PC-01"')
        assert isinstance(node, HostDeclaration)
        assert node.hostname == "LAB-PC-01"

    def test_host_location(self):
        src = 'CASE "X"\nHOST "LAB-PC-01"'
        program = parse(src)
        host = program.body[1]
        assert isinstance(host, HostDeclaration)
        assert host.loc.line == 2

    def test_host_with_spaces_in_name(self):
        """A hostname with an internal space, passed as a quoted string arg, parses fine."""
        node = parse_one('HOST "some host"')
        assert isinstance(node, HostDeclaration)
        assert node.hostname == "some host"

    def test_host_parse_success(self):
        node = parse_one('HOST "192.168.1.10"')
        assert node.hostname == "192.168.1.10"


# ──────────────────────────────────────────────────────────
# 3. ANALYZE FILES
# ──────────────────────────────────────────────────────────

class TestAnalyzeFiles:
    def test_analyze_files(self):
        node = parse_one("ANALYZE FILES")
        assert isinstance(node, AnalyzeCommand)
        assert node.target == "FILES"

    def test_analyze_files_location(self):
        node = parse_one("ANALYZE FILES")
        assert node.loc.line == 1


# ──────────────────────────────────────────────────────────
# 4. ANALYZE PROCESSES
# ──────────────────────────────────────────────────────────

class TestAnalyzeProcesses:
    def test_analyze_processes(self):
        node = parse_one("ANALYZE PROCESSES")
        assert isinstance(node, AnalyzeCommand)
        assert node.target == "PROCESSES"


# ──────────────────────────────────────────────────────────
# 5. ANALYZE NETWORK
# ──────────────────────────────────────────────────────────

class TestAnalyzeNetwork:
    def test_analyze_network(self):
        node = parse_one("ANALYZE NETWORK")
        assert isinstance(node, AnalyzeCommand)
        assert node.target == "NETWORK"

    def test_analyze_system(self):
        node = parse_one("ANALYZE SYSTEM")
        assert isinstance(node, AnalyzeCommand)
        assert node.target == "SYSTEM"

    def test_all_analyze_variants_in_sequence(self):
        src = "ANALYZE FILES\nANALYZE PROCESSES\nANALYZE NETWORK\nANALYZE SYSTEM"
        program = parse(src)
        assert len(program.body) == 4
        assert all(isinstance(n, AnalyzeCommand) for n in program.body)
        targets = [n.target for n in program.body]
        assert targets == ["FILES", "PROCESSES", "NETWORK", "SYSTEM"]

    def test_analyze_unknown_target_raises(self):
        with pytest.raises(ParseError):
            parse("ANALYZE MEMORY")  # MEMORY is not a valid JOCKY keyword here


# ──────────────────────────────────────────────────────────
# 6. BLOCKCHAIN TRACE
# ──────────────────────────────────────────────────────────

class TestBlockchainTrace:
    def test_blockchain_trace(self):
        node = parse_one('BLOCKCHAIN TRACE "0xABC123"')
        assert isinstance(node, BlockchainTraceCommand)
        assert node.address == "0xABC123"

    def test_blockchain_trace_long_address(self):
        addr = "0x" + "a" * 40
        node = parse_one(f'BLOCKCHAIN TRACE "{addr}"')
        assert node.address == addr

    def test_blockchain_trace_location(self):
        node = parse_one('BLOCKCHAIN TRACE "0x1234"')
        assert node.loc.line == 1


# ──────────────────────────────────────────────────────────
# 7. IDENTIFY VASP
# ──────────────────────────────────────────────────────────

class TestIdentifyVasp:
    def test_identify_vasp(self):
        node = parse_one("IDENTIFY VASP")
        assert isinstance(node, IdentifyVaspCommand)

    def test_identify_vasp_location(self):
        src = "CASE \"X\"\nIDENTIFY VASP"
        program = parse(src)
        node = program.body[1]
        assert node.loc.line == 2


# ──────────────────────────────────────────────────────────
# 8. CORRELATE EVIDENCE
# ──────────────────────────────────────────────────────────

class TestCorrelateEvidence:
    def test_correlate_evidence(self):
        node = parse_one("CORRELATE EVIDENCE")
        assert isinstance(node, CorrelateEvidenceCommand)

    def test_correlate_wrong_second_word_raises(self):
        with pytest.raises(ParseError):
            parse("CORRELATE REPORT")


# ──────────────────────────────────────────────────────────
# 9. BUILD commands
# ──────────────────────────────────────────────────────────

class TestBuildCommands:
    def test_build_timeline(self):
        node = parse_one("BUILD TIMELINE")
        assert isinstance(node, BuildTimelineCommand)

    def test_build_attack_graph(self):
        node = parse_one("BUILD ATTACK GRAPH")
        assert isinstance(node, BuildAttackGraphCommand)

    def test_both_build_commands_in_sequence(self):
        src = "BUILD TIMELINE\nBUILD ATTACK GRAPH"
        program = parse(src)
        assert isinstance(program.body[0], BuildTimelineCommand)
        assert isinstance(program.body[1], BuildAttackGraphCommand)

    def test_build_unknown_target_raises(self):
        with pytest.raises(ParseError, match="Expected TIMELINE or ATTACK"):
            parse("BUILD REPORT")

    def test_build_attack_missing_graph_raises(self):
        with pytest.raises(ParseError):
            parse("BUILD ATTACK EVIDENCE")


# ──────────────────────────────────────────────────────────
# 10. Invalid syntax (structural errors)
# ──────────────────────────────────────────────────────────

class TestInvalidSyntax:
    def test_bare_string_raises(self):
        """A string literal on its own is not a valid statement."""
        with pytest.raises(ParseError):
            parse('"hello"')

    def test_trace_missing_suspicious_raises(self):
        with pytest.raises(ParseError):
            parse("TRACE CONNECTIONS")

    def test_trace_missing_connections_raises(self):
        with pytest.raises(ParseError):
            parse("TRACE SUSPICIOUS GRAPH")

    def test_anchor_wrong_word_raises(self):
        with pytest.raises(ParseError):
            parse("ANCHOR TIMELINE")

    def test_generate_wrong_word_raises(self):
        with pytest.raises(ParseError):
            parse("GENERATE TIMELINE")


# ──────────────────────────────────────────────────────────
# 11. Unknown command keyword
# ──────────────────────────────────────────────────────────

class TestUnknownKeyword:
    def test_typo_command_raises_with_suggestion(self):
        with pytest.raises(ParseError) as exc_info:
            parse("ANALYZEE FILES")
        msg = str(exc_info.value)
        assert "ANALYZEE" in msg
        # The error message should list expected commands
        assert "ANALYZE" in msg

    def test_completely_unknown_word_raises(self):
        with pytest.raises(ParseError):
            parse("INVESTIGATE FILES")

    def test_error_carries_correct_line(self):
        src = "CASE \"X\"\nHOST \"Y\"\nBADCOMMAND"
        with pytest.raises(ParseError) as exc_info:
            parse(src)
        assert "Line 3" in str(exc_info.value)


# ──────────────────────────────────────────────────────────
# 12. Missing string argument
# ──────────────────────────────────────────────────────────

class TestMissingStringArgument:
    def test_case_missing_string_raises(self):
        with pytest.raises(ParseError, match="STRING"):
            parse("CASE")

    def test_case_wrong_argument_type_raises(self):
        with pytest.raises(ParseError):
            parse("CASE FILES")   # FILES is a keyword, not a string

    def test_host_missing_string_raises(self):
        with pytest.raises(ParseError, match="STRING"):
            parse("HOST")

    def test_blockchain_trace_missing_string_raises(self):
        with pytest.raises(ParseError, match="STRING"):
            parse("BLOCKCHAIN TRACE")

    def test_blockchain_trace_wrong_arg_raises(self):
        with pytest.raises(ParseError):
            parse("BLOCKCHAIN TRACE REPORT")


# ──────────────────────────────────────────────────────────
# Full program (integration)
# ──────────────────────────────────────────────────────────

class TestFullProgram:
    FULL_SRC = """
// INC-2026-001 Ransomware Investigation
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

    def test_full_program_parses(self):
        program = parse(self.FULL_SRC)
        assert isinstance(program, Program)

    def test_full_program_node_count(self):
        program = parse(self.FULL_SRC)
        assert len(program.body) == 13

    def test_full_program_node_order(self):
        program = parse(self.FULL_SRC)
        expected_types = [
            CaseDeclaration,
            HostDeclaration,
            AnalyzeCommand,
            AnalyzeCommand,
            AnalyzeCommand,
            TraceCommand,
            BlockchainTraceCommand,
            IdentifyVaspCommand,
            CorrelateEvidenceCommand,
            BuildTimelineCommand,
            BuildAttackGraphCommand,
            AnchorEvidenceCommand,
            GenerateReportCommand,
        ]
        for node, expected in zip(program.body, expected_types):
            assert isinstance(node, expected), (
                f"Expected {expected.__name__}, got {type(node).__name__}"
            )

    def test_case_id_extracted(self):
        program = parse(self.FULL_SRC)
        case_node = program.body[0]
        assert isinstance(case_node, CaseDeclaration)
        assert case_node.case_id == "INC-2026-001"

    def test_host_extracted(self):
        program = parse(self.FULL_SRC)
        host_node = program.body[1]
        assert isinstance(host_node, HostDeclaration)
        assert host_node.hostname == "LAB-PC-01"

    def test_blockchain_address_extracted(self):
        program = parse(self.FULL_SRC)
        bc_node = program.body[6]
        assert isinstance(bc_node, BlockchainTraceCommand)
        assert bc_node.address == "0xABC123"
class TestCheckSecurity:
    def test_check_security(self):
        node = parse_one('CHECK SECURITY')
        assert isinstance(node, CheckSecurityCommand)
        assert node.loc.line == 1
        assert node.loc.column == 1

    def test_check_missing_security_raises(self):
        with pytest.raises(ParseError):
            parse('CHECK')

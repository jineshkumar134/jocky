"""
JOCKY Parser
-------------
Converts a flat token list produced by the Lexer into a Program AST.

Grammar (simplified BNF):

    program          ::= statement* EOF
    statement        ::= case_decl
                       | host_decl
                       | analyze_cmd
                       | trace_cmd
                       | blockchain_trace_cmd
                       | identify_vasp_cmd
                       | correlate_evidence_cmd
                       | build_timeline_cmd
                       | build_attack_graph_cmd
                       | anchor_evidence_cmd
                       | generate_report_cmd
                       | register_host_cmd
                       | attach_evidence_cmd

    case_decl               ::= CASE STRING
    host_decl               ::= HOST STRING
    analyze_cmd             ::= ANALYZE ( FILES | PROCESSES | NETWORK | SYSTEM )
    trace_cmd               ::= TRACE SUSPICIOUS CONNECTIONS
    blockchain_trace_cmd    ::= BLOCKCHAIN TRACE STRING
    identify_vasp_cmd       ::= IDENTIFY VASP
    correlate_evidence_cmd  ::= CORRELATE EVIDENCE
    build_timeline_cmd      ::= BUILD TIMELINE
    build_attack_graph_cmd  ::= BUILD ATTACK GRAPH
    anchor_evidence_cmd     ::= ANCHOR EVIDENCE
    verify_evidence_cmd     ::= VERIFY EVIDENCE
    generate_report_cmd     ::= GENERATE REPORT
    assess_risk_cmd         ::= ASSESS RISK
    check_security_cmd      ::= CHECK SECURITY
    register_host_cmd       ::= REGISTER HOST STRING
    attach_evidence_cmd     ::= ATTACH EVIDENCE

The parser is a hand-written recursive descent parser.  Every ``_parse_*``
method is responsible for consuming exactly the tokens it needs and raising
a clear ParseError if they are missing or wrong.
"""

from __future__ import annotations

from typing import List, Optional

from compiler.lexer import Token, TokenType
from compiler.ast import (
    ASTNode,
    SourceLocation,
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
    AssessRiskCommand,
    AnchorEvidenceCommand,
    VerifyEvidenceCommand,
    GenerateReportCommand,
    CheckSecurityCommand,
    RegisterHostCommand,
    AttachEvidenceCommand,
    ResearchCommand,
)


# ──────────────────────────────────────────────────────────
# ParseError
# ──────────────────────────────────────────────────────────

class ParseError(Exception):
    """Raised when the parser encounters a syntax error.

    Carries the source position so the CLI can show a helpful message.
    """
    def __init__(self, message: str, line: int, column: int) -> None:
        super().__init__(f"Line {line}, Column {column}: {message}")
        self.line   = line
        self.column = column


# ──────────────────────────────────────────────────────────
# Parser
# ──────────────────────────────────────────────────────────

# The set of TokenTypes that may legally start a statement,
# used in the "unknown command" error message.
_STATEMENT_STARTERS = {
    TokenType.CASE,
    TokenType.HOST,
    TokenType.ANALYZE,
    TokenType.TRACE,
    TokenType.BLOCKCHAIN,
    TokenType.IDENTIFY,
    TokenType.CORRELATE,
    TokenType.BUILD,
    TokenType.ANCHOR,
    TokenType.VERIFY,
    TokenType.GENERATE,
    TokenType.ASSESS,
    TokenType.CHECK,
    TokenType.REGISTER,
    TokenType.ATTACH,
    TokenType.RESEARCH,
}

_STARTER_NAMES = [
    "CASE", "HOST", "ANALYZE", "TRACE", "BLOCKCHAIN",
    "IDENTIFY", "CORRELATE", "BUILD", "ANCHOR", "VERIFY", "GENERATE",
    "ASSESS", "CHECK", "REGISTER", "ATTACH", "RESEARCH",
]


class Parser:
    """
    Recursive-descent parser for the JOCKY language.

    Usage::

        tokens = Lexer(source).tokenize()
        program = Parser(tokens).parse()
    """

    def __init__(self, tokens: List[Token]) -> None:
        self._tokens = tokens
        self._pos    = 0

    # ── public ─────────────────────────────────────────────

    def parse(self) -> Program:
        body: list[ASTNode] = []
        while not self._at_end():
            stmt = self._parse_statement()
            body.append(stmt)
        eof = self._current()
        return Program(
            loc=SourceLocation(eof.line, eof.column),
            body=tuple(body),
        )

    # ── token navigation ───────────────────────────────────

    def _current(self) -> Token:
        return self._tokens[self._pos]

    def _peek_type(self) -> TokenType:
        return self._current().type

    def _at_end(self) -> bool:
        return self._peek_type() == TokenType.EOF

    def _advance(self) -> Token:
        tok = self._current()
        if not self._at_end():
            self._pos += 1
        return tok

    def _expect(self, *types: TokenType) -> Token:
        """Consume the current token if it is one of *types*, else error."""
        tok = self._current()
        if tok.type not in types:
            expected = " or ".join(t.name for t in types)
            raise ParseError(
                f"Expected {expected} but found {tok.value!r}",
                tok.line, tok.column,
            )
        return self._advance()

    def _loc(self) -> SourceLocation:
        tok = self._current()
        return SourceLocation(tok.line, tok.column)

    # ── top-level dispatch ─────────────────────────────────

    def _parse_statement(self) -> ASTNode:
        tok  = self._current()
        tt   = tok.type

        if tt == TokenType.CASE:
            return self._parse_case()
        if tt == TokenType.HOST:
            return self._parse_host()
        if tt == TokenType.ANALYZE:
            return self._parse_analyze()
        if tt == TokenType.TRACE:
            return self._parse_trace()
        if tt == TokenType.BLOCKCHAIN:
            return self._parse_blockchain_trace()
        if tt == TokenType.IDENTIFY:
            return self._parse_identify_vasp()
        if tt == TokenType.CORRELATE:
            return self._parse_correlate_evidence()
        if tt == TokenType.BUILD:
            return self._parse_build()
        if tt == TokenType.ANCHOR:
            return self._parse_anchor_evidence()
        if tt == TokenType.VERIFY:
            return self._parse_verify_evidence()
        if tt == TokenType.GENERATE:
            return self._parse_generate_report()
        if tt == TokenType.ASSESS:
            return self._parse_assess_risk()
        if tt == TokenType.CHECK:
            return self._parse_check_security()
        if tt == TokenType.REGISTER:
            return self._parse_register_host()
        if tt == TokenType.ATTACH:
            return self._parse_attach_evidence()
        if tt == TokenType.RESEARCH:
            return self._parse_research()

        # Unknown token
        expected_list = ", ".join(_STARTER_NAMES)
        if tt == TokenType.UNKNOWN:
            raise ParseError(
                f"Unknown command {tok.value!r}.\n"
                f"  Expected one of: {expected_list}",
                tok.line, tok.column,
            )
        raise ParseError(
            f"Unexpected token {tok.value!r} ({tt.name}).\n"
            f"  Expected one of: {expected_list}",
            tok.line, tok.column,
        )

    # ── individual statement parsers ───────────────────────

    def _parse_case(self) -> CaseDeclaration:
        """CASE STRING"""
        loc = self._loc()
        self._expect(TokenType.CASE)
        str_tok = self._expect(TokenType.STRING)
        return CaseDeclaration(loc=loc, case_id=_unquote(str_tok))

    def _parse_host(self) -> HostDeclaration:
        """HOST STRING"""
        loc = self._loc()
        self._expect(TokenType.HOST)
        str_tok = self._expect(TokenType.STRING)
        return HostDeclaration(loc=loc, hostname=_unquote(str_tok))

    def _parse_analyze(self) -> AnalyzeCommand:
        """ANALYZE ( FILES | PROCESSES | NETWORK | SYSTEM )"""
        loc = self._loc()
        self._expect(TokenType.ANALYZE)
        target_tok = self._expect(
            TokenType.FILES, TokenType.PROCESSES, TokenType.NETWORK, TokenType.SYSTEM
        )
        return AnalyzeCommand(loc=loc, target=target_tok.value.upper())

    def _parse_trace(self) -> TraceCommand:
        """TRACE SUSPICIOUS CONNECTIONS"""
        loc = self._loc()
        self._expect(TokenType.TRACE)
        self._expect(TokenType.SUSPICIOUS)
        self._expect(TokenType.CONNECTIONS)
        return TraceCommand(loc=loc)

    def _parse_blockchain_trace(self) -> BlockchainTraceCommand:
        """BLOCKCHAIN TRACE STRING"""
        loc = self._loc()
        self._expect(TokenType.BLOCKCHAIN)
        self._expect(TokenType.TRACE)
        str_tok = self._expect(TokenType.STRING)
        return BlockchainTraceCommand(loc=loc, address=_unquote(str_tok))

    def _parse_identify_vasp(self) -> IdentifyVaspCommand:
        """IDENTIFY VASP"""
        loc = self._loc()
        self._expect(TokenType.IDENTIFY)
        self._expect(TokenType.VASP)
        return IdentifyVaspCommand(loc=loc)

    def _parse_correlate_evidence(self) -> CorrelateEvidenceCommand:
        """CORRELATE EVIDENCE"""
        loc = self._loc()
        self._expect(TokenType.CORRELATE)
        self._expect(TokenType.EVIDENCE)
        return CorrelateEvidenceCommand(loc=loc)

    def _parse_build(self) -> ASTNode:
        """BUILD TIMELINE | BUILD ATTACK GRAPH"""
        loc = self._loc()
        self._expect(TokenType.BUILD)
        next_tok = self._current()

        if next_tok.type == TokenType.TIMELINE:
            self._advance()
            return BuildTimelineCommand(loc=loc)

        if next_tok.type == TokenType.ATTACK:
            self._advance()
            self._expect(TokenType.GRAPH)
            return BuildAttackGraphCommand(loc=loc)

        raise ParseError(
            f"Expected TIMELINE or ATTACK after BUILD, "
            f"but found {next_tok.value!r}",
            next_tok.line, next_tok.column,
        )

    def _parse_anchor_evidence(self) -> AnchorEvidenceCommand:
        """ANCHOR EVIDENCE"""
        loc = self._loc()
        self._expect(TokenType.ANCHOR)
        self._expect(TokenType.EVIDENCE)
        return AnchorEvidenceCommand(loc=loc)

    def _parse_verify_evidence(self) -> VerifyEvidenceCommand:
        """VERIFY EVIDENCE"""
        loc = self._loc()
        self._expect(TokenType.VERIFY)
        self._expect(TokenType.EVIDENCE)
        return VerifyEvidenceCommand(loc=loc)

    def _parse_generate_report(self) -> GenerateReportCommand:
        """GENERATE REPORT"""
        loc = self._loc()
        self._expect(TokenType.GENERATE)
        self._expect(TokenType.REPORT)
        return GenerateReportCommand(loc=loc)

    def _parse_assess_risk(self) -> AssessRiskCommand:
        """ASSESS RISK"""
        loc = self._loc()
        self._expect(TokenType.ASSESS)
        self._expect(TokenType.RISK)
        return AssessRiskCommand(loc=loc)

    def _parse_check_security(self) -> CheckSecurityCommand:
        """CHECK SECURITY"""
        loc = self._loc()
        self._expect(TokenType.CHECK)
        self._expect(TokenType.SECURITY)
        return CheckSecurityCommand(loc=loc)

    def _parse_register_host(self) -> RegisterHostCommand:
        """REGISTER HOST STRING"""
        loc = self._loc()
        self._expect(TokenType.REGISTER)
        self._expect(TokenType.HOST)
        str_tok = self._expect(TokenType.STRING)
        return RegisterHostCommand(loc=loc, hostname=_unquote(str_tok))

    def _parse_attach_evidence(self) -> AttachEvidenceCommand:
        """ATTACH EVIDENCE"""
        loc = self._loc()
        self._expect(TokenType.ATTACH)
        self._expect(TokenType.EVIDENCE)
        return AttachEvidenceCommand(loc=loc)

    def _parse_research(self) -> ResearchCommand:
        """RESEARCH STRING"""
        loc = self._loc()
        self._expect(TokenType.RESEARCH)
        str_tok = self._expect(TokenType.STRING)
        return ResearchCommand(loc=loc, scenario_id=_unquote(str_tok))


# ──────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────

def _unquote(tok: Token) -> str:
    """Strip surrounding double-quotes from a STRING token's value."""
    v = tok.value
    if v.startswith('"') and v.endswith('"'):
        return v[1:-1]
    return v

"""
tests/test_lexer.py
-------------------
Unit tests for the JOCKY lexer.
"""

import pytest
from compiler.lexer import Lexer, LexError, Token, TokenType


def lex(src: str) -> list[Token]:
    """Convenience: lex and strip the trailing EOF token."""
    return [t for t in Lexer(src).tokenize() if t.type != TokenType.EOF]


# ──────────────────────────────────────────────────────────
# Keyword recognition
# ──────────────────────────────────────────────────────────

class TestKeywords:
    def test_all_keywords_recognised(self):
        pairs = [
            ("CASE",        TokenType.CASE),
            ("HOST",        TokenType.HOST),
            ("ANALYZE",     TokenType.ANALYZE),
            ("TRACE",       TokenType.TRACE),
            ("BLOCKCHAIN",  TokenType.BLOCKCHAIN),
            ("IDENTIFY",    TokenType.IDENTIFY),
            ("CORRELATE",   TokenType.CORRELATE),
            ("BUILD",       TokenType.BUILD),
            ("ANCHOR",      TokenType.ANCHOR),
            ("GENERATE",    TokenType.GENERATE),
            ("FILES",       TokenType.FILES),
            ("PROCESSES",   TokenType.PROCESSES),
            ("NETWORK",     TokenType.NETWORK),
            ("SYSTEM",      TokenType.SYSTEM),
            ("SUSPICIOUS",  TokenType.SUSPICIOUS),
            ("CONNECTIONS", TokenType.CONNECTIONS),
            ("VASP",        TokenType.VASP),
            ("EVIDENCE",    TokenType.EVIDENCE),
            ("TIMELINE",    TokenType.TIMELINE),
            ("ATTACK",      TokenType.ATTACK),
            ("CHECK",        TokenType.CHECK),
            ("SECURITY",     TokenType.SECURITY),

        ]
        for word, expected_type in pairs:
            tokens = lex(word)
            assert len(tokens) == 1, f"Expected 1 token for {word!r}"
            assert tokens[0].type == expected_type, (
                f"{word!r} should be {expected_type}, got {tokens[0].type}"
            )


# ──────────────────────────────────────────────────────────
# String literals
# ──────────────────────────────────────────────────────────

class TestStringLiterals:
    def test_simple_string(self):
        tokens = lex('"INC-2026-001"')
        assert len(tokens) == 1
        assert tokens[0].type  == TokenType.STRING
        assert tokens[0].value == '"INC-2026-001"'

    def test_string_with_internal_spaces(self):
        tokens = lex('"hello world"')
        assert tokens[0].type  == TokenType.STRING
        assert tokens[0].value == '"hello world"'

    def test_string_with_escaped_quote(self):
        tokens = lex(r'"he said \"hi\""')
        assert tokens[0].type  == TokenType.STRING

    def test_unterminated_string_raises(self):
        with pytest.raises(LexError, match="Unterminated string"):
            lex('"INC-2026-001')

    def test_newline_in_string_raises(self):
        with pytest.raises(LexError, match="Newline inside string"):
            lex('"abc\ndef"')


# ──────────────────────────────────────────────────────────
# Comments and whitespace
# ──────────────────────────────────────────────────────────

class TestCommentsAndWhitespace:
    def test_line_comment_skipped(self):
        tokens = lex("// this is a comment\nCASE")
        assert len(tokens) == 1
        assert tokens[0].type == TokenType.CASE

    def test_inline_comment_after_keyword(self):
        tokens = lex("GENERATE  // generate the report\nREPORT")
        types = [t.type for t in tokens]
        assert types == [TokenType.GENERATE, TokenType.REPORT]

    def test_blank_lines_ignored(self):
        tokens = lex("\n\n\nCASE\n\n")
        assert len(tokens) == 1


# ──────────────────────────────────────────────────────────
# Source positions
# ──────────────────────────────────────────────────────────

class TestSourcePositions:
    def test_first_token_position(self):
        tokens = lex("CASE")
        assert tokens[0].line   == 1
        assert tokens[0].column == 1

    def test_second_line_token(self):
        tokens = lex("CASE\nHOST")
        host_tok = tokens[1]
        assert host_tok.line   == 2
        assert host_tok.column == 1

    def test_column_tracking(self):
        tokens = lex("CASE HOST")
        host_tok = tokens[1]
        assert host_tok.column == 6  # "CASE " = 5 chars → HOST starts at col 6

    def test_string_position(self):
        tokens = lex('CASE "INC-2026-001"')
        str_tok = tokens[1]
        assert str_tok.type   == TokenType.STRING
        assert str_tok.column == 6


# ──────────────────────────────────────────────────────────
# Unknown words
# ──────────────────────────────────────────────────────────

class TestUnknownWords:
    def test_unknown_word_emits_unknown_token(self):
        tokens = lex("ANALYZEE")
        assert tokens[0].type  == TokenType.UNKNOWN
        assert tokens[0].value == "ANALYZEE"

    def test_unexpected_char_raises(self):
        with pytest.raises(LexError, match="Unexpected character"):
            lex("@CASE")


# ──────────────────────────────────────────────────────────
# EOF
# ──────────────────────────────────────────────────────────

class TestEOF:
    def test_empty_source_produces_only_eof(self):
        tokens = Lexer("").tokenize()
        assert len(tokens) == 1
        assert tokens[0].type == TokenType.EOF

    def test_eof_always_last(self):
        tokens = Lexer("CASE").tokenize()
        assert tokens[-1].type == TokenType.EOF

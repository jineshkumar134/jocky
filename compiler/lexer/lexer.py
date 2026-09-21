"""
JOCKY Lexer
-----------
Tokenizes a .jky source string into a flat list of Token objects.

Responsibilities:
  - Recognise keyword tokens (CASE, HOST, ANALYZE, TRACE, BLOCKCHAIN, …)
  - Recognise quoted-string literals
  - Skip line comments (// …) and whitespace
  - Track line + column for every token so the parser can produce useful errors
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import List


# ──────────────────────────────────────────────────────────
# Token types
# ──────────────────────────────────────────────────────────

class TokenType(Enum):
    # ── literals ───────────────────────────────────────────
    STRING = auto()        # "…"

    # ── keywords ───────────────────────────────────────────
    CASE       = auto()
    HOST       = auto()
    ANALYZE    = auto()
    TRACE      = auto()
    BLOCKCHAIN = auto()
    IDENTIFY   = auto()
    CORRELATE  = auto()
    BUILD      = auto()
    ANCHOR     = auto()
    GENERATE   = auto()
    ASSESS     = auto()
    VERIFY     = auto()
    CHECK      = auto()
    SECURITY   = auto()
    REGISTER   = auto()
    ATTACH     = auto()
    RESEARCH   = auto()

    # ── command-argument keywords ──────────────────────────
    FILES       = auto()
    PROCESSES   = auto()
    NETWORK     = auto()
    SYSTEM      = auto()
    SUSPICIOUS  = auto()
    CONNECTIONS = auto()
    VASP        = auto()
    EVIDENCE    = auto()
    TIMELINE    = auto()
    ATTACK      = auto()
    GRAPH       = auto()
    REPORT      = auto()
    RISK        = auto()

    # ── structural ─────────────────────────────────────────
    EOF        = auto()
    UNKNOWN    = auto()    # lexed but unrecognised bare word — parser will error


# maps bare words → their TokenType
_KEYWORD_MAP: dict[str, TokenType] = {
    "CASE":        TokenType.CASE,
    "HOST":        TokenType.HOST,
    "ANALYZE":     TokenType.ANALYZE,
    "TRACE":       TokenType.TRACE,
    "BLOCKCHAIN":  TokenType.BLOCKCHAIN,
    "IDENTIFY":    TokenType.IDENTIFY,
    "CORRELATE":   TokenType.CORRELATE,
    "BUILD":       TokenType.BUILD,
    "ANCHOR":      TokenType.ANCHOR,
    "GENERATE":    TokenType.GENERATE,
    "ASSESS":      TokenType.ASSESS,
    "VERIFY":      TokenType.VERIFY,
    "CHECK":       TokenType.CHECK,
    "SECURITY":    TokenType.SECURITY,
    "REGISTER":    TokenType.REGISTER,
    "ATTACH":      TokenType.ATTACH,
    "RESEARCH":    TokenType.RESEARCH,
    "FILES":       TokenType.FILES,
    "PROCESSES":   TokenType.PROCESSES,
    "NETWORK":     TokenType.NETWORK,
    "SYSTEM":      TokenType.SYSTEM,
    "SUSPICIOUS":  TokenType.SUSPICIOUS,
    "CONNECTIONS": TokenType.CONNECTIONS,
    "VASP":        TokenType.VASP,
    "EVIDENCE":    TokenType.EVIDENCE,
    "TIMELINE":    TokenType.TIMELINE,
    "ATTACK":      TokenType.ATTACK,
    "GRAPH":       TokenType.GRAPH,
    "REPORT":      TokenType.REPORT,
    "RISK":        TokenType.RISK,
}



# ──────────────────────────────────────────────────────────
# Token
# ──────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Token:
    type:    TokenType
    value:   str          # raw text (string literals include the quotes)
    line:    int          # 1-based
    column:  int          # 1-based, start of token


# ──────────────────────────────────────────────────────────
# LexError
# ──────────────────────────────────────────────────────────

class LexError(Exception):
    def __init__(self, message: str, line: int, column: int) -> None:
        super().__init__(f"Line {line}, Column {column}: {message}")
        self.line   = line
        self.column = column


# ──────────────────────────────────────────────────────────
# Lexer
# ──────────────────────────────────────────────────────────

# A "word" token: one or more uppercase letters, digits, or underscores
_WORD_RE  = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_SPACE_RE = re.compile(r"[ \t]+")


class Lexer:
    """
    Single-pass hand-written lexer.

    Usage::

        tokens = Lexer(source).tokenize()
    """

    def __init__(self, source: str) -> None:
        self._src    = source
        self._pos    = 0          # current character index
        self._line   = 1
        self._col    = 1
        self._tokens: List[Token] = []

    # ── public ─────────────────────────────────────────────

    def tokenize(self) -> List[Token]:
        """Return the full token list (including a final EOF token)."""
        while self._pos < len(self._src):
            self._scan_next()
        self._emit(TokenType.EOF, "")
        return self._tokens

    # ── private helpers ────────────────────────────────────

    def _peek(self) -> str:
        return self._src[self._pos] if self._pos < len(self._src) else ""

    def _advance(self) -> str:
        ch = self._src[self._pos]
        self._pos += 1
        if ch == "\n":
            self._line += 1
            self._col = 1
        else:
            self._col += 1
        return ch

    def _emit(self, tt: TokenType, value: str, col_override: int | None = None) -> None:
        col = col_override if col_override is not None else self._col
        self._tokens.append(Token(tt, value, self._line, col))

    # ── scanning ───────────────────────────────────────────

    def _scan_next(self) -> None:
        start_line = self._line
        start_col  = self._col
        ch         = self._peek()

        # whitespace (spaces & tabs)
        if ch in (" ", "\t"):
            while self._peek() in (" ", "\t"):
                self._advance()
            return

        # newline
        if ch == "\n":
            self._advance()
            return

        # line comment: // …
        if ch == "/" and self._pos + 1 < len(self._src) and self._src[self._pos + 1] == "/":
            while self._peek() not in ("\n", ""):
                self._advance()
            return

        # quoted string literal
        if ch == '"':
            self._scan_string(start_line, start_col)
            return

        # word / keyword
        if ch.isalpha() or ch == "_":
            self._scan_word(start_line, start_col)
            return

        # anything else is a lex error
        raise LexError(f"Unexpected character: {ch!r}", start_line, start_col)

    def _scan_string(self, line: int, col: int) -> None:
        """Consume a double-quoted string; supports \\\" escape."""
        self._advance()  # opening "
        buf = []
        while True:
            ch = self._peek()
            if ch == "":
                raise LexError("Unterminated string literal", line, col)
            if ch == "\n":
                raise LexError("Newline inside string literal", line, col)
            if ch == "\\":
                self._advance()
                esc = self._peek()
                if esc == "":
                    raise LexError("Unterminated escape sequence", line, col)
                if esc == '"':
                    buf.append('"')
                elif esc == "\\":
                    buf.append("\\")
                elif esc == "n":
                    buf.append("\n")
                else:
                    buf.append("\\")
                    buf.append(esc)
                self._advance()
            elif ch == '"':
                self._advance()  # closing "
                raw = '"' + "".join(buf) + '"'
                self._tokens.append(Token(TokenType.STRING, raw, line, col))
                return
            else:
                buf.append(ch)
                self._advance()

    def _scan_word(self, line: int, col: int) -> None:
        buf = []
        while self._peek().isalnum() or self._peek() == "_":
            buf.append(self._advance())
        word = "".join(buf)
        tt   = _KEYWORD_MAP.get(word.upper(), TokenType.UNKNOWN)
        # store the word as-is; for keywords normalise to upper so
        # the parser can rely on the value being the keyword text.
        self._tokens.append(Token(tt, word, line, col))

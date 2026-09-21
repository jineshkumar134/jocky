"""
JOCKY Compiler Facade
---------------------
High-level entry point that wires together:
  Lexer → Parser → IR lowering → LLVM IR generation.

Usage (Python API)::

    from compiler.compiler import compile_source, CompileResult

    result = compile_source(source_text, source_name="hello.jky", emit_llvm=True)
    if result.ok:
        print(result.ir)         # InvestigationIR
        print(result.llvm_ir)    # LLVM IR text
    else:
        for err in result.errors:
            print(err)

Pipeline
--------
  Source text
    → Lexer        (compiler.lexer)
    → Token list
    → Parser       (compiler.parser)
    → AST Program
    → IR lowering  (compiler.ir.lowering)
    → InvestigationIR
    → LLVM Backend (compiler.llvm.backend)
    → LLVM IR text
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from compiler.lexer    import Lexer, LexError, Token
from compiler.parser   import Parser, ParseError
from compiler.ast      import Program
from compiler.ir       import lower, LoweringResult, InvestigationIR
from compiler.llvm     import generate_llvm, LLVMResult


@dataclass
class CompileResult:
    """Result returned by :func:`compile_source`."""
    ok:          bool
    tokens:      List[Token]              = field(default_factory=list)
    program:     Optional[Program]        = None
    ir:          Optional[InvestigationIR] = None
    llvm_ir:     Optional[str]            = None
    errors:      List[str]                = field(default_factory=list)
    warnings:    List[str]                = field(default_factory=list)


def compile_source(
    source: str,
    source_name: str = "<source>",
    skip_ir: bool = False,
    emit_llvm: bool = False,
) -> CompileResult:
    """
    Run the full JOCKY compilation pipeline on *source* text.

    Parameters
    ----------
    source:
        Raw .jky source text.
    source_name:
        Used in error messages to identify the file.
    skip_ir:
        When ``True`` the IR lowering pass is skipped and only
        tokens + AST are returned.
    emit_llvm:
        When ``True``, compiles JOCKY IR down to verified LLVM IR text.

    Returns a :class:`CompileResult` with:
      - ``.ok``       – True only when all enabled phases succeeded
      - ``.tokens``   – token list (empty on lex error)
      - ``.program``  – the Program AST (None on lex/parse error)
      - ``.ir``       – the InvestigationIR (None on any error, or if skip_ir)
      - ``.llvm_ir``  – the verified LLVM IR string (if emit_llvm is True)
      - ``.errors``   – list of human-readable error messages
      - ``.warnings`` – list of non-fatal notices
    """
    # ── Lex ────────────────────────────────────────────────
    try:
        tokens = Lexer(source).tokenize()
    except LexError as exc:
        return CompileResult(
            ok=False,
            errors=[f"Lex error in {source_name}: {exc}"],
        )

    # ── Parse ───────────────────────────────────────────────
    try:
        program = Parser(tokens).parse()
    except ParseError as exc:
        return CompileResult(
            ok=False,
            tokens=tokens,
            errors=[f"Parse error in {source_name}: {exc}"],
        )

    if skip_ir:
        return CompileResult(ok=True, tokens=tokens, program=program)

    # ── IR Lowering ─────────────────────────────────────────
    lowering = lower(program)
    if not lowering.ok:
        return CompileResult(
            ok=False,
            tokens=tokens,
            program=program,
            errors=[
                f"IR lowering error in {source_name}: {e}"
                for e in lowering.errors
            ],
            warnings=lowering.warnings,
        )

    ir = lowering.ir

    # ── LLVM IR Generation (Optional or if requested) ───────
    llvm_text = None
    if emit_llvm and ir is not None:
        llvm_res = generate_llvm(ir)
        if not llvm_res.ok:
            return CompileResult(
                ok=False,
                tokens=tokens,
                program=program,
                ir=ir,
                errors=[
                    f"LLVM generation error in {source_name}: {e}"
                    for e in llvm_res.errors
                ],
                warnings=lowering.warnings,
            )
        llvm_text = llvm_res.ir_text

    return CompileResult(
        ok=True,
        tokens=tokens,
        program=program,
        ir=ir,
        llvm_ir=llvm_text,
        warnings=lowering.warnings,
    )

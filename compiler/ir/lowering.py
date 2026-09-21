"""
JOCKY AST → IR Lowering Pass
-----------------------------
Translates a validated AST ``Program`` into an ``InvestigationIR``.

Responsibilities
----------------
1. **Extract declarations** — pull ``CASE`` and ``HOST`` statements out of
   the program body and construct the top-level ``InvestigationIR`` wrapper.
2. **Translate commands** — convert each command AST node into its
   corresponding typed ``IROperation`` node.
3. **Preserve source positions** — carry source lines from AST nodes into
   the IR so runtime errors remain traceable.
4. **Enforce semantics**:
   - Exactly one ``CASE`` declaration required.
   - Exactly one ``HOST`` declaration required.
   - Duplicate declarations are reported as errors.
   - Unknown AST nodes emit a warning and are skipped.

Error handling
--------------
The lowerer collects all errors rather than failing on the first one,
providing a complete diagnostic report in a single pass.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from compiler.ast.nodes import (
    ASTNode,
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
from compiler.ir.nodes import (
    InvestigationIR,
    HostTarget,
    IROperation,
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
    AssessRiskOp,
    AnchorEvidenceOp,
    VerifyEvidenceOp,
    GenerateReportOp,
    CheckSecurityOp,
    RegisterHostOp,
    AttachEvidenceOp,
    ResearchOp,
)


# ──────────────────────────────────────────────────────────
# Result object
# ──────────────────────────────────────────────────────────

class LoweringError(Exception):
    """Raised when lowering fails and the caller wants an exception."""
    def __init__(self, errors: List[str]) -> None:
        super().__init__("\n".join(errors))
        self.errors = errors


@dataclass
class LoweringResult:
    """Outcome of lowering an AST to IR."""
    ok:       bool
    ir:       Optional[InvestigationIR]      = None
    errors:   List[str]                      = field(default_factory=list)
    warnings: List[str]                      = field(default_factory=list)


# ──────────────────────────────────────────────────────────
# Lowering pass
# ──────────────────────────────────────────────────────────

class ASTToIR:
    """
    Single-pass AST → IR lowerer.

    Usage::

        result = ASTToIR(program).lower()
    """

    def __init__(self, program: Program) -> None:
        self._program  = program
        self._errors:   List[str] = []
        self._warnings: List[str] = []

    # ── public ─────────────────────────────────────────────

    def lower(self) -> LoweringResult:
        case_decl: Optional[CaseDeclaration] = None
        host_decl: Optional[HostDeclaration] = None
        operations: List[IROperation]        = []

        # ── First pass: extract declarations and operations ─
        for node in self._program.body:
            if isinstance(node, CaseDeclaration):
                if case_decl is not None:
                    self._err(
                        f"Duplicate CASE declaration at line {node.loc.line} "
                        f"(first was at line {case_decl.loc.line})"
                    )
                else:
                    case_decl = node

            elif isinstance(node, HostDeclaration):
                if host_decl is not None:
                    self._err(
                        f"Duplicate HOST declaration at line {node.loc.line} "
                        f"(first was at line {host_decl.loc.line})"
                    )
                else:
                    host_decl = node

            else:
                op = self._lower_operation(node)
                if op is not None:
                    operations.append(op)

        # ── Validate required declarations ──────────────────
        if case_decl is None:
            self._err("Missing required CASE declaration")
        if host_decl is None:
            self._err("Missing required HOST declaration")

        # ── Return early if there are errors ────────────────
        if self._errors:
            return LoweringResult(
                ok=False,
                errors=self._errors,
                warnings=self._warnings,
            )

        # ── Build IR ────────────────────────────────────────
        assert case_decl is not None   # mypy / type narrowing
        assert host_decl is not None

        ir = InvestigationIR(
            case_id=case_decl.case_id,
            host=HostTarget(
                hostname=host_decl.hostname,
                source_line=host_decl.loc.line,
            ),
            operations=operations,
            source_line=case_decl.loc.line,
        )

        return LoweringResult(
            ok=True,
            ir=ir,
            errors=self._errors,
            warnings=self._warnings,
        )

    # ── private ─────────────────────────────────────────────

    def _err(self, msg: str) -> None:
        self._errors.append(msg)

    def _warn(self, msg: str) -> None:
        self._warnings.append(msg)

    def _lower_operation(self, node: ASTNode) -> Optional[IROperation]:
        """Map one AST command node to an IR operation.

        Returns ``None`` and emits a warning for unrecognised node types
        (future-proofing for when new AST nodes are added before the
        lowering pass is updated).
        """
        line = node.loc.line

        if isinstance(node, AnalyzeCommand):
            return self._lower_analyze(node, line)

        if isinstance(node, TraceCommand):
            return TraceConnectionsOp(source_line=line)

        if isinstance(node, BlockchainTraceCommand):
            return BlockchainTraceOp(
                wallet=node.address,
                chain=_infer_chain(node.address),
                source_line=line,
            )

        if isinstance(node, IdentifyVaspCommand):
            return IdentifyVaspOp(source_line=line)

        if isinstance(node, CorrelateEvidenceCommand):
            return CorrelateEvidenceOp(source_line=line)

        if isinstance(node, BuildTimelineCommand):
            return BuildTimelineOp(source_line=line)

        if isinstance(node, BuildAttackGraphCommand):
            return BuildAttackGraphOp(source_line=line)

        if isinstance(node, AssessRiskCommand):
            return AssessRiskOp(source_line=line)

        if isinstance(node, AnchorEvidenceCommand):
            return AnchorEvidenceOp(source_line=line)

        if isinstance(node, VerifyEvidenceCommand):
            return VerifyEvidenceOp(source_line=line)

        if isinstance(node, GenerateReportCommand):
            return GenerateReportOp(source_line=line)

        if isinstance(node, CheckSecurityCommand):
            return CheckSecurityOp(source_line=line)

        if isinstance(node, RegisterHostCommand):
            return RegisterHostOp(hostname=node.hostname, source_line=line)

        if isinstance(node, AttachEvidenceCommand):
            return AttachEvidenceOp(source_line=line)

        if isinstance(node, ResearchCommand):
            return ResearchOp(scenario_id=node.scenario_id, source_line=line)

        # Unknown node — warn instead of crashing so the pipeline stays robust
        self._warn(
            f"Unknown AST node type {type(node).__name__!r} at line {line} "
            f"— skipped during lowering"
        )
        return None

    def _lower_analyze(
        self, node: AnalyzeCommand, line: int
    ) -> Optional[IROperation]:
        target = node.target.upper()
        if target == "FILES":
            return AnalyzeFilesOp(source_line=line)
        if target == "PROCESSES":
            return AnalyzeProcessesOp(source_line=line)
        if target == "NETWORK":
            return AnalyzeNetworkOp(source_line=line)
        if target == "SYSTEM":
            return AnalyzeSystemOp(source_line=line)
        # This branch should never be reached if the parser is correct.
        self._err(
            f"Invalid ANALYZE target {target!r} at line {line}; "
            f"expected FILES, PROCESSES, NETWORK, or SYSTEM"
        )
        return None


# ──────────────────────────────────────────────────────────
# Module-level convenience function
# ──────────────────────────────────────────────────────────

def lower(program: Program) -> LoweringResult:
    """Lower *program* (an AST ``Program``) to ``InvestigationIR``.

    This is the preferred public API for the lowering pass.

    Returns a :class:`LoweringResult` that always contains either a
    valid ``ir`` or a non-empty ``errors`` list.
    """
    return ASTToIR(program).lower()


# ──────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────

def _infer_chain(address: str) -> str:
    """Heuristically determine the target blockchain from the address string.

    Phase 2 only recognises EVM addresses (``0x`` prefix).  Future phases
    will handle Solana base-58, Bitcoin bech32, etc.
    """
    if address.lower().startswith("0x"):
        return "ethereum"
    return "unknown"

"""
JOCKY Abstract Syntax Tree node definitions.
---------------------------------------------
Each node is a frozen dataclass so it is:
  - safe to hash / compare in tests
  - impossible to mutate after construction (which matters for later phases)

Visitor pattern support is provided via the ASTVisitor base class.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Any


# ──────────────────────────────────────────────────────────
# Position information
# ──────────────────────────────────────────────────────────

@dataclass(frozen=True)
class SourceLocation:
    """Carries the original source position of a node."""
    line:   int
    column: int

    def __str__(self) -> str:
        return f"line {self.line}, col {self.column}"


# ──────────────────────────────────────────────────────────
# Base node
# ──────────────────────────────────────────────────────────

@dataclass(frozen=True)
class ASTNode:
    """Abstract base for every AST node.

    Every node records where it appeared in the source so that later
    phases (IR gen, runtime errors) can point back to the .jky file.
    """
    loc: SourceLocation


# ──────────────────────────────────────────────────────────
# Leaf / argument nodes
# ──────────────────────────────────────────────────────────

@dataclass(frozen=True)
class StringArg(ASTNode):
    """A quoted-string argument, e.g. "INC-2026-001".

    ``value`` is the *unquoted* content.
    """
    value: str


# ──────────────────────────────────────────────────────────
# Top-level declaration nodes
# ──────────────────────────────────────────────────────────

@dataclass(frozen=True)
class CaseDeclaration(ASTNode):
    """CASE "case-id"

    Declares the investigation case identifier.
    """
    case_id: str   # unquoted string value


@dataclass(frozen=True)
class HostDeclaration(ASTNode):
    """HOST "hostname"

    Declares the host under investigation.
    """
    hostname: str  # unquoted string value


# ──────────────────────────────────────────────────────────
# Command nodes
# ──────────────────────────────────────────────────────────

@dataclass(frozen=True)
class AnalyzeCommand(ASTNode):
    """ANALYZE <target>

    target is one of: FILES | PROCESSES | NETWORK
    """
    target: str    # "FILES" | "PROCESSES" | "NETWORK"


@dataclass(frozen=True)
class TraceCommand(ASTNode):
    """TRACE SUSPICIOUS CONNECTIONS"""
    pass


@dataclass(frozen=True)
class BlockchainTraceCommand(ASTNode):
    """BLOCKCHAIN TRACE "<address>"

    Traces a blockchain address / transaction hash.
    """
    address: str   # unquoted


@dataclass(frozen=True)
class IdentifyVaspCommand(ASTNode):
    """IDENTIFY VASP"""
    pass


@dataclass(frozen=True)
class CorrelateEvidenceCommand(ASTNode):
    """CORRELATE EVIDENCE"""
    pass


@dataclass(frozen=True)
class BuildTimelineCommand(ASTNode):
    """BUILD TIMELINE"""
    pass


@dataclass(frozen=True)
class BuildAttackGraphCommand(ASTNode):
    """BUILD ATTACK GRAPH"""
    pass


@dataclass(frozen=True)
class AnchorEvidenceCommand(ASTNode):
    """ANCHOR EVIDENCE"""
    pass


@dataclass(frozen=True)
class VerifyEvidenceCommand(ASTNode):
    """VERIFY EVIDENCE"""
    pass


@dataclass(frozen=True)
class CheckSecurityCommand(ASTNode):
    """CHECK SECURITY command"""
    pass

@dataclass(frozen=True)
class GenerateReportCommand(ASTNode):
    """GENERATE REPORT"""
    pass


@dataclass(frozen=True)
class AssessRiskCommand(ASTNode):
    """ASSESS RISK"""
    pass


@dataclass(frozen=True)
class RegisterHostCommand(ASTNode):
    """REGISTER HOST "hostname"

    Registers an additional host with the central investigation manager.
    The hostname may differ from the primary HOST declaration.
    """
    hostname: str  # unquoted string value


@dataclass(frozen=True)
class AttachEvidenceCommand(ASTNode):
    """ATTACH EVIDENCE

    Attaches the current host's EvidencePackage to the active case in the
    central investigation manager.  The package_hash is never modified.
    """
    pass


@dataclass(frozen=True)
class ResearchCommand(ASTNode):
    """RESEARCH "scenario_id"

    Invokes a registered safe research and benchmarking scenario.
    """
    scenario_id: str


# ──────────────────────────────────────────────────────────
# Root Program node
# ──────────────────────────────────────────────────────────

# All node types that may appear as children of Program
Statement = (
    CaseDeclaration
    | HostDeclaration
    | AnalyzeCommand
    | TraceCommand
    | BlockchainTraceCommand
    | IdentifyVaspCommand
    | CorrelateEvidenceCommand
    | BuildTimelineCommand
    | BuildAttackGraphCommand
    | AssessRiskCommand
    | AnchorEvidenceCommand
    | VerifyEvidenceCommand
    | CheckSecurityCommand
    | GenerateReportCommand
    | RegisterHostCommand
    | AttachEvidenceCommand
    | ResearchCommand
)



@dataclass(frozen=True)
class Program(ASTNode):
    """Root of a JOCKY program.

    ``body`` is an ordered sequence of declarations and commands exactly
    as they appear in the source file.
    """
    body: tuple  # tuple[Statement, ...]  (tuple keeps the node frozen)


# ──────────────────────────────────────────────────────────
# Visitor
# ──────────────────────────────────────────────────────────

class ASTVisitor:
    """Base class for tree-walking visitors.

    Subclass and override ``visit_<ClassName>`` methods.  Call
    ``visitor.visit(node)`` to dispatch automatically.
    """

    def visit(self, node: ASTNode) -> Any:
        method_name = "visit_" + type(node).__name__
        method = getattr(self, method_name, self.generic_visit)
        return method(node)

    def generic_visit(self, node: ASTNode) -> Any:
        """Called when no explicit visitor method exists for a node type."""
        return None

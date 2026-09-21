"""
JOCKY Intermediate Representation (IR) node definitions.
---------------------------------------------------------
Every command in the language has a corresponding typed IR operation node.
The IR is the single source of truth passed to the runtime executor, the
future LLVM backend, and any external tool should consume the IR, never
the raw AST nodes.

Design principles
-----------------
* **Pydantic v2 models** — free serialisation to/from JSON/dict so the IR
  can be persisted, diffed, and passed between services.
* **Discriminated union** — every operation carries a ``kind`` literal so
  a serialised IR blob can be round-tripped without a type registry.
* **Source traceability** — every IR node optionally records the
  originating source line so runtime errors point back to the .jky file.
* **Typed parameters** — no raw strings where a structured field suffices
  (e.g.  ``chain: str`` defaults to ``"ethereum"``).
"""

from __future__ import annotations

from typing import Annotated, List, Literal, Optional, Union

from pydantic import BaseModel, Field


# ──────────────────────────────────────────────────────────
# Shared base for all IR operation nodes
# ──────────────────────────────────────────────────────────

class IRNode(BaseModel):
    """Base for every IR node.  Pydantic handles (de)serialisation."""

    # Source line where the corresponding AST node was declared.
    # None when constructed programmatically (e.g. in tests).
    source_line: Optional[int] = None

    model_config = {"frozen": True}   # nodes are immutable after construction


# ──────────────────────────────────────────────────────────
# Operation nodes  (one per JOCKY command)
# ──────────────────────────────────────────────────────────

class AnalyzeFilesOp(IRNode):
    """ANALYZE FILES — enumerate and hash files on the target host."""
    kind: Literal["ANALYZE_FILES"] = "ANALYZE_FILES"


class AnalyzeProcessesOp(IRNode):
    """ANALYZE PROCESSES — collect running process list and metadata."""
    kind: Literal["ANALYZE_PROCESSES"] = "ANALYZE_PROCESSES"


class AnalyzeNetworkOp(IRNode):
    """ANALYZE NETWORK — capture active network connections."""
    kind: Literal["ANALYZE_NETWORK"] = "ANALYZE_NETWORK"


class AnalyzeSystemOp(IRNode):
    """ANALYZE SYSTEM — collect operating system and platform metadata."""
    kind: Literal["ANALYZE_SYSTEM"] = "ANALYZE_SYSTEM"


class TraceConnectionsOp(IRNode):
    """TRACE SUSPICIOUS CONNECTIONS — filter and flag suspicious flows."""
    kind: Literal["TRACE_CONNECTIONS"] = "TRACE_CONNECTIONS"


class BlockchainTraceOp(IRNode):
    """BLOCKCHAIN TRACE — trace a wallet / transaction across a chain.

    Parameters
    ----------
    wallet:
        The address or transaction hash supplied in the source.
    chain:
        The blockchain to query.  Defaults to ``"ethereum"`` (EVM-compatible).
        Later phases will infer this from the address format or let the
        investigator specify it explicitly.
    """
    kind:   Literal["BLOCKCHAIN_TRACE"] = "BLOCKCHAIN_TRACE"
    wallet: str
    chain:  str = "ethereum"


class IdentifyVaspOp(IRNode):
    """IDENTIFY VASP — attribute the traced wallet to a known exchange/entity."""
    kind: Literal["IDENTIFY_VASP"] = "IDENTIFY_VASP"


class CorrelateEvidenceOp(IRNode):
    """CORRELATE EVIDENCE — join forensic and blockchain artefacts."""
    kind: Literal["CORRELATE_EVIDENCE"] = "CORRELATE_EVIDENCE"


class BuildTimelineOp(IRNode):
    """BUILD TIMELINE — produce a chronological event sequence."""
    kind: Literal["BUILD_TIMELINE"] = "BUILD_TIMELINE"


class BuildAttackGraphOp(IRNode):
    """BUILD ATTACK GRAPH — construct attacker-TTP relationship graph."""
    kind: Literal["BUILD_ATTACK_GRAPH"] = "BUILD_ATTACK_GRAPH"


class AssessRiskOp(IRNode):
    """ASSESS RISK — calculate deterministic risk score and severity."""
    kind: Literal["ASSESS_RISK"] = "ASSESS_RISK"


class AnchorEvidenceOp(IRNode):
    """ANCHOR EVIDENCE — hash and persist evidence to immutable storage.

    Parameters
    ----------
    algorithm:
        Hashing algorithm used for content addressing.  Fixed at SHA-256.
    backend:
        Storage backend.  Defaults to ``"ipfs"``; ``"evm"`` will anchor
        the IPFS CID on-chain.  Later phases will expand this.
    """
    kind:      Literal["ANCHOR_EVIDENCE"] = "ANCHOR_EVIDENCE"
    algorithm: str = "sha256"
    backend:   str = "ipfs"


class VerifyEvidenceOp(IRNode):
    """VERIFY EVIDENCE — verify integrity of anchored evidence against IPFS/EVM."""
    kind: Literal["VERIFY_EVIDENCE"] = "VERIFY_EVIDENCE"


class GenerateReportOp(IRNode):
    """GENERATE REPORT — emit a structured forensic report.

    Parameters
    ----------
    format:
        Output format.  Defaults to ``"json"``; ``"pdf"`` and ``"html"``
        will be supported in later phases.
    """
    kind:   Literal["GENERATE_REPORT"] = "GENERATE_REPORT"
    format: str = "json"


class CheckSecurityOp(IRNode):
    """CHECK SECURITY — perform a read‑only platform security pre‑check.

    Returns a ``SecurityStatus`` structure (handled later in runtime).
    """
    kind: Literal["CHECK_SECURITY"] = "CHECK_SECURITY"


class RegisterHostOp(IRNode):
    """REGISTER HOST "hostname" — register an additional host for central management."""
    kind: Literal["REGISTER_HOST"] = "REGISTER_HOST"
    hostname: str


class AttachEvidenceOp(IRNode):
    """ATTACH EVIDENCE — attach the current EvidencePackage to the central case."""
    kind: Literal["ATTACH_EVIDENCE"] = "ATTACH_EVIDENCE"


class ResearchOp(IRNode):
    """RESEARCH "scenario_id" — execute safe research benchmark scenario."""
    kind: Literal["RESEARCH"] = "RESEARCH"
    scenario_id: str


# ──────────────────────────────────────────────────────────
# Discriminated union  —  all possible operation types
# ──────────────────────────────────────────────────────────

IROperation = Annotated[
    Union[
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
    ],
    Field(discriminator="kind"),
]


# ──────────────────────────────────────────────────────────
# Host target
# ──────────────────────────────────────────────────────────

class HostTarget(BaseModel):
    """The target machine for this investigation."""
    hostname: str
    source_line: Optional[int] = None

    model_config = {"frozen": True}


# ──────────────────────────────────────────────────────────
# Root  —  InvestigationIR
# ──────────────────────────────────────────────────────────

class InvestigationIR(BaseModel):
    """
    Root of the JOCKY IR.

    Every compiled ``.jky`` program maps to exactly one ``InvestigationIR``
    instance.  The runtime, LLVM backend, and dashboard all consume this
    object rather than the AST.

    Fields
    ------
    case_id:
        Investigation identifier declared by ``CASE "…"``.
    host:
        The ``HostTarget`` declared by ``HOST "…"``.
    operations:
        Ordered list of IR operations to execute.
    """
    case_id:    str
    host:       HostTarget
    operations: List[IROperation] = Field(default_factory=list)

    # preserve source position of the CASE declaration itself
    source_line: Optional[int] = None

    model_config = {"frozen": True}

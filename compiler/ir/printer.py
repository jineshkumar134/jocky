"""
JOCKY IR Pretty-Printer
========================
Renders an ``InvestigationIR`` as a human-readable tree for the CLI
and for debugging.
"""

from __future__ import annotations

from typing import List

from compiler.ir.nodes import (
    InvestigationIR,
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
    AnchorEvidenceOp,
    VerifyEvidenceOp,
    GenerateReportOp,
    RegisterHostOp,
    AttachEvidenceOp,
    ResearchOp,
)


def _loc(line: int | None) -> str:
    return f"[line {line}]" if line is not None else ""


def _op_params(op: IROperation) -> list[tuple[str, str]]:
    """Return (key, value) pairs for the operation's non-kind parameters."""
    if isinstance(op, BlockchainTraceOp):
        return [("wallet", op.wallet), ("chain", op.chain)]
    if isinstance(op, AnchorEvidenceOp):
        return [("algorithm", op.algorithm), ("backend", op.backend)]
    if isinstance(op, GenerateReportOp):
        return [("format", op.format)]
    if isinstance(op, RegisterHostOp):
        return [("hostname", op.hostname)]
    if isinstance(op, ResearchOp):
        return [("scenario", op.scenario_id)]
    return []


def render(ir: InvestigationIR) -> str:
    """Return a printable ASCII tree of the ``InvestigationIR``."""
    lines: list[str] = []

    # Root
    case_loc = _loc(ir.source_line)
    lines.append("InvestigationIR")
    lines.append(f"  ├── case_id   : {ir.case_id:<35}  {case_loc}")

    host_loc = _loc(ir.host.source_line)
    lines.append(f"  ├── host      : {ir.host.hostname:<35}  {host_loc}")

    ops = ir.operations
    lines.append(f"  └── operations ({len(ops)})")

    for idx, op in enumerate(ops):
        is_last = (idx == len(ops) - 1)
        branch  = "└── " if is_last else "├── "
        indent  = "        " if is_last else "│       "
        num     = f"[{idx + 1:02d}]"
        op_loc  = _loc(op.source_line)
        lines.append(f"      {branch}{num}  {op.kind:<28}  {op_loc}")

        for key, val in _op_params(op):
            lines.append(f"      {indent}  {key:<12}: {val}")

    return "\n".join(lines)

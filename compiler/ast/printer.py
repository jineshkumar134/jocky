"""AST printer for JOCKY AST."""

from __future__ import annotations

from .nodes import (
    ASTNode,
    ASTVisitor,
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


class _PrinterVisitor(ASTVisitor):
    def __init__(self) -> None:
        self.lines: list[str] = []
        self._indent = 0

    def _emit(self, text: str) -> None:
        self.lines.append("  " * self._indent + text)

    def visit_Program(self, node: Program) -> None:
        self._emit(f"Program ({len(node.body)} statements)")
        self._indent += 1
        for stmt in node.body:
            self.visit(stmt)
        self._indent -= 1

    def visit_CaseDeclaration(self, node: CaseDeclaration) -> None:
        self._emit(f"CASE {node.case_id!r}")

    def visit_HostDeclaration(self, node: HostDeclaration) -> None:
        self._emit(f"HOST {node.hostname!r}")

    def visit_AnalyzeCommand(self, node: AnalyzeCommand) -> None:
        self._emit(f"ANALYZE {node.target}")

    def visit_TraceCommand(self, node: TraceCommand) -> None:
        self._emit("TRACE SUSPICIOUS CONNECTIONS")

    def visit_BlockchainTraceCommand(self, node: BlockchainTraceCommand) -> None:
        self._emit(f"BLOCKCHAIN TRACE {node.address!r}")

    def visit_IdentifyVaspCommand(self, node: IdentifyVaspCommand) -> None:
        self._emit("IDENTIFY VASP")

    def visit_CorrelateEvidenceCommand(self, node: CorrelateEvidenceCommand) -> None:
        self._emit("CORRELATE EVIDENCE")

    def visit_BuildTimelineCommand(self, node: BuildTimelineCommand) -> None:
        self._emit("BUILD TIMELINE")

    def visit_BuildAttackGraphCommand(self, node: BuildAttackGraphCommand) -> None:
        self._emit("BUILD ATTACK GRAPH")

    def visit_AssessRiskCommand(self, node: AssessRiskCommand) -> None:
        self._emit("ASSESS RISK")

    def visit_AnchorEvidenceCommand(self, node: AnchorEvidenceCommand) -> None:
        self._emit("ANCHOR EVIDENCE")

    def visit_VerifyEvidenceCommand(self, node: VerifyEvidenceCommand) -> None:
        self._emit("VERIFY EVIDENCE")

    def visit_GenerateReportCommand(self, node: GenerateReportCommand) -> None:
        self._emit("GENERATE REPORT")

    def visit_CheckSecurityCommand(self, node: CheckSecurityCommand) -> None:
        self._emit("CHECK SECURITY")

    def visit_RegisterHostCommand(self, node: RegisterHostCommand) -> None:
        self._emit(f"REGISTER HOST {node.hostname!r}")

    def visit_AttachEvidenceCommand(self, node: AttachEvidenceCommand) -> None:
        self._emit("ATTACH EVIDENCE")

    def visit_ResearchCommand(self, node: ResearchCommand) -> None:
        self._emit(f"RESEARCH {node.scenario_id!r}")


def render(node: ASTNode) -> str:
    visitor = _PrinterVisitor()
    visitor.visit(node)
    return "\n".join(visitor.lines)

"""
JOCKY LLVM Backend
==================
Lowers a ``InvestigationIR`` to LLVM IR text using **llvmlite**.

Architecture
------------
Every compiled investigation becomes one **LLVM module** whose name is
derived from the case identifier.  Inside that module:

1. **Global string constants** (``private unnamed_addr``) hold the case ID,
   hostname, wallet addresses, and other string parameters — exactly as a
   C compiler would emit string literals.

2. **External function declarations** (``declare``) name every JOCKY
   runtime function.  The runtime library (implemented in Phase 4+) will
   supply the real bodies; here we only declare the ABI.

3. **Investigation entry-point** – ``i32 @jocky_investigate(i8*, i8*)`` –
   the main function that calls each declared operation in source order,
   passing the appropriate string-pointer arguments.  It returns ``0`` on
   success.

ABI Convention
--------------
All JOCKY runtime functions return ``i32`` (0 = success, non-zero = error).
String arguments are ``i8*`` (null-terminated, UTF-8).

Operation → External function mapping
--------------------------------------
+------------------------+----------------------------------+---------------------------+
| IR kind                | LLVM extern                      | Arguments                 |
+========================+==================================+===========================+
| ANALYZE_FILES          | jocky_analyze_files              | (host: i8*)               |
| ANALYZE_PROCESSES      | jocky_analyze_processes          | (host: i8*)               |
| ANALYZE_NETWORK        | jocky_analyze_network            | (host: i8*)               |
| TRACE_CONNECTIONS      | jocky_trace_connections          | (host: i8*)               |
| BLOCKCHAIN_TRACE       | jocky_blockchain_trace           | (wallet: i8*, chain: i8*) |
| IDENTIFY_VASP          | jocky_identify_vasp              | (host: i8*)               |
| CORRELATE_EVIDENCE     | jocky_correlate_evidence         | (host: i8*)               |
| BUILD_TIMELINE         | jocky_build_timeline             | (host: i8*)               |
| BUILD_ATTACK_GRAPH     | jocky_build_attack_graph         | (host: i8*)               |
| ANCHOR_EVIDENCE        | jocky_anchor_evidence            | (algo: i8*, backend: i8*) |
| GENERATE_REPORT        | jocky_generate_report            | (format: i8*)             |
+------------------------+----------------------------------+---------------------------+
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import llvmlite.ir       as ll
import llvmlite.binding  as llvm

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
    AssessRiskOp,
    AnchorEvidenceOp,
    VerifyEvidenceOp,
    GenerateReportOp,
)



# ──────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────

_I8   = ll.IntType(8)
_I32  = ll.IntType(32)
_I8P  = _I8.as_pointer()
_ZERO = ll.Constant(_I32, 0)

_RET_OK = ll.Constant(_I32, 0)


# ──────────────────────────────────────────────────────────
# Result
# ──────────────────────────────────────────────────────────

@dataclass
class LLVMResult:
    """Returned by :meth:`JockyLLVMBackend.generate`."""
    ok:          bool
    ir_text:     str                  = ""
    module_name: str                  = ""
    errors:      List[str]            = field(default_factory=list)


# ──────────────────────────────────────────────────────────
# Backend
# ──────────────────────────────────────────────────────────

class JockyLLVMBackend:
    """
    Compiles one ``InvestigationIR`` to an LLVM module.

    Usage::

        result = JockyLLVMBackend(investigation_ir).generate()
        if result.ok:
            print(result.ir_text)
    """

    def __init__(self, ir: InvestigationIR) -> None:
        self._ir     = ir
        self._module: Optional[ll.Module] = None
        # Map from string value → GlobalVariable so we reuse constants
        self._str_cache: Dict[str, ll.GlobalVariable] = {}
        # Declared extern functions, keyed by name
        self._externs: Dict[str, ll.Function] = {}

    # ── public ─────────────────────────────────────────────

    def generate(self) -> LLVMResult:
        """Run the full lowering and return a :class:`LLVMResult`."""
        module_name = _safe_id(f"jocky_{self._ir.case_id}")
        try:
            self._module = ll.Module(name=module_name)
            self._module.triple = llvm.get_default_triple()

            self._emit_module_comment()
            self._declare_all_externs()
            self._emit_investigation_fn()

            ir_text = str(self._module)

            # Verify via the LLVM binding (parse + structural check)
            parsed = llvm.parse_assembly(ir_text)
            parsed.verify()

            return LLVMResult(ok=True, ir_text=ir_text, module_name=module_name)

        except Exception as exc:  # noqa: BLE001
            return LLVMResult(
                ok=False,
                module_name=module_name,
                errors=[f"LLVM backend error: {exc}"],
            )

    # ── module-level emission ──────────────────────────────

    def _emit_module_comment(self) -> None:
        """Embed a header comment in the module's source filename field."""
        # llvmlite doesn't expose module-level metadata for inline comments,
        # but we can set the source_filename (shown in the IR output).
        self._module.add_metadata([
            ll.MetaDataString(self._module,
                f"JOCKY Investigation: {self._ir.case_id} | "
                f"Host: {self._ir.host.hostname} | "
                f"Operations: {len(self._ir.operations)}"
            )
        ])

    def _declare_all_externs(self) -> None:
        """Declare every possible JOCKY runtime extern once."""
        # One-arg (host: i8*)
        for name in [
            "jocky_analyze_files",
            "jocky_analyze_processes",
            "jocky_analyze_network",
            "jocky_analyze_system",
            "jocky_trace_connections",
            "jocky_identify_vasp",
            "jocky_correlate_evidence",
            "jocky_build_timeline",
            "jocky_build_attack_graph",
            "jocky_assess_risk",
            "jocky_verify_evidence",
        ]:
            self._declare_extern(name, [_I8P])


        # Two-arg: wallet + chain
        self._declare_extern("jocky_blockchain_trace", [_I8P, _I8P])

        # Two-arg: algorithm + backend
        self._declare_extern("jocky_anchor_evidence", [_I8P, _I8P])

        # One-arg: format
        self._declare_extern("jocky_generate_report", [_I8P])

    def _declare_extern(self, name: str, arg_types: list) -> ll.Function:
        """Create (or look up) an ``i32 @name(…)`` external declaration."""
        if name in self._externs:
            return self._externs[name]
        fn_type = ll.FunctionType(_I32, arg_types)
        fn = ll.Function(self._module, fn_type, name=name)
        fn.attributes.add("nounwind")
        self._externs[name] = fn
        return fn

    # ── main function ──────────────────────────────────────

    def _emit_investigation_fn(self) -> None:
        """Emit ``i32 @jocky_investigate(i8* case_id, i8* host)``."""
        fn_name = _safe_id(f"jocky_investigate_{self._ir.case_id}")
        fn_type = ll.FunctionType(_I32, [_I8P, _I8P])
        fn = ll.Function(self._module, fn_type, name=fn_name)
        fn.args[0].name = "case_id"
        fn.args[1].name = "host"

        entry = fn.append_basic_block("entry")
        builder = ll.IRBuilder(entry)

        # Pre-load the host pointer — many operations pass it through
        host_gv  = self._global_string(self._ir.host.hostname, "str_host")
        host_ptr = builder.gep(host_gv, [_ZERO, _ZERO], inbounds=True, name="host_ptr")

        for idx, op in enumerate(self._ir.operations):
            self._emit_operation(builder, op, host_ptr, idx)

        builder.ret(_RET_OK)

    # ── per-operation emission ─────────────────────────────

    def _emit_operation(
        self,
        builder:  ll.IRBuilder,
        op:       IROperation,
        host_ptr: ll.Value,
        idx:      int,
    ) -> None:
        """Emit the ``call`` instruction for one IR operation."""
        lbl = f"op{idx:02d}"

        if isinstance(op, AnalyzeFilesOp):
            builder.call(self._externs["jocky_analyze_files"], [host_ptr], name=lbl)

        elif isinstance(op, AnalyzeProcessesOp):
            builder.call(self._externs["jocky_analyze_processes"], [host_ptr], name=lbl)

        elif isinstance(op, AnalyzeNetworkOp):
            builder.call(self._externs["jocky_analyze_network"], [host_ptr], name=lbl)

        elif isinstance(op, AnalyzeSystemOp):
            builder.call(self._externs["jocky_analyze_system"], [host_ptr], name=lbl)

        elif isinstance(op, TraceConnectionsOp):
            builder.call(self._externs["jocky_trace_connections"], [host_ptr], name=lbl)

        elif isinstance(op, BlockchainTraceOp):
            wallet_gv  = self._global_string(op.wallet, f"str_wallet_{idx:02d}")
            chain_gv   = self._global_string(op.chain,  f"str_chain_{idx:02d}")
            wallet_ptr = builder.gep(wallet_gv, [_ZERO, _ZERO], inbounds=True,
                                     name=f"wallet_{idx:02d}")
            chain_ptr  = builder.gep(chain_gv,  [_ZERO, _ZERO], inbounds=True,
                                     name=f"chain_{idx:02d}")
            builder.call(self._externs["jocky_blockchain_trace"],
                         [wallet_ptr, chain_ptr], name=lbl)

        elif isinstance(op, IdentifyVaspOp):
            builder.call(self._externs["jocky_identify_vasp"], [host_ptr], name=lbl)

        elif isinstance(op, CorrelateEvidenceOp):
            builder.call(self._externs["jocky_correlate_evidence"], [host_ptr], name=lbl)

        elif isinstance(op, BuildTimelineOp):
            builder.call(self._externs["jocky_build_timeline"], [host_ptr], name=lbl)

        elif isinstance(op, BuildAttackGraphOp):
            builder.call(self._externs["jocky_build_attack_graph"], [host_ptr], name=lbl)

        elif isinstance(op, AssessRiskOp):
            builder.call(self._externs["jocky_assess_risk"], [host_ptr], name=lbl)

        elif isinstance(op, AnchorEvidenceOp):

            algo_gv    = self._global_string(op.algorithm, f"str_algo_{idx:02d}")
            backend_gv = self._global_string(op.backend,   f"str_backend_{idx:02d}")
            algo_ptr   = builder.gep(algo_gv,    [_ZERO, _ZERO], inbounds=True,
                                     name=f"algo_{idx:02d}")
            backend_ptr = builder.gep(backend_gv, [_ZERO, _ZERO], inbounds=True,
                                      name=f"backend_{idx:02d}")
            builder.call(self._externs["jocky_anchor_evidence"],
                         [algo_ptr, backend_ptr], name=lbl)

        elif isinstance(op, VerifyEvidenceOp):
            builder.call(self._externs["jocky_verify_evidence"], [host_ptr], name=lbl)

        elif isinstance(op, GenerateReportOp):
            fmt_gv  = self._global_string(op.format, f"str_fmt_{idx:02d}")
            fmt_ptr = builder.gep(fmt_gv, [_ZERO, _ZERO], inbounds=True,
                                  name=f"fmt_{idx:02d}")
            builder.call(self._externs["jocky_generate_report"], [fmt_ptr], name=lbl)

        else:
            # Future-proof: unknown op kinds result in a no-op call to a
            # clearly-named stub so the module stays verifiable.
            stub_name = f"jocky_unimplemented_{op.kind.lower()}"
            stub = self._declare_extern(stub_name, [])
            builder.call(stub, [], name=lbl)

    # ── string constant helper ─────────────────────────────

    def _global_string(self, value: str, hint: str) -> ll.GlobalVariable:
        """
        Return (or create) a ``private unnamed_addr constant [N x i8]`` for
        a null-terminated UTF-8 string.  Repeated calls with the same
        *value* reuse the existing global variable.
        """
        if value in self._str_cache:
            return self._str_cache[value]

        encoded   = bytearray((value + "\x00").encode("utf-8"))
        arr_type  = ll.ArrayType(_I8, len(encoded))
        gv_name   = _safe_id(hint)[:64]   # LLVM name length limit

        # ensure unique name within the module
        if gv_name in [g.name for g in self._module.global_values]:
            gv_name = f"{gv_name}_{len(self._str_cache)}"

        gv = ll.GlobalVariable(self._module, arr_type, name=gv_name)
        gv.global_constant = True
        gv.linkage         = "private"
        gv.unnamed_addr    = True
        gv.initializer     = ll.Constant(arr_type, encoded)

        self._str_cache[value] = gv
        return gv


# ──────────────────────────────────────────────────────────
# Module-level helpers
# ──────────────────────────────────────────────────────────

def _safe_id(s: str) -> str:
    """Convert an arbitrary string to a valid LLVM identifier."""
    return re.sub(r"[^A-Za-z0-9_]", "_", s)


# ──────────────────────────────────────────────────────────
# Convenience function
# ──────────────────────────────────────────────────────────

def generate_llvm(ir: InvestigationIR) -> LLVMResult:
    """Lower *ir* to LLVM IR and return a :class:`LLVMResult`.

    This is the preferred public API for the LLVM backend.
    """
    return JockyLLVMBackend(ir).generate()

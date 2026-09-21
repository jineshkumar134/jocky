"""
JOCKY Runtime — Operation Dispatcher
=====================================
Dispatches structured JOCKY IR operations to the registered forensic adapters.

Architecture:
- Registry pattern: Handlers are mapped by operation kind string.
- Clean separation: Executes structured IR objects, NOT raw source strings.
- Graceful stubbing: Future operations (e.g. Blockchain, Reports) return structured
  NOT_IMPLEMENTED status without crashing the investigation.
- Extensible: New adapters can register handlers as future phases arrive.
"""

from __future__ import annotations

import dataclasses
import inspect
from typing import Any, Callable, Dict, Optional

from compiler.ir.nodes import (
    RegisterHostOp,
    AttachEvidenceOp,
    ResearchOp,
    AnalyzeFilesOp,
    AnalyzeNetworkOp,
    AnalyzeProcessesOp,
    AnalyzeSystemOp,
    AnchorEvidenceOp,
    BlockchainTraceOp,
    BuildAttackGraphOp,
    BuildTimelineOp,
    CorrelateEvidenceOp,
    GenerateReportOp,
    IROperation,
    TraceConnectionsOp,
)
from forensic.endpoint.base import EndpointAdapter, EndpointResult
from forensic.network.base import NetworkAdapter, NetworkResult


class OperationResult:
    """
    Normalized result of executing a single IR operation in the runtime.
    """

    def __init__(
        self,
        operation: str,
        status: str,
        data: Optional[Any] = None,
        message: Optional[str] = None,
        errors: Optional[list[str]] = None,
    ):
        self.operation = operation
        self.status = status  # SUCCESS, PARTIAL, FAILED, NOT_IMPLEMENTED
        self.data = data
        self.message = message
        self.errors = errors or []

    def to_dict(self) -> Dict[str, Any]:
        data_serialized = None
        if self.data is not None:
            if hasattr(self.data, "model_dump"):
                data_serialized = self.data.model_dump()
            elif dataclasses.is_dataclass(self.data):
                data_serialized = dataclasses.asdict(self.data)
            elif isinstance(self.data, dict):
                data_serialized = self.data
            else:
                data_serialized = str(self.data)

        return {
            "operation": self.operation,
            "status": self.status,
            "message": self.message,
            "data": data_serialized,
            "errors": self.errors,
        }


HandlerFunc = Callable[..., OperationResult]


class OperationDispatcher:
    """
    Dispatches JOCKY IR operations to matching forensic adapter methods.
    """

    def __init__(self):
        self._handlers: Dict[str, HandlerFunc] = {}
        self._register_default_handlers()

    def register_handler(self, kind: str, handler: HandlerFunc) -> None:
        """Register or override an operation handler."""
        self._handlers[kind] = handler

    def dispatch(
        self,
        op: IROperation,
        adapter: Any,
        network_adapter: Optional[Any] = None,
        blockchain_adapter: Optional[Any] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> OperationResult:
        """
        Dispatch a single IROperation to its registered handler.
        Passes adapter, network_adapter, blockchain_adapter, and execution context.
        """
        handler = self._handlers.get(op.kind)
        if handler:
            try:
                sig = inspect.signature(handler)
                params_count = len(sig.parameters)
                ctx = context if context is not None else {}
                if params_count >= 5:
                    return handler(op, adapter, network_adapter, blockchain_adapter, ctx)
                elif params_count == 4:
                    return handler(op, adapter, network_adapter, blockchain_adapter)
                elif params_count == 3:
                    return handler(op, adapter, network_adapter)
                return handler(op, adapter)
            except Exception as exc:
                return OperationResult(
                    operation=op.kind,
                    status="FAILED",
                    message=f"Handler execution error: {exc}",
                    errors=[str(exc)],
                )

        # Unregistered / future operations
        return OperationResult(
            operation=op.kind,
            status="NOT_IMPLEMENTED",
            message=f"Operation {op.kind} is not implemented (reserved for future phases).",
        )

    def _register_default_handlers(self) -> None:
        # 1. ANALYZE_FILES
        def handle_analyze_files(op: IROperation, adapter: EndpointAdapter, *_) -> OperationResult:
            res: EndpointResult = adapter.analyze_files()
            return OperationResult(
                operation=op.kind,
                status=res.status,
                data=res,
                message=f"Analyzed {len(res.artifacts)} file(s).",
                errors=res.errors,
            )

        # 2. ANALYZE_PROCESSES
        def handle_analyze_processes(op: IROperation, adapter: EndpointAdapter, *_) -> OperationResult:
            res: EndpointResult = adapter.analyze_processes()
            return OperationResult(
                operation=op.kind,
                status=res.status,
                data=res,
                message=f"Enumerated {len(res.artifacts)} process(es).",
                errors=res.errors,
            )

        # 3. ANALYZE_SYSTEM
        def handle_analyze_system(
            op: IROperation,
            adapter: EndpointAdapter,
            network_adapter: Optional[Any] = None,
            blockchain_adapter: Optional[Any] = None,
            context: Optional[Dict[str, Any]] = None,
        ) -> OperationResult:
            res: EndpointResult = adapter.analyze_system()
            ctx = context or {}
            try:
                from forensic.platform.factory import PlatformAdapterFactory
                platform_adapter = ctx.get("platform_adapter") or PlatformAdapterFactory.get_adapter()
                p_info = platform_adapter.get_platform_info()
                ctx["last_platform_info"] = p_info
                if hasattr(res, "summary") and isinstance(res.summary, dict):
                    res.summary["platform_info"] = p_info.__dict__ if hasattr(p_info, "__dict__") else str(p_info)
            except Exception:
                pass

            return OperationResult(
                operation=op.kind,
                status=res.status,
                data=res,
                message="System metadata collected.",
                errors=res.errors,
            )

        # 4. ANALYZE_NETWORK
        def handle_analyze_network(
            op: IROperation, adapter: Any, network_adapter: Optional[Any] = None, *_
        ) -> OperationResult:
            net_ad = network_adapter
            if net_ad is None:
                if isinstance(adapter, NetworkAdapter):
                    net_ad = adapter
                elif hasattr(adapter, "fixture_dir"):
                    from forensic.network.fixture import FixtureNetworkAdapter

                    net_ad = FixtureNetworkAdapter(host=getattr(adapter, "host", "LOCAL-HOST"))
                else:
                    from forensic.network.local import LocalNetworkAdapter

                    net_ad = LocalNetworkAdapter(host=getattr(adapter, "host", "LOCAL-HOST"))

            res: NetworkResult = net_ad.analyze_network()
            return OperationResult(
                operation=op.kind,
                status=res.status,
                data=res,
                message=f"Analyzed {len(res.connections)} connection(s), {len(res.listeners)} listener(s).",
                errors=res.errors,
            )

        # 5. BLOCKCHAIN_TRACE
        def handle_blockchain_trace(
            op: BlockchainTraceOp,
            adapter: Any,
            network_adapter: Optional[Any] = None,
            blockchain_adapter: Optional[Any] = None,
            context: Optional[Dict[str, Any]] = None,
        ) -> OperationResult:
            if blockchain_adapter is None:
                return OperationResult(
                    operation=op.kind,
                    status="NOT_IMPLEMENTED",
                    message=f"Operation {op.kind} is not implemented without a BlockchainAdapter.",
                )

            from blockchain.tracer.tracer import BlockchainTracer
            tracer = BlockchainTracer(blockchain_adapter)
            trace_res = tracer.trace(seed_address=op.wallet, chain=op.chain)

            if context is not None:
                context["last_blockchain_trace"] = trace_res

            return OperationResult(
                operation=op.kind,
                status="SUCCESS",
                data=trace_res,
                message=f"Traced {len(trace_res.hops)} hop(s) across {len(trace_res.wallets)} wallet(s).",
            )

        # 6. IDENTIFY_VASP
        def handle_identify_vasp(
            op: IROperation,
            adapter: Any,
            network_adapter: Optional[Any] = None,
            blockchain_adapter: Optional[Any] = None,
            context: Optional[Dict[str, Any]] = None,
        ) -> OperationResult:
            if blockchain_adapter is None and (not context or "last_blockchain_trace" not in context):
                return OperationResult(
                    operation=op.kind,
                    status="NOT_IMPLEMENTED",
                    message=f"Operation {op.kind} is not implemented without a BlockchainAdapter or trace context.",
                )

            from blockchain.vasp.attribution import VASPAttributionEngine
            engine = VASPAttributionEngine()

            wallets = []
            txs = []
            target_wallet = None

            if context and "last_blockchain_trace" in context:
                last_trace = context["last_blockchain_trace"]
                wallets = getattr(last_trace, "wallets", [])
                txs = getattr(last_trace, "transactions", [])
                target_wallet = getattr(last_trace, "seed_address", None)
            else:
                target_wallet = "0xWALLET003"
                if blockchain_adapter:
                    w = blockchain_adapter.get_wallet(target_wallet)
                    if w:
                        wallets = [w]
                        txs = blockchain_adapter.get_transactions(target_wallet)

            vasp_res = engine.attribute(wallets=wallets, transactions=txs, target_wallet=target_wallet)

            if context is not None:
                context["last_vasp_result"] = vasp_res

            top_cand = vasp_res.summary.get("top_candidate")
            msg = f"Attributed to {len(vasp_res.attributions)} VASP candidate(s). Top: {top_cand or 'None'}"
            return OperationResult(
                operation=op.kind,
                status="SUCCESS",
                data=vasp_res,
                message=msg,
            )

        # 7. GENERATE_REPORT (Explicitly NOT_IMPLEMENTED as instructed)
        def handle_generate_report(op: IROperation, *_) -> OperationResult:
            return OperationResult(
                operation=op.kind,
                status="NOT_IMPLEMENTED",
                message="Report generation is reserved for a future integration phase.",
            )

        # 8. CORRELATE_EVIDENCE
        def handle_correlate_evidence(
            op: IROperation,
            adapter: Any,
            network_adapter: Optional[Any] = None,
            blockchain_adapter: Optional[Any] = None,
            context: Optional[Dict[str, Any]] = None,
        ) -> OperationResult:
            """
            Run the CorrelationEngine against all evidence accumulated so far.

            Requires context["accumulated_results"] to be populated by the executor
            (list of OperationResult from prior operations in this investigation).
            """
            ctx = context or {}
            prior_results = ctx.get("accumulated_results", [])
            case_id = ctx.get("case_id", "UNKNOWN")
            host = ctx.get("host", "UNKNOWN")

            # Convert accumulated OperationResults to UniversalEvidence items
            try:
                from forensic.endpoint.base import EndpointResult
                from forensic.network.base import NetworkResult
                from forensic.evidence.converters import (
                    endpoint_result_to_evidence,
                    network_result_to_evidence,
                )
                from blockchain.converters import (
                    wallet_to_evidence,
                    transaction_to_evidence,
                    vasp_attribution_to_evidence,
                )
                from correlation.engine import CorrelationEngine
                from forensic.evidence.models import EvidencePackage
                from forensic.evidence.canonical import canonical_hash

                evidence_items = []
                for r in prior_results:
                    if isinstance(r.data, EndpointResult):
                        evidence_items.extend(
                            endpoint_result_to_evidence(r.data, case_id=case_id)
                        )
                    elif isinstance(r.data, NetworkResult):
                        evidence_items.extend(
                            network_result_to_evidence(r.data, case_id=case_id)
                        )
                    elif (
                        hasattr(r.data, "__class__")
                        and r.data.__class__.__name__ == "BlockchainTraceResult"
                    ):
                        for w in r.data.wallets:
                            evidence_items.append(
                                wallet_to_evidence(w, host=host, case_id=case_id)
                            )
                        for tx in r.data.transactions:
                            evidence_items.append(
                                transaction_to_evidence(tx, host=host, case_id=case_id)
                            )
                    elif (
                        hasattr(r.data, "__class__")
                        and r.data.__class__.__name__ == "VASPResult"
                    ):
                        for attr in r.data.attributions:
                            evidence_items.append(
                                vasp_attribution_to_evidence(attr, host=host, case_id=case_id)
                            )

                from datetime import datetime, timezone
                now = datetime.now(timezone.utc).isoformat()
                temp_hash = canonical_hash({"case_id": case_id, "host": host, "ts": now})
                pkg = EvidencePackage(
                    case_id=case_id,
                    host=host,
                    created_at=now,
                    evidence=evidence_items,
                    package_hash=temp_hash,
                )

                engine = CorrelationEngine()
                corr_result = engine.correlate(pkg, case_id=case_id, host=host)

                # Store result in context for build_universal_package() to reuse
                ctx["correlation_result"] = corr_result

                num = len(corr_result.findings)
                conf = corr_result.confidence
                return OperationResult(
                    operation=op.kind,
                    status="SUCCESS",
                    data=corr_result,
                    message=(
                        f"Correlation complete: {num} finding(s), "
                        f"overall confidence: {conf:.2f}."
                    ),
                )
            except Exception as exc:
                return OperationResult(
                    operation=op.kind,
                    status="FAILED",
                    message=f"Correlation engine error: {exc}",
                    errors=[str(exc)],
                )

        # 9. BUILD_ATTACK_GRAPH
        def handle_build_attack_graph(
            op: IROperation,
            adapter: Any,
            network_adapter: Optional[Any] = None,
            blockchain_adapter: Optional[Any] = None,
            context: Optional[Dict[str, Any]] = None,
        ) -> OperationResult:
            """
            Build an InvestigationGraph from all evidence, relationships, and
            correlations accumulated in the current investigation.
            """
            ctx = context or {}
            prior_results = ctx.get("accumulated_results", [])
            case_id = ctx.get("case_id", "UNKNOWN")
            host = ctx.get("host", "UNKNOWN")

            try:
                from forensic.endpoint.base import EndpointResult
                from forensic.network.base import NetworkResult
                from forensic.evidence.converters import (
                    endpoint_result_to_evidence,
                    network_result_to_evidence,
                    extract_grounded_relationships,
                    build_evidence_package,
                )
                from blockchain.converters import (
                    wallet_to_evidence,
                    transaction_to_evidence,
                    vasp_attribution_to_evidence,
                    extract_blockchain_relationships,
                )
                from graph.builder import GraphBuilder

                evidence_items = []
                for r in prior_results:
                    if isinstance(r.data, EndpointResult):
                        evidence_items.extend(
                            endpoint_result_to_evidence(r.data, case_id=case_id)
                        )
                    elif isinstance(r.data, NetworkResult):
                        evidence_items.extend(
                            network_result_to_evidence(r.data, case_id=case_id)
                        )
                    elif (
                        hasattr(r.data, "__class__")
                        and r.data.__class__.__name__ == "BlockchainTraceResult"
                    ):
                        for w in r.data.wallets:
                            evidence_items.append(
                                wallet_to_evidence(w, host=host, case_id=case_id)
                            )
                        for tx in r.data.transactions:
                            evidence_items.append(
                                transaction_to_evidence(tx, host=host, case_id=case_id)
                            )
                    elif (
                        hasattr(r.data, "__class__")
                        and r.data.__class__.__name__ == "VASPResult"
                    ):
                        for attr in r.data.attributions:
                            evidence_items.append(
                                vasp_attribution_to_evidence(attr, host=host, case_id=case_id)
                            )

                rels = extract_grounded_relationships(evidence_items)
                bc_rels = extract_blockchain_relationships(evidence_items)
                rel_ids = {rel.id for rel in rels}
                for b_rel in bc_rels:
                    if b_rel.id not in rel_ids:
                        rel_ids.add(b_rel.id)
                        rels.append(b_rel)

                corr_result = ctx.get("correlation_result")
                correlations_list = [f.to_dict() for f in corr_result.findings] if corr_result else []

                package = build_evidence_package(
                    case_id=case_id,
                    host=host,
                    evidence=evidence_items,
                    relationships=rels,
                    correlations=correlations_list,
                )

                builder = GraphBuilder()
                graph = builder.build_from_package(package, correlation_result=corr_result)

                ctx["last_graph"] = graph

                num_nodes = len(graph.nodes)
                num_edges = len(graph.edges)

                return OperationResult(
                    operation=op.kind,
                    status="SUCCESS",
                    data=graph,
                    message=f"Investigation graph built: {num_nodes} nodes, {num_edges} edges.",
                )
            except Exception as exc:
                return OperationResult(
                    operation=op.kind,
                    status="FAILED",
                    message=f"Graph builder error: {exc}",
                    errors=[str(exc)],
                )

        # 10. BUILD_TIMELINE
        def handle_build_timeline(
            op: IROperation,
            adapter: Any,
            network_adapter: Optional[Any] = None,
            blockchain_adapter: Optional[Any] = None,
            context: Optional[Dict[str, Any]] = None,
        ) -> OperationResult:
            """
            Build an InvestigationTimeline from all evidence, relationships,
            and correlations accumulated in the current investigation.
            """
            ctx = context or {}
            prior_results = ctx.get("accumulated_results", [])
            case_id = ctx.get("case_id", "UNKNOWN")
            host = ctx.get("host", "UNKNOWN")

            try:
                from forensic.endpoint.base import EndpointResult
                from forensic.network.base import NetworkResult
                from forensic.evidence.converters import (
                    endpoint_result_to_evidence,
                    network_result_to_evidence,
                    extract_grounded_relationships,
                    build_evidence_package,
                )
                from blockchain.converters import (
                    wallet_to_evidence,
                    transaction_to_evidence,
                    vasp_attribution_to_evidence,
                    extract_blockchain_relationships,
                )
                from timeline.builder import TimelineBuilder

                evidence_items = []
                for r in prior_results:
                    if isinstance(r.data, EndpointResult):
                        evidence_items.extend(endpoint_result_to_evidence(r.data, case_id=case_id))
                    elif isinstance(r.data, NetworkResult):
                        evidence_items.extend(network_result_to_evidence(r.data, case_id=case_id))
                    elif hasattr(r.data, "__class__") and r.data.__class__.__name__ == "BlockchainTraceResult":
                        for w in r.data.wallets:
                            evidence_items.append(wallet_to_evidence(w, host=host, case_id=case_id))
                        for tx in r.data.transactions:
                            evidence_items.append(transaction_to_evidence(tx, host=host, case_id=case_id))
                    elif hasattr(r.data, "__class__") and r.data.__class__.__name__ == "VASPResult":
                        for attr in r.data.attributions:
                            evidence_items.append(vasp_attribution_to_evidence(attr, host=host, case_id=case_id))

                rels = extract_grounded_relationships(evidence_items)
                bc_rels = extract_blockchain_relationships(evidence_items)
                rel_ids = {rel.id for rel in rels}
                for b_rel in bc_rels:
                    if b_rel.id not in rel_ids:
                        rel_ids.add(b_rel.id)
                        rels.append(b_rel)

                corr_result = ctx.get("correlation_result")
                correlations_list = [f.to_dict() for f in corr_result.findings] if corr_result else []

                package = build_evidence_package(
                    case_id=case_id,
                    host=host,
                    evidence=evidence_items,
                    relationships=rels,
                    correlations=correlations_list,
                )

                graph = ctx.get("last_graph")
                builder = TimelineBuilder()
                timeline = builder.build_from_package(
                    package, graph=graph, correlation_result=corr_result
                )

                ctx["last_timeline"] = timeline

                return OperationResult(
                    operation=op.kind,
                    status="SUCCESS",
                    data=timeline,
                    message=f"Timeline built: {len(timeline.events)} event(s).",
                )
            except Exception as exc:
                return OperationResult(
                    operation=op.kind,
                    status="FAILED",
                    message=f"Timeline builder error: {exc}",
                    errors=[str(exc)],
                )

        # 11. ASSESS_RISK
        def handle_assess_risk(
            op: IROperation,
            adapter: Any,
            network_adapter: Optional[Any] = None,
            blockchain_adapter: Optional[Any] = None,
            context: Optional[Dict[str, Any]] = None,
        ) -> OperationResult:
            """
            Execute the deterministic RiskEngine against accumulated evidence,
            correlations, and graph structures.
            """
            ctx = context or {}
            prior_results = ctx.get("accumulated_results", [])
            case_id = ctx.get("case_id", "UNKNOWN")
            host = ctx.get("host", "UNKNOWN")

            try:
                from forensic.endpoint.base import EndpointResult
                from forensic.network.base import NetworkResult
                from forensic.evidence.converters import (
                    endpoint_result_to_evidence,
                    network_result_to_evidence,
                    extract_grounded_relationships,
                    build_evidence_package,
                )
                from blockchain.converters import (
                    wallet_to_evidence,
                    transaction_to_evidence,
                    vasp_attribution_to_evidence,
                    extract_blockchain_relationships,
                )
                from risk.engine import RiskEngine

                evidence_items = []
                for r in prior_results:
                    if isinstance(r.data, EndpointResult):
                        evidence_items.extend(endpoint_result_to_evidence(r.data, case_id=case_id))
                    elif isinstance(r.data, NetworkResult):
                        evidence_items.extend(network_result_to_evidence(r.data, case_id=case_id))
                    elif hasattr(r.data, "__class__") and r.data.__class__.__name__ == "BlockchainTraceResult":
                        for w in r.data.wallets:
                            evidence_items.append(wallet_to_evidence(w, host=host, case_id=case_id))
                        for tx in r.data.transactions:
                            evidence_items.append(transaction_to_evidence(tx, host=host, case_id=case_id))
                    elif hasattr(r.data, "__class__") and r.data.__class__.__name__ == "VASPResult":
                        for attr in r.data.attributions:
                            evidence_items.append(vasp_attribution_to_evidence(attr, host=host, case_id=case_id))

                rels = extract_grounded_relationships(evidence_items)
                bc_rels = extract_blockchain_relationships(evidence_items)
                rel_ids = {rel.id for rel in rels}
                for b_rel in bc_rels:
                    if b_rel.id not in rel_ids:
                        rel_ids.add(b_rel.id)
                        rels.append(b_rel)

                corr_result = ctx.get("correlation_result")
                correlations_list = [f.to_dict() for f in corr_result.findings] if corr_result else []

                package = build_evidence_package(
                    case_id=case_id,
                    host=host,
                    evidence=evidence_items,
                    relationships=rels,
                    correlations=correlations_list,
                )

                graph = ctx.get("last_graph")
                engine = RiskEngine()
                assessment = engine.assess(
                    package, graph=graph, correlation_result=corr_result
                )

                ctx["last_risk_assessment"] = assessment

                # Phase 13: update attached packages for this case with this risk assessment
                from management.manager import _PACKAGE_CACHE
                for pkg_obj in _PACKAGE_CACHE.values():
                    if getattr(pkg_obj, "case_id", None) == case_id:
                        object.__setattr__(pkg_obj, "_risk_assessment", assessment)

                return OperationResult(
                    operation=op.kind,
                    status="SUCCESS",
                    data=assessment,
                    message=(
                        f"Risk assessment complete: score {assessment.score}/100 "
                        f"({assessment.severity.value}), {len(assessment.findings)} finding(s)."
                    ),
                )
            except Exception as exc:
                return OperationResult(
                    operation=op.kind,
                    status="FAILED",
                    message=f"Risk engine error: {exc}",
                    errors=[str(exc)],
                )

        # 12. ANCHOR_EVIDENCE
        def handle_anchor_evidence(
            op: IROperation,
            adapter: Any,
            network_adapter: Optional[Any] = None,
            blockchain_adapter: Optional[Any] = None,
            context: Optional[Dict[str, Any]] = None,
        ) -> OperationResult:
            ctx = context or {}
            try:
                from anchoring.engine import EvidenceAnchorEngine
                
                # We need the full evidence package to anchor
                # The executor builds it later in the pipeline normally, but we need it now
                # Let's borrow the package-building logic
                from forensic.endpoint.base import EndpointResult
                from forensic.network.base import NetworkResult
                from forensic.evidence.converters import (
                    endpoint_result_to_evidence,
                    network_result_to_evidence,
                    extract_grounded_relationships,
                    build_evidence_package,
                )
                from blockchain.converters import (
                    wallet_to_evidence,
                    transaction_to_evidence,
                    vasp_attribution_to_evidence,
                    extract_blockchain_relationships,
                )
                
                prior_results = ctx.get("accumulated_results", [])
                case_id = ctx.get("case_id", "UNKNOWN")
                host = ctx.get("host", "UNKNOWN")
                
                evidence_items = []
                for r in prior_results:
                    if isinstance(r.data, EndpointResult):
                        evidence_items.extend(endpoint_result_to_evidence(r.data, case_id=case_id))
                    elif isinstance(r.data, NetworkResult):
                        evidence_items.extend(network_result_to_evidence(r.data, case_id=case_id))
                    elif hasattr(r.data, "__class__") and r.data.__class__.__name__ == "BlockchainTraceResult":
                        for w in r.data.wallets:
                            evidence_items.append(wallet_to_evidence(w, host=host, case_id=case_id))
                        for tx in r.data.transactions:
                            evidence_items.append(transaction_to_evidence(tx, host=host, case_id=case_id))
                    elif hasattr(r.data, "__class__") and r.data.__class__.__name__ == "VASPResult":
                        for attr in r.data.attributions:
                            evidence_items.append(vasp_attribution_to_evidence(attr, host=host, case_id=case_id))

                rels = extract_grounded_relationships(evidence_items)
                bc_rels = extract_blockchain_relationships(evidence_items)
                rel_ids = {rel.id for rel in rels}
                for b_rel in bc_rels:
                    if b_rel.id not in rel_ids:
                        rel_ids.add(b_rel.id)
                        rels.append(b_rel)

                corr_result = ctx.get("correlation_result")
                correlations_list = [f.to_dict() for f in corr_result.findings] if corr_result else []

                graph_obj = ctx.get("last_graph")
                graph_dict = graph_obj.to_dict() if graph_obj is not None else None

                package = build_evidence_package(
                    case_id=case_id,
                    host=host,
                    evidence=evidence_items,
                    relationships=rels,
                    correlations=correlations_list,
                    graph=graph_dict,
                )
                
                # Gather derived metadata
                metadata = {}
                if graph_obj:
                    metadata["graph_hash"] = graph_obj.graph_hash
                if ctx.get("last_timeline"):
                    metadata["timeline_hash"] = ctx.get("last_timeline").timeline_hash
                if ctx.get("last_risk_assessment"):
                    metadata["risk_hash"] = ctx.get("last_risk_assessment").risk_hash

                if "anchor_engine" not in ctx:
                    ctx["anchor_engine"] = EvidenceAnchorEngine()
                engine = ctx["anchor_engine"]
                anchor = engine.anchor(package, metadata=metadata)
                
                ctx["last_anchor"] = anchor
                ctx["last_package"] = package  # Save for verification
                
                return OperationResult(
                    operation=op.kind,
                    status="SUCCESS",
                    data=anchor,
                    message=f"Evidence package {anchor.package_hash[:8]} anchored to IPFS ({anchor.ipfs_cid[:8]}...) and EVM ({anchor.tx_hash[:8]}...).",
                )
            except Exception as exc:
                return OperationResult(
                    operation=op.kind,
                    status="FAILED",
                    message=f"Evidence anchoring error: {exc}",
                    errors=[str(exc)],
                )

        # 13. VERIFY_EVIDENCE
        def handle_verify_evidence(
            op: IROperation,
            adapter: Any,
            network_adapter: Optional[Any] = None,
            blockchain_adapter: Optional[Any] = None,
            context: Optional[Dict[str, Any]] = None,
        ) -> OperationResult:
            ctx = context or {}
            try:
                from anchoring.engine import EvidenceAnchorEngine
                
                package = ctx.get("last_package")
                anchor = ctx.get("last_anchor")
                
                if not package:
                    return OperationResult(
                        operation=op.kind,
                        status="FAILED",
                        message="Verification failed: No evidence package available. Must run ANCHOR EVIDENCE or build package first.",
                    )
                
                if "anchor_engine" not in ctx:
                    ctx["anchor_engine"] = EvidenceAnchorEngine()
                engine = ctx["anchor_engine"]
                result = engine.verify(package, anchor)
                
                ctx["last_verification"] = result
                
                status_str = "SUCCESS" if result.is_valid else "FAILED"
                msg = f"Evidence verification {'passed' if result.is_valid else 'failed'}. IPFS: {result.ipfs_match}, EVM: {result.evm_match}."
                
                return OperationResult(
                    operation=op.kind,
                    status=status_str,
                    data=result,
                    message=msg,
                    errors=result.errors,
                )
            except Exception as exc:
                return OperationResult(
                    operation=op.kind,
                    status="FAILED",
                    message=f"Evidence verification error: {exc}",
                    errors=[str(exc)],
                )



        # 14. CHECK_SECURITY
        def handle_check_security(
            op: IROperation,
            adapter: Any,
            network_adapter: Optional[Any] = None,
            blockchain_adapter: Optional[Any] = None,
            context: Optional[Dict[str, Any]] = None,
        ) -> OperationResult:
            ctx = context or {}
            try:
                from forensic.security.precheck import SecurityPrecheck
                from forensic.platform.factory import PlatformAdapterFactory
                import dataclasses

                platform_adapter = ctx.get("platform_adapter")
                if platform_adapter is None:
                    platform_adapter = PlatformAdapterFactory.get_adapter()

                precheck = SecurityPrecheck(adapter=platform_adapter)
                platform_info, security_status = precheck.run_check()

                data = {
                    "platform_info": dataclasses.asdict(platform_info),
                    "security_status": dataclasses.asdict(security_status),
                }

                ctx["last_platform_info"] = platform_info
                ctx["last_security_status"] = security_status

                return OperationResult(
                    operation=op.kind,
                    status="SUCCESS",
                    data=data,
                    message=f"Platform security pre-check completed for {platform_info.os_name}.",
                )
            except Exception as exc:
                return OperationResult(
                    operation=op.kind,
                    status="FAILED",
                    message=f"Security pre-check error: {exc}",
                    errors=[str(exc)],
                )

        self.register_handler("ANALYZE_FILES", handle_analyze_files)
        self.register_handler("ANALYZE_PROCESSES", handle_analyze_processes)
        self.register_handler("ANALYZE_SYSTEM", handle_analyze_system)
        self.register_handler("ANALYZE_NETWORK", handle_analyze_network)
        self.register_handler("BLOCKCHAIN_TRACE", handle_blockchain_trace)
        self.register_handler("IDENTIFY_VASP", handle_identify_vasp)
        self.register_handler("GENERATE_REPORT", handle_generate_report)
        self.register_handler("CORRELATE_EVIDENCE", handle_correlate_evidence)
        self.register_handler("BUILD_ATTACK_GRAPH", handle_build_attack_graph)
        self.register_handler("BUILD_TIMELINE", handle_build_timeline)
        self.register_handler("ASSESS_RISK", handle_assess_risk)
        self.register_handler("ANCHOR_EVIDENCE", handle_anchor_evidence)
        self.register_handler("VERIFY_EVIDENCE", handle_verify_evidence)
        self.register_handler("CHECK_SECURITY", handle_check_security)




        def handle_register_host(op: RegisterHostOp, ea: EndpointAdapter, na: NetworkAdapter, ba: Any, ctx: Dict[str, Any]) -> OperationResult:
            try:
                from management.manager import CentralInvestigationManager
                from management.models import HostStatus

                mgr: CentralInvestigationManager = ctx.get("investigation_manager")
                if mgr is None:
                    mgr = CentralInvestigationManager.global_instance()
                    ctx["investigation_manager"] = mgr

                case_id = ctx.get("case_id", "DEFAULT_CASE")
                mgr.get_or_create_case(case_id)

                platform_adapter = ctx.get("platform_adapter")
                p_info = None
                if platform_adapter is not None and hasattr(platform_adapter, "get_platform_info"):
                    try:
                        import dataclasses
                        info = platform_adapter.get_platform_info()
                        if dataclasses.is_dataclass(info):
                            p_info = dataclasses.asdict(info)
                        elif isinstance(info, dict):
                            p_info = info
                    except Exception:
                        pass

                record = mgr.register_host(
                    case_id=case_id,
                    hostname=op.hostname,
                    status=HostStatus.ONLINE if op.hostname == ctx.get("host") else HostStatus.UNKNOWN,
                    platform_info=p_info,
                )

                data = {
                    "host_id": record.host_id,
                    "hostname": record.hostname,
                    "status": record.status.value,
                    "case_id": case_id,
                }
                return OperationResult(
                    operation=op.kind,
                    status="SUCCESS",
                    data=data,
                    message=f"Host '{op.hostname}' registered with case '{case_id}' (host_id: {record.host_id}).",
                )
            except Exception as exc:
                return OperationResult(
                    operation=op.kind,
                    status="FAILED",
                    message=f"Register host error: {exc}",
                    errors=[str(exc)],
                )

        def handle_attach_evidence(op: AttachEvidenceOp, ea: EndpointAdapter, na: NetworkAdapter, ba: Any, ctx: Dict[str, Any]) -> OperationResult:
            try:
                from management.manager import CentralInvestigationManager
                from forensic.evidence.converters import (
                    build_evidence_package,
                    endpoint_result_to_evidence,
                    network_result_to_evidence,
                    extract_grounded_relationships,
                )
                from blockchain.converters import (
                    wallet_to_evidence,
                    transaction_to_evidence,
                    vasp_attribution_to_evidence,
                    extract_blockchain_relationships,
                )
                from datetime import datetime, timezone

                mgr: CentralInvestigationManager = ctx.get("investigation_manager")
                if mgr is None:
                    mgr = CentralInvestigationManager.global_instance()
                    ctx["investigation_manager"] = mgr

                case_id = ctx.get("case_id", "DEFAULT_CASE")
                host = ctx.get("host", "DEFAULT_HOST")
                mgr.get_or_create_case(case_id)

                # Collect evidence items up to this point
                accumulated = ctx.get("accumulated_results", [])
                evidence_items = []
                bc_count = 0
                vasp_count = 0

                for r in accumulated:
                    if isinstance(r.data, EndpointResult):
                        evidence_items.extend(endpoint_result_to_evidence(r.data, case_id=case_id))
                    elif isinstance(r.data, NetworkResult):
                        evidence_items.extend(network_result_to_evidence(r.data, case_id=case_id))
                    elif hasattr(r.data, "__class__") and r.data.__class__.__name__ == "BlockchainTraceResult":
                        bc_count += len(r.data.transactions) + len(r.data.wallets)
                        for w in r.data.wallets:
                            evidence_items.append(wallet_to_evidence(w, host=host, case_id=case_id))
                        for tx in r.data.transactions:
                            evidence_items.append(transaction_to_evidence(tx, host=host, case_id=case_id))
                    elif hasattr(r.data, "__class__") and r.data.__class__.__name__ == "VASPResult":
                        vasp_count += len(r.data.attributions)
                        for attr in r.data.attributions:
                            evidence_items.append(vasp_attribution_to_evidence(attr, host=host, case_id=case_id))

                rels = extract_grounded_relationships(evidence_items)
                bc_rels = extract_blockchain_relationships(evidence_items)
                rel_ids = {r.id for r in rels}
                for b_rel in bc_rels:
                    if b_rel.id not in rel_ids:
                        rel_ids.add(b_rel.id)
                        rels.append(b_rel)

                corr_result = ctx.get("correlation_result")
                correlations = (
                    [f.to_dict() for f in corr_result.findings]
                    if corr_result is not None
                    else []
                )

                graph_obj = ctx.get("last_graph")
                graph_dict = graph_obj.to_dict() if graph_obj is not None else None

                # Use static/deterministic timestamp if one is shared or default
                # But to guarantee build_universal_package() produces the exact same package_hash,
                # we store this package in ctx so build_universal_package() can reuse it!
                created_at = ctx.get("started_at") or "2026-09-18T00:00:00+00:00"
                pkg = build_evidence_package(
                    case_id=case_id,
                    host=host,
                    evidence=evidence_items,
                    relationships=rels,
                    created_at=created_at,
                    correlations=correlations,
                    graph=graph_dict,
                )
                ctx["attached_universal_package"] = pkg

                # Capture pre-attachment package_hash
                pre_hash = pkg.package_hash

                # Attach existing risk if already run
                risk_obj = ctx.get("last_risk_assessment")
                if risk_obj is not None:
                    object.__setattr__(pkg, "_risk_assessment", risk_obj)
                object.__setattr__(pkg, "_blockchain_finding_count", bc_count)
                object.__setattr__(pkg, "_vasp_finding_count", vasp_count)

                # Register in manager package cache
                mgr.register_package(pkg.package_hash, pkg)
                mgr.attach_evidence(case_id=case_id, hostname=host, package_hash=pkg.package_hash)

                # Post-attachment package_hash check
                post_hash = pkg.package_hash
                if pre_hash != post_hash:
                    raise RuntimeError(f"package_hash changed during attachment! {pre_hash} != {post_hash}")

                data = {
                    "case_id": case_id,
                    "host": host,
                    "package_hash": pkg.package_hash,
                    "evidence_count": len(pkg.evidence),
                    "relationship_count": len(pkg.relationships),
                    "correlation_count": len(pkg.correlations),
                }
                return OperationResult(
                    operation=op.kind,
                    status="SUCCESS",
                    data=data,
                    message=f"EvidencePackage attached to case '{case_id}' (hash: {pkg.package_hash}).",
                )
            except Exception as exc:
                return OperationResult(
                    operation=op.kind,
                    status="FAILED",
                    message=f"Attach evidence error: {exc}",
                    errors=[str(exc)],
                )


        def handle_research(op: ResearchOp, ea: EndpointAdapter, na: NetworkAdapter, ba: Any, ctx: Dict[str, Any]) -> OperationResult:
            try:
                from research.engine import ResearchLabEngine
                from research.serialization import result_to_dict

                engine = ctx.get("research_engine")
                if engine is None:
                    engine = ResearchLabEngine()
                    ctx["research_engine"] = engine

                # Execute safe scenario
                res = engine.run_scenario(op.scenario_id)

                # Store in execution context list
                if "research_results" not in ctx:
                    ctx["research_results"] = []
                ctx["research_results"].append(res)

                return OperationResult(
                    operation=op.kind,
                    status="SUCCESS",
                    data=result_to_dict(res),
                    message=(
                        f"Security Research Scenario '{op.scenario_id}' executed safely. "
                        f"Observables: {len(res.observables)}, Findings: {len(res.findings)}, "
                        f"Coverage: {res.benchmark.detection_coverage * 100:.0f}%, Hash: {res.result_hash[:12]}..."
                    ),
                )
            except KeyError as exc:
                return OperationResult(
                    operation=op.kind,
                    status="FAILED",
                    message=str(exc),
                    errors=[str(exc)],
                )
            except Exception as exc:
                return OperationResult(
                    operation=op.kind,
                    status="FAILED",
                    message=f"Research scenario error: {exc}",
                    errors=[str(exc)],
                )

        self.register_handler("REGISTER_HOST", handle_register_host)
        self.register_handler("ATTACH_EVIDENCE", handle_attach_evidence)
        self.register_handler("RESEARCH", handle_research)

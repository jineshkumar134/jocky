"""
JOCKY Runtime — Investigation Executor
=======================================
Executes a compiled JOCKY IR Investigation across registered forensic adapters.

Key Principles:
- Executes structured IR objects, not raw strings.
- Dispatches each operation through OperationDispatcher with endpoint and network adapters.
- Maintains overall execution context (case_id, host, timestamps, summaries).
- Produces clean structured execution results with evidence package conversion.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from compiler.ir.nodes import InvestigationIR
from forensic.endpoint.base import EndpointAdapter, EndpointResult
from forensic.endpoint.local import LocalEndpointAdapter
from forensic.network.base import NetworkAdapter, NetworkResult
from runtime.executor.dispatcher import OperationDispatcher, OperationResult


class InvestigationExecutionResult:
    """
    Summary and detailed outcome of executing an entire JOCKY investigation.
    """

    def __init__(
        self,
        case_id: str,
        host: str,
        started_at: str,
        completed_at: str,
        results: List[OperationResult],
        context: Optional[Dict[str, Any]] = None,
        platform_info: Optional[Any] = None,
        security_status: Optional[Any] = None,
    ):
        self.case_id = case_id
        self.host = host
        self.started_at = started_at
        self.completed_at = completed_at
        self.results = results
        self.context = context or {}
        self.summary = self._compute_summary()

        # Phase 12: Platform & Security posture
        self.platform_info = platform_info or self.context.get("last_platform_info")
        self.security_status = security_status or self.context.get("last_security_status")

    def _compute_summary(self) -> Dict[str, Any]:
        total_ops = len(self.results)
        success_count = sum(1 for r in self.results if r.status == "SUCCESS")
        partial_count = sum(1 for r in self.results if r.status == "PARTIAL")
        failed_count = sum(1 for r in self.results if r.status == "FAILED")
        unimplemented_count = sum(1 for r in self.results if r.status == "NOT_IMPLEMENTED")

        return {
            "total_operations": total_ops,
            "successful_operations": success_count,
            "partial_operations": partial_count,
            "failed_operations": failed_count,
            "unimplemented_operations": unimplemented_count,
        }

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "case_id": self.case_id,
            "host": self.host,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "summary": self.summary,
            "operations": [r.to_dict() for r in self.results],
        }

        # Coexist endpoint & network categorized representations
        for r in self.results:
            if isinstance(r.data, NetworkResult):
                d["network"] = {
                    "connections": [c.model_dump() for c in r.data.connections],
                    "listeners": [l.model_dump() for l in r.data.listeners],
                    "dns": [dns.model_dump() for dns in r.data.dns_records],
                    "summary": r.data.summary,
                }
            elif isinstance(r.data, EndpointResult):
                if "endpoint" not in d:
                    d["endpoint"] = {}
                d["endpoint"][r.operation.lower()] = [
                    a.model_dump() if hasattr(a, "model_dump") else a for a in r.data.artifacts
                ]

            elif hasattr(r.data, "__class__") and r.data.__class__.__name__ == "BlockchainTraceResult":
                d["blockchain"] = {
                    "seed_address": r.data.seed_address,
                    "chain": r.data.chain,
                    "wallets": [w.model_dump() for w in r.data.wallets],
                    "transactions": [tx.model_dump() for tx in r.data.transactions],
                    "hops": [h.model_dump() for h in r.data.hops],
                    "summary": r.data.summary,
                }
            elif hasattr(r.data, "__class__") and r.data.__class__.__name__ == "VASPResult":
                d["vasp"] = {
                    "target_wallet": r.data.target_wallet,
                    "attributions": [a.model_dump() for a in r.data.attributions],
                    "summary": r.data.summary,
                }

        # Phase 9: Expose graph if built
        graph_obj = self.context.get("last_graph")
        if graph_obj is not None:
            d["graph"] = graph_obj.to_dict()
            d["investigation_graph"] = graph_obj.to_dict()

        # Phase 10: Expose timeline and risk_assessment if built
        timeline_obj = self.context.get("last_timeline")
        if timeline_obj is not None:
            d["timeline"] = timeline_obj.to_dict()

        risk_obj = self.context.get("last_risk_assessment")
        if risk_obj is not None:
            d["risk_assessment"] = risk_obj.to_dict()

        # Phase 12: Expose platform_info and security_status if available
        import dataclasses
        if self.platform_info is not None:
            if dataclasses.is_dataclass(self.platform_info):
                d["platform_info"] = dataclasses.asdict(self.platform_info)
            elif isinstance(self.platform_info, dict):
                d["platform_info"] = self.platform_info
            elif hasattr(self.platform_info, "__dict__"):
                d["platform_info"] = dict(self.platform_info.__dict__)

        if self.security_status is not None:
            if dataclasses.is_dataclass(self.security_status):
                d["security_status"] = dataclasses.asdict(self.security_status)
            elif isinstance(self.security_status, dict):
                d["security_status"] = self.security_status
            elif hasattr(self.security_status, "__dict__"):
                d["security_status"] = dict(self.security_status.__dict__)

        # Phase 13: Expose case_management if CentralInvestigationManager was invoked
        mgr = self.context.get("investigation_manager")
        if mgr is not None:
            try:
                from management.serialization import case_summary_to_dict, case_to_dict
                case = mgr.get_case(self.case_id)
                summary = mgr.generate_summary(self.case_id)
                d["case_management"] = {
                    "case": case_to_dict(case) if case else None,
                    "case_hash": mgr.compute_case_hash(self.case_id) if case else None,
                    "summary": case_summary_to_dict(summary),
                }
            except Exception:
                pass

        # Phase 15: Expose research_results if any RESEARCH operations ran
        research_list = self.context.get("research_results")
        if research_list:
            from research.serialization import result_to_dict
            d["research_results"] = [result_to_dict(r) for r in research_list]

        # Phase 6, 7, 8, 9 & 10: Universal Evidence Package
        pkg = self.build_universal_package()
        d["evidence_package"] = pkg.to_dict()

        return d



    def build_universal_package(self):
        """
        Build a strongly typed Universal EvidencePackage from all collected results.
        Collates endpoint, network, blockchain, and VASP evidence, links grounded
        relationships, runs the Correlation Engine, and computes deterministic
        package integrity hashes.
        """
        if hasattr(self, "_universal_package") and self._universal_package is not None:
            return self._universal_package

        if self.context.get("attached_universal_package") is not None:
            self._universal_package = self.context["attached_universal_package"]
            return self._universal_package

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

        evidence_items = []
        for r in self.results:
            if isinstance(r.data, EndpointResult):
                evidence_items.extend(endpoint_result_to_evidence(r.data, case_id=self.case_id))
            elif isinstance(r.data, NetworkResult):
                evidence_items.extend(network_result_to_evidence(r.data, case_id=self.case_id))
            elif hasattr(r.data, "__class__") and r.data.__class__.__name__ == "BlockchainTraceResult":
                for w in r.data.wallets:
                    evidence_items.append(wallet_to_evidence(w, host=self.host, case_id=self.case_id))
                for tx in r.data.transactions:
                    evidence_items.append(transaction_to_evidence(tx, host=self.host, case_id=self.case_id))
            elif hasattr(r.data, "__class__") and r.data.__class__.__name__ == "VASPResult":
                for attr in r.data.attributions:
                    evidence_items.append(vasp_attribution_to_evidence(attr, host=self.host, case_id=self.case_id))

        # Grounded relationships
        rels = extract_grounded_relationships(evidence_items)
        bc_rels = extract_blockchain_relationships(evidence_items)
        rel_ids = {r.id for r in rels}
        for b_rel in bc_rels:
            if b_rel.id not in rel_ids:
                rel_ids.add(b_rel.id)
                rels.append(b_rel)

        # Phase 8: Run Correlation Engine
        # Re-use result from CORRELATE_EVIDENCE op if it was explicitly called,
        # otherwise run the engine fresh (deterministic — same evidence → same findings).
        corr_result = self.context.get("correlation_result")
        if corr_result is None:
            try:
                from correlation.engine import CorrelationEngine
                from forensic.evidence.models import EvidencePackage
                from forensic.evidence.canonical import canonical_hash
                from datetime import datetime, timezone

                now = datetime.now(timezone.utc).isoformat()
                temp_hash = canonical_hash({"case_id": self.case_id, "host": self.host, "ts": now})
                temp_pkg = EvidencePackage(
                    case_id=self.case_id,
                    host=self.host,
                    created_at=now,
                    evidence=evidence_items,
                    package_hash=temp_hash,
                )
                engine = CorrelationEngine()
                corr_result = engine.correlate(temp_pkg, case_id=self.case_id, host=self.host)
            except Exception:
                corr_result = None

        correlations = (
            [f.to_dict() for f in corr_result.findings]
            if corr_result is not None
            else []
        )

        # Phase 9: Attach graph if built
        graph_obj = self.context.get("last_graph")
        graph_dict = graph_obj.to_dict() if graph_obj is not None else None

        pkg = build_evidence_package(
            case_id=self.case_id,
            host=self.host,
            evidence=evidence_items,
            relationships=rels,
            created_at=self.completed_at,
            correlations=correlations,
            graph=graph_dict,
        )
        self._universal_package = pkg
        return pkg


    def to_evidence_package(self) -> Dict[str, Any]:
        """
        Evidence Conversion Layer (Section 6, 11, & Phase 7):
        Collates all operation results into a unified evidence package.
        Includes backward-compatible items while exposing universal evidence package.
        """
        evidence_items = []
        for r in self.results:
            if isinstance(r.data, (EndpointResult, NetworkResult)):
                evidence_items.append(r.data.to_evidence())
            else:
                evidence_items.append(
                    {
                        "evidence_id": f"EVID-OP-{r.operation}",
                        "operation": r.operation,
                        "status": r.status,
                        "message": r.message,
                        "data": r.to_dict().get("data"),
                    }
                )

        pkg = self.build_universal_package()
        pkg_dict = pkg.to_dict()

        return {
            "case_id": self.case_id,
            "host": self.host,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "evidence_package_version": "0.7.0",
            "items": evidence_items,
            "evidence": pkg_dict["evidence"],
            "relationships": pkg_dict["relationships"],
            "package_hash": pkg.package_hash,
            "evidence_package": pkg_dict,
        }


class RuntimeExecutor:
    """
    Main runtime engine for executing a JOCKY InvestigationIR.
    """

    def __init__(
        self,
        ir: InvestigationIR,
        adapter: Optional[EndpointAdapter] = None,
        network_adapter: Optional[NetworkAdapter] = None,
        blockchain_adapter: Optional[Any] = None,
        platform_adapter: Optional[Any] = None,
        dispatcher: Optional[OperationDispatcher] = None,
    ):
        self.ir = ir
        self.adapter = adapter or LocalEndpointAdapter(host=ir.host.hostname)

        if network_adapter is not None:
            self.network_adapter = network_adapter
        elif hasattr(self.adapter, "fixture_dir"):
            from forensic.network.fixture import FixtureNetworkAdapter

            self.network_adapter = FixtureNetworkAdapter(host=ir.host.hostname)
        else:
            from forensic.network.local import LocalNetworkAdapter

            self.network_adapter = LocalNetworkAdapter(host=ir.host.hostname)

        self.blockchain_adapter = blockchain_adapter
        self.platform_adapter = platform_adapter
        self.dispatcher = dispatcher or OperationDispatcher()

    def execute(self) -> InvestigationExecutionResult:
        """
        Execute all operations defined in the InvestigationIR in order.
        """
        started_at = datetime.now(timezone.utc).isoformat()
        results: List[OperationResult] = []
        context: Dict[str, Any] = {
            "case_id": self.ir.case_id,
            "host": self.ir.host.hostname,
            "accumulated_results": results,  # live reference — grows as ops run
            "platform_adapter": self.platform_adapter,
        }

        for op in self.ir.operations:
            res = self.dispatcher.dispatch(
                op,
                self.adapter,
                self.network_adapter,
                self.blockchain_adapter,
                context,
            )
            results.append(res)

        completed_at = datetime.now(timezone.utc).isoformat()

        return InvestigationExecutionResult(
            case_id=self.ir.case_id,
            host=self.ir.host.hostname,
            started_at=started_at,
            completed_at=completed_at,
            results=results,
            context=context,
        )


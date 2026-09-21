"""
Case and Investigation API Endpoints for JOCKY Dashboard
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException

from compiler.compiler import compile_source
from runtime.executor.executor import RuntimeExecutor
from forensic.endpoint.fixture import FixtureEndpointAdapter
from forensic.network.fixture import FixtureNetworkAdapter
from blockchain.evm.adapter import EVMAdapter
from forensic.platform.factory import PlatformAdapterFactory
from management.manager import CentralInvestigationManager

router = APIRouter(prefix="/cases", tags=["Cases"])

# Global cache of executed investigation result dicts keyed by case_id
_INVESTIGATION_CACHE: Dict[str, Dict[str, Any]] = {}

DEFAULT_FIXTURE_SCRIPT = """
CASE "JOCKY-FINAL-2026"
HOST "LAB-PC-01"

CHECK SECURITY

REGISTER HOST "LAB-PC-01"
REGISTER HOST "LAB-PC-02"
REGISTER HOST "LAB-PC-03"

ANALYZE SYSTEM
ANALYZE FILES
ANALYZE PROCESSES
ANALYZE NETWORK

TRACE SUSPICIOUS CONNECTIONS

BLOCKCHAIN TRACE "0xWALLET001"
IDENTIFY VASP

CORRELATE EVIDENCE
BUILD ATTACK GRAPH
BUILD TIMELINE
ATTACH EVIDENCE
ASSESS RISK

ANCHOR EVIDENCE
VERIFY EVIDENCE
GENERATE REPORT

RESEARCH "synthetic_polymorphism"
RESEARCH "synthetic_memory_execution"
RESEARCH "synthetic_driver_risk"
RESEARCH "synthetic_security_controls"
RESEARCH "synthetic_network_behavior"
"""


def _get_or_run_case(case_id: str = "JOCKY-FINAL-2026") -> Dict[str, Any]:
    """Execute the synthetic investigation pipeline once and cache results in-memory."""
    if case_id in _INVESTIGATION_CACHE:
        return _INVESTIGATION_CACHE[case_id]

    # Run the canonical multi-host fixture investigation script
    CentralInvestigationManager.reset_global()
    res = compile_source(DEFAULT_FIXTURE_SCRIPT)
    if not res.ok or res.ir is None:
        raise RuntimeError(f"Compilation of default fixture failed: {res.errors}")

    ea = FixtureEndpointAdapter(host="LAB-PC-01")
    na = FixtureNetworkAdapter(host="LAB-PC-01")
    ba = EVMAdapter()
    pa = PlatformAdapterFactory.get_adapter()
    executor = RuntimeExecutor(res.ir, adapter=ea, network_adapter=na, blockchain_adapter=ba, platform_adapter=pa)
    result = executor.execute()
    data = result.to_dict()

    _INVESTIGATION_CACHE[case_id] = data
    return data


@router.get("")
async def list_cases() -> List[Dict[str, Any]]:
    """List all available investigation cases."""
    data = _get_or_run_case("JOCKY-FINAL-2026")
    cm = data.get("case_management") or {}
    case = cm.get("case") or {}
    summary = cm.get("summary") or {}
    return [
        {
            "case_id": data["case_id"],
            "title": case.get("title", data["case_id"]),
            "status": summary.get("status", "OPEN"),
            "host_count": summary.get("host_count", 1),
            "evidence_package_count": summary.get("evidence_package_count", 1),
            "highest_risk_score": summary.get("highest_risk_score", 0),
            "highest_risk_severity": summary.get("highest_risk_severity", "LOW"),
            "started_at": data.get("started_at"),
            "completed_at": data.get("completed_at"),
        }
    ]


@router.get("/{case_id}")
async def get_case_details(case_id: str) -> Dict[str, Any]:
    """Get full case details, overview, and central management info."""
    data = _get_or_run_case(case_id)
    if data.get("case_id") != case_id:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found")
    return {
        "case_id": data["case_id"],
        "host": data["host"],
        "started_at": data["started_at"],
        "completed_at": data["completed_at"],
        "summary": data.get("summary", {}),
        "case_management": data.get("case_management", {}),
        "platform_info": data.get("platform_info"),
        "security_status": data.get("security_status"),
    }


@router.get("/{case_id}/hosts")
async def get_case_hosts(case_id: str) -> List[Dict[str, Any]]:
    """Get all hosts registered with this case."""
    data = _get_or_run_case(case_id)
    if data.get("case_id") != case_id:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found")

    # Retrieve from manager if available or operations
    hosts = []
    reg_ops = [op for op in data.get("operations", []) if op.get("operation") == "REGISTER_HOST"]
    primary_host = data.get("host")
    p_info = data.get("platform_info")
    sec_status = data.get("security_status")

    if reg_ops:
        for op in reg_ops:
            h_data = op.get("data", {})
            hostname = h_data.get("hostname")
            is_primary = (hostname == primary_host)
            hosts.append({
                "host_id": h_data.get("host_id"),
                "hostname": hostname,
                "status": h_data.get("status", "ONLINE" if is_primary else "UNKNOWN"),
                "is_primary": is_primary,
                "has_evidence": is_primary,
                "platform_info": p_info if is_primary else None,
                "security_status": sec_status if is_primary else None,
            })
    else:
        hosts.append({
            "host_id": f"HOST-{primary_host}",
            "hostname": primary_host,
            "status": "ONLINE",
            "is_primary": True,
            "has_evidence": True,
            "platform_info": p_info,
            "security_status": sec_status,
        })

    return hosts


@router.get("/{case_id}/evidence")
async def get_case_evidence(case_id: str) -> Dict[str, Any]:
    """Get collected UniversalEvidence items, relationships, and correlations."""
    data = _get_or_run_case(case_id)
    if data.get("case_id") != case_id:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found")

    pkg = data.get("evidence_package", {})
    return {
        "case_id": data["case_id"],
        "host": data["host"],
        "package_hash": pkg.get("package_hash", ""),
        "created_at": pkg.get("created_at"),
        "evidence": pkg.get("evidence", []),
        "relationships": pkg.get("relationships", []),
        "correlations": pkg.get("correlations", []),
    }


@router.get("/{case_id}/graph")
async def get_case_graph(case_id: str) -> Dict[str, Any]:
    """Get the Phase 9 Investigation Graph."""
    data = _get_or_run_case(case_id)
    if data.get("case_id") != case_id:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found")

    graph = data.get("graph") or data.get("investigation_graph")
    if not graph:
        raise HTTPException(status_code=404, detail="Investigation graph not generated for this case")
    return graph


@router.get("/{case_id}/timeline")
async def get_case_timeline(case_id: str) -> Dict[str, Any]:
    """Get the Phase 10 Investigation Timeline."""
    data = _get_or_run_case(case_id)
    if data.get("case_id") != case_id:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found")

    timeline = data.get("timeline")
    if not timeline:
        raise HTTPException(status_code=404, detail="Timeline not generated for this case")
    return timeline


@router.get("/{case_id}/risk")
async def get_case_risk(case_id: str) -> Dict[str, Any]:
    """Get the Phase 10 Risk Assessment."""
    data = _get_or_run_case(case_id)
    if data.get("case_id") != case_id:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found")

    risk = data.get("risk_assessment")
    if not risk:
        raise HTTPException(status_code=404, detail="Risk assessment not generated for this case")
    return risk


@router.get("/{case_id}/blockchain")
async def get_case_blockchain(case_id: str) -> Dict[str, Any]:
    """Get Phase 7 Blockchain trace and VASP attribution data."""
    data = _get_or_run_case(case_id)
    if data.get("case_id") != case_id:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found")

    return {
        "blockchain": data.get("blockchain"),
        "vasp": data.get("vasp"),
    }


@router.get("/{case_id}/anchoring")
async def get_case_anchoring(case_id: str) -> Dict[str, Any]:
    """Get Phase 11 Anchoring and Verification records."""
    data = _get_or_run_case(case_id)
    if data.get("case_id") != case_id:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found")

    anchor_op = next((op for op in data.get("operations", []) if op.get("operation") == "ANCHOR_EVIDENCE"), None)
    verify_op = next((op for op in data.get("operations", []) if op.get("operation") == "VERIFY_EVIDENCE"), None)

    return {
        "anchor": anchor_op.get("data") if anchor_op else None,
        "verification": verify_op.get("data") if verify_op else None,
    }


@router.get("/{case_id}/security")
async def get_case_security(case_id: str) -> Dict[str, Any]:
    """Get Phase 12 Platform info and security pre-check status."""
    data = _get_or_run_case(case_id)
    if data.get("case_id") != case_id:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found")

    return {
        "platform_info": data.get("platform_info"),
        "security_status": data.get("security_status"),
    }


@router.get("/{case_id}/research")
async def get_case_research(case_id: str) -> List[Dict[str, Any]]:
    """Get security research scenario results executed for this case."""
    data = _get_or_run_case(case_id)
    if data.get("case_id") != case_id:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found")

    # If already in execution results, return them
    if "research_results" in data:
        return data["research_results"]

    # Otherwise execute safe research scenarios via ResearchLabEngine on demand
    from research.engine import ResearchLabEngine
    from research.serialization import result_to_dict

    engine = ResearchLabEngine()
    results = []
    for sc in engine.registry.list_scenarios():
        res = engine.run_scenario(sc.scenario_id)
        results.append(result_to_dict(res))

    data["research_results"] = results
    return results

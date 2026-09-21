"""
JOCKY Forensic — Artifact to Universal Evidence Converters
==========================================================
Converts forensic artifacts from Endpoint and Network adapters into
the Universal Evidence Model, enforcing:
- Strict evidence-grounded relationship extraction (PID matching, DNS resolutions)
- Deterministic evidence ID derivation using host + collector seeds
- Cryptographic canonical integrity hashing for every evidence item
- Full collation into an immutable EvidencePackage
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from forensic.endpoint.base import (
    EndpointResult,
    FileArtifact,
    ProcessArtifact,
    SystemArtifact,
)
from forensic.evidence.canonical import (
    canonical_hash,
    generate_evidence_id,
)
from forensic.evidence.models import (
    DNSRecordEntity,
    EvidenceIntegrity,
    EvidencePackage,
    EvidenceProvenance,
    EvidenceType,
    FileEntity,
    NetworkConnectionEntity,
    NetworkListenerEntity,
    ProcessEntity,
    Relationship,
    RelationshipType,
    SystemEntity,
    UniversalEvidence,
)
from forensic.network.base import (
    DNSRecord,
    NetworkConnection,
    NetworkListener,
    NetworkResult,
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def file_artifact_to_evidence(
    artifact: FileArtifact,
    host: str,
    case_id: Optional[str] = None,
    collector: str = "EndpointAdapter",
) -> UniversalEvidence:
    """Convert a FileArtifact into a UniversalEvidence instance."""
    entity = FileEntity(
        path=artifact.path,
        name=artifact.name,
        extension=artifact.extension,
        size=artifact.size,
        sha256=artifact.sha256,
        modified_at=artifact.modified_at,
        created_at=artifact.created_at,
        accessed_at=artifact.accessed_at,
        file_type=artifact.file_type,
        error=artifact.error,
    )
    ev_id = generate_evidence_id(
        evidence_type=EvidenceType.FILE.value,
        entity_data=entity.model_dump(),
        host=host,
        collector=collector,
    )
    provenance = EvidenceProvenance(
        collector=collector,
        adapter="endpoint",
        source=f"host:{host}",
        collection_method="os.scandir/hashlib.sha256",
        collected_at=artifact.modified_at or _utc_now(),
        host=host,
        case_id=case_id,
    )
    # Compute integrity hash over canonical record without integrity
    record_payload = {
        "id": ev_id,
        "type": EvidenceType.FILE.value,
        "source": "endpoint",
        "timestamp": provenance.collected_at,
        "confidence": 1.0,
        "entity": entity.model_dump(),
        "relationships": [],
        "provenance": provenance.model_dump(),
    }
    digest = canonical_hash(record_payload)
    integrity = EvidenceIntegrity(algorithm="SHA-256", value=digest)

    return UniversalEvidence(
        id=ev_id,
        type=EvidenceType.FILE,
        source="endpoint",
        timestamp=provenance.collected_at,
        confidence=1.0,
        entity=entity,
        relationships=[],
        provenance=provenance,
        integrity=integrity,
    )


def process_artifact_to_evidence(
    artifact: ProcessArtifact,
    host: str,
    case_id: Optional[str] = None,
    collector: str = "EndpointAdapter",
) -> UniversalEvidence:
    """Convert a ProcessArtifact into a UniversalEvidence instance."""
    entity = ProcessEntity(
        pid=artifact.pid,
        name=artifact.name,
        parent_pid=artifact.parent_pid,
        executable=artifact.executable,
        username=artifact.username,
        start_time=artifact.start_time,
        status=artifact.status,
        error=artifact.error,
    )
    ev_id = generate_evidence_id(
        evidence_type=EvidenceType.PROCESS.value,
        entity_data=entity.model_dump(),
        host=host,
        collector=collector,
    )
    collected_at = artifact.start_time or _utc_now()
    provenance = EvidenceProvenance(
        collector=collector,
        adapter="endpoint",
        source=f"host:{host}",
        collection_method="psutil.process_iter",
        collected_at=collected_at,
        host=host,
        case_id=case_id,
    )
    record_payload = {
        "id": ev_id,
        "type": EvidenceType.PROCESS.value,
        "source": "endpoint",
        "timestamp": collected_at,
        "confidence": 1.0,
        "entity": entity.model_dump(),
        "relationships": [],
        "provenance": provenance.model_dump(),
    }
    digest = canonical_hash(record_payload)
    integrity = EvidenceIntegrity(algorithm="SHA-256", value=digest)

    return UniversalEvidence(
        id=ev_id,
        type=EvidenceType.PROCESS,
        source="endpoint",
        timestamp=collected_at,
        confidence=1.0,
        entity=entity,
        relationships=[],
        provenance=provenance,
        integrity=integrity,
    )


def system_artifact_to_evidence(
    artifact: SystemArtifact,
    host: str,
    case_id: Optional[str] = None,
    collector: str = "EndpointAdapter",
) -> UniversalEvidence:
    """Convert a SystemArtifact into a UniversalEvidence instance."""
    entity = SystemEntity(
        hostname=artifact.hostname,
        os=artifact.os,
        architecture=artifact.architecture,
        kernel=artifact.kernel,
        runtime=artifact.runtime,
        cpu_count=artifact.cpu_count,
        memory_total_bytes=artifact.memory_total_bytes,
        boot_time=artifact.boot_time,
    )
    ev_id = generate_evidence_id(
        evidence_type=EvidenceType.SYSTEM.value,
        entity_data=entity.model_dump(),
        host=host,
        collector=collector,
    )
    collected_at = artifact.boot_time or _utc_now()
    provenance = EvidenceProvenance(
        collector=collector,
        adapter="endpoint",
        source=f"host:{host}",
        collection_method="platform.uname",
        collected_at=collected_at,
        host=host,
        case_id=case_id,
    )
    record_payload = {
        "id": ev_id,
        "type": EvidenceType.SYSTEM.value,
        "source": "endpoint",
        "timestamp": collected_at,
        "confidence": 1.0,
        "entity": entity.model_dump(),
        "relationships": [],
        "provenance": provenance.model_dump(),
    }
    digest = canonical_hash(record_payload)
    integrity = EvidenceIntegrity(algorithm="SHA-256", value=digest)

    return UniversalEvidence(
        id=ev_id,
        type=EvidenceType.SYSTEM,
        source="endpoint",
        timestamp=collected_at,
        confidence=1.0,
        entity=entity,
        relationships=[],
        provenance=provenance,
        integrity=integrity,
    )


def network_connection_to_evidence(
    conn: NetworkConnection,
    host: str,
    case_id: Optional[str] = None,
    collector: str = "NetworkAdapter",
) -> UniversalEvidence:
    """Convert a NetworkConnection into a UniversalEvidence instance."""
    entity = NetworkConnectionEntity(
        protocol=conn.protocol,
        local_address=conn.local_address,
        local_port=conn.local_port,
        remote_address=conn.remote_address,
        remote_port=conn.remote_port,
        status=conn.status,
        pid=conn.pid,
        process_name=conn.process_name,
        timestamp=conn.timestamp,
        direction=conn.direction,
        risk_indicators=conn.risk_indicators,
    )
    ev_id = generate_evidence_id(
        evidence_type=EvidenceType.NETWORK_CONNECTION.value,
        entity_data=entity.model_dump(),
        host=host,
        collector=collector,
    )
    collected_at = conn.timestamp or _utc_now()
    provenance = EvidenceProvenance(
        collector=collector,
        adapter="network",
        source=f"host:{host}",
        collection_method="psutil.net_connections",
        collected_at=collected_at,
        host=host,
        case_id=case_id,
    )
    record_payload = {
        "id": ev_id,
        "type": EvidenceType.NETWORK_CONNECTION.value,
        "source": "network",
        "timestamp": collected_at,
        "confidence": 1.0,
        "entity": entity.model_dump(),
        "relationships": [],
        "provenance": provenance.model_dump(),
    }
    digest = canonical_hash(record_payload)
    integrity = EvidenceIntegrity(algorithm="SHA-256", value=digest)

    return UniversalEvidence(
        id=ev_id,
        type=EvidenceType.NETWORK_CONNECTION,
        source="network",
        timestamp=collected_at,
        confidence=1.0,
        entity=entity,
        relationships=[],
        provenance=provenance,
        integrity=integrity,
    )


def network_listener_to_evidence(
    listener: NetworkListener,
    host: str,
    case_id: Optional[str] = None,
    collector: str = "NetworkAdapter",
    collected_at: Optional[str] = None,
) -> UniversalEvidence:
    """Convert a NetworkListener into a UniversalEvidence instance."""
    entity = NetworkListenerEntity(
        protocol=listener.protocol,
        local_address=listener.local_address,
        local_port=listener.local_port,
        pid=listener.pid,
        process_name=listener.process_name,
        status=listener.status,
        risk_indicators=listener.risk_indicators,
    )
    ev_id = generate_evidence_id(
        evidence_type=EvidenceType.NETWORK_LISTENER.value,
        entity_data=entity.model_dump(),
        host=host,
        collector=collector,
    )
    timestamp_str = collected_at or _utc_now()
    provenance = EvidenceProvenance(
        collector=collector,
        adapter="network",
        source=f"host:{host}",
        collection_method="psutil.net_connections",
        collected_at=timestamp_str,
        host=host,
        case_id=case_id,
    )
    record_payload = {
        "id": ev_id,
        "type": EvidenceType.NETWORK_LISTENER.value,
        "source": "network",
        "timestamp": timestamp_str,
        "confidence": 1.0,
        "entity": entity.model_dump(),
        "relationships": [],
        "provenance": provenance.model_dump(),
    }
    digest = canonical_hash(record_payload)
    integrity = EvidenceIntegrity(algorithm="SHA-256", value=digest)

    return UniversalEvidence(
        id=ev_id,
        type=EvidenceType.NETWORK_LISTENER,
        source="network",
        timestamp=timestamp_str,
        confidence=1.0,
        entity=entity,
        relationships=[],
        provenance=provenance,
        integrity=integrity,
    )


def dns_record_to_evidence(
    dns: DNSRecord,
    host: str,
    case_id: Optional[str] = None,
    collector: str = "NetworkAdapter",
) -> UniversalEvidence:
    """Convert a DNSRecord into a UniversalEvidence instance."""
    entity = DNSRecordEntity(
        domain=dns.domain,
        addresses=dns.addresses,
        query_time=dns.query_time,
        status=dns.status,
        error=dns.error,
    )
    ev_id = generate_evidence_id(
        evidence_type=EvidenceType.DNS_RECORD.value,
        entity_data=entity.model_dump(),
        host=host,
        collector=collector,
    )
    collected_at = dns.query_time or _utc_now()
    provenance = EvidenceProvenance(
        collector=collector,
        adapter="network",
        source=f"host:{host}",
        collection_method="socket.getaddrinfo",
        collected_at=collected_at,
        host=host,
        case_id=case_id,
    )
    record_payload = {
        "id": ev_id,
        "type": EvidenceType.DNS_RECORD.value,
        "source": "network",
        "timestamp": collected_at,
        "confidence": 1.0,
        "entity": entity.model_dump(),
        "relationships": [],
        "provenance": provenance.model_dump(),
    }
    digest = canonical_hash(record_payload)
    integrity = EvidenceIntegrity(algorithm="SHA-256", value=digest)

    return UniversalEvidence(
        id=ev_id,
        type=EvidenceType.DNS_RECORD,
        source="network",
        timestamp=collected_at,
        confidence=1.0,
        entity=entity,
        relationships=[],
        provenance=provenance,
        integrity=integrity,
    )


def endpoint_result_to_evidence(
    result: EndpointResult,
    case_id: Optional[str] = None,
    collector: Optional[str] = None,
) -> List[UniversalEvidence]:
    """Convert an entire EndpointResult into a list of UniversalEvidence instances."""
    col = collector or f"EndpointAdapter:{result.operation}"
    evidence_items: List[UniversalEvidence] = []

    for art in result.artifacts:
        if isinstance(art, FileArtifact) or (isinstance(art, dict) and art.get("type") == "FILE"):
            obj = art if isinstance(art, FileArtifact) else FileArtifact(**art)
            evidence_items.append(file_artifact_to_evidence(obj, host=result.host, case_id=case_id, collector=col))
        elif isinstance(art, ProcessArtifact) or (isinstance(art, dict) and art.get("type") == "PROCESS"):
            obj = art if isinstance(art, ProcessArtifact) else ProcessArtifact(**art)
            evidence_items.append(process_artifact_to_evidence(obj, host=result.host, case_id=case_id, collector=col))
        elif isinstance(art, SystemArtifact) or (isinstance(art, dict) and art.get("type") == "SYSTEM"):
            obj = art if isinstance(art, SystemArtifact) else SystemArtifact(**art)
            evidence_items.append(system_artifact_to_evidence(obj, host=result.host, case_id=case_id, collector=col))

    return evidence_items


def network_result_to_evidence(
    result: NetworkResult,
    case_id: Optional[str] = None,
    collector: Optional[str] = None,
) -> List[UniversalEvidence]:
    """Convert an entire NetworkResult into a list of UniversalEvidence instances."""
    col = collector or "NetworkAdapter:ANALYZE_NETWORK"
    evidence_items: List[UniversalEvidence] = []

    for conn in result.connections:
        evidence_items.append(network_connection_to_evidence(conn, host=result.host, case_id=case_id, collector=col))
    for listener in result.listeners:
        evidence_items.append(network_listener_to_evidence(listener, host=result.host, case_id=case_id, collector=col, collected_at=result.timestamp))
    for dns in result.dns_records:
        evidence_items.append(dns_record_to_evidence(dns, host=result.host, case_id=case_id, collector=col))

    return evidence_items


def extract_grounded_relationships(
    evidence_items: List[UniversalEvidence],
) -> List[Relationship]:
    """
    Extract strictly evidence-grounded relationships between items.
    Rules:
    - PROCESS -> CONNECTS_TO -> NETWORK_CONNECTION:
        Created ONLY when a process and a network connection share an explicit non-zero PID.
    - PROCESS -> LISTENING_ON -> NETWORK_LISTENER:
        Created ONLY when a process and a listening socket share an explicit non-zero PID.
    - DNS_RECORD -> RESOLVES_TO -> IP:
        Created ONLY from explicit resolved answer addresses in the DNS record.

    No relationships are invented or inferred without direct grounded attribute matches.
    """
    relationships: List[Relationship] = []
    rel_ids_seen = set()

    # Index processes by PID
    processes_by_pid: Dict[int, List[UniversalEvidence]] = {}
    for ev in evidence_items:
        if ev.type == EvidenceType.PROCESS and hasattr(ev.entity, "pid"):
            pid = ev.entity.pid
            if pid is not None and pid > 0:
                processes_by_pid.setdefault(pid, []).append(ev)

    for ev in evidence_items:
        # Grounded connection linking
        if ev.type == EvidenceType.NETWORK_CONNECTION and hasattr(ev.entity, "pid"):
            pid = ev.entity.pid
            if pid is not None and pid in processes_by_pid:
                for proc_ev in processes_by_pid[pid]:
                    rel = Relationship.create(
                        rel_type=RelationshipType.CONNECTS_TO,
                        source_id=proc_ev.id,
                        target_id=ev.id,
                        confidence=1.0,
                        supporting_evidence=[proc_ev.id, ev.id],
                        metadata={
                            "pid": pid,
                            "process_name": getattr(ev.entity, "process_name", None),
                            "remote": f"{getattr(ev.entity, 'remote_address', '')}:{getattr(ev.entity, 'remote_port', '')}",
                        },
                    )
                    if rel.id not in rel_ids_seen:
                        rel_ids_seen.add(rel.id)
                        relationships.append(rel)

        # Grounded listener linking
        elif ev.type == EvidenceType.NETWORK_LISTENER and hasattr(ev.entity, "pid"):
            pid = ev.entity.pid
            if pid is not None and pid in processes_by_pid:
                for proc_ev in processes_by_pid[pid]:
                    rel = Relationship.create(
                        rel_type=RelationshipType.LISTENING_ON,
                        source_id=proc_ev.id,
                        target_id=ev.id,
                        confidence=1.0,
                        supporting_evidence=[proc_ev.id, ev.id],
                        metadata={
                            "pid": pid,
                            "process_name": getattr(ev.entity, "process_name", None),
                            "local": f"{getattr(ev.entity, 'local_address', '')}:{getattr(ev.entity, 'local_port', '')}",
                        },
                    )
                    if rel.id not in rel_ids_seen:
                        rel_ids_seen.add(rel.id)
                        relationships.append(rel)

        # Grounded DNS resolution linking
        elif ev.type == EvidenceType.DNS_RECORD and hasattr(ev.entity, "addresses"):
            addresses = getattr(ev.entity, "addresses", [])
            for addr in addresses:
                target_id = f"ip-{addr}"
                rel = Relationship.create(
                    rel_type=RelationshipType.RESOLVES_TO,
                    source_id=ev.id,
                    target_id=target_id,
                    confidence=1.0,
                    supporting_evidence=[ev.id],
                    metadata={"domain": getattr(ev.entity, "domain", ""), "address": addr},
                )
                if rel.id not in rel_ids_seen:
                    rel_ids_seen.add(rel.id)
                    relationships.append(rel)

    return relationships


def build_evidence_package(
    case_id: str,
    host: str,
    evidence: List[UniversalEvidence],
    relationships: Optional[List[Relationship]] = None,
    metadata: Optional[Dict[str, Any]] = None,
    created_at: Optional[str] = None,
    correlations: Optional[List[Dict[str, Any]]] = None,
    graph: Optional[Dict[str, Any]] = None,
) -> EvidencePackage:
    """
    Collate a list of UniversalEvidence items, their grounded relationships,
    and optional correlation findings into a cryptographically hashed EvidencePackage.

    InvestigationGraph is a derived view and is NOT included in the canonical
    package_hash computation.
    """
    rels = (
        relationships
        if relationships is not None
        else extract_grounded_relationships(evidence)
    )
    corrs = correlations or []
    pkg_created_at = created_at or _utc_now()
    meta = metadata or {}

    # Compute deterministic package hash over all fields (excluding graph)
    temp_dict = {
        "case_id": case_id,
        "correlations": corrs,
        "created_at": pkg_created_at,
        "evidence": [e.to_dict() for e in evidence],
        "host": host,
        "metadata": meta,
        "relationships": [r.model_dump() for r in rels],
    }
    pkg_hash = canonical_hash(temp_dict)

    return EvidencePackage(
        case_id=case_id,
        host=host,
        created_at=pkg_created_at,
        evidence=evidence,
        relationships=rels,
        correlations=corrs,
        graph=graph,
        metadata=meta,
        package_hash=pkg_hash,
    )



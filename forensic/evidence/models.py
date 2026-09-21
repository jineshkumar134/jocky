"""
JOCKY Forensic — Universal Evidence Data Models
===============================================
Defines the strongly-typed Universal Evidence Model schemas:
- EvidenceType & RelationshipType Enums
- Strongly typed Entity models (File, Process, System, Network, DNS, and future Blockchain)
- Relationship model for grounded entity linking
- EvidenceProvenance & EvidenceIntegrity
- UniversalEvidence core model with deterministic hashing
- EvidencePackage aggregate for case collation and cryptographic integrity
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Literal, Optional, Union

from pydantic import BaseModel, Field, field_validator

from forensic.evidence.canonical import (
    canonical_hash,
    canonical_json,
    generate_evidence_id,
    generate_relationship_id,
)


# ──────────────────────────────────────────────────────────
# Evidence and Relationship Type Enums
# ──────────────────────────────────────────────────────────

class EvidenceType(str, Enum):
    """
    Standardized classification of evidence items across JOCKY forensic modules.
    """
    # Active Phase 4 & 5 types
    FILE = "FILE"
    PROCESS = "PROCESS"
    SYSTEM = "SYSTEM"
    NETWORK_CONNECTION = "NETWORK_CONNECTION"
    NETWORK_LISTENER = "NETWORK_LISTENER"
    DNS_RECORD = "DNS_RECORD"

    # Future-compatible reserved types (Phase 7+)
    WALLET = "WALLET"
    TRANSACTION = "TRANSACTION"
    VASP = "VASP"
    BLOCKCHAIN_EVENT = "BLOCKCHAIN_EVENT"


class RelationshipType(str, Enum):
    """
    Standardized relation types between forensic entities.
    """
    # Active Phase 6 types
    CONNECTS_TO = "CONNECTS_TO"
    EXECUTED = "EXECUTED"
    RESOLVES_TO = "RESOLVES_TO"
    LISTENING_ON = "LISTENING_ON"
    SPAWNED = "SPAWNED"
    ACCESSED = "ACCESSED"

    # Future-compatible reserved types (Phase 7+)
    SENT_TO = "SENT_TO"
    ATTRIBUTED_TO = "ATTRIBUTED_TO"
    ASSOCIATED_WITH = "ASSOCIATED_WITH"


# ──────────────────────────────────────────────────────────
# Entity Models
# ──────────────────────────────────────────────────────────

class BaseEntity(BaseModel):
    """Base class for all forensic entities."""
    type: str

    model_config = {"frozen": True, "extra": "allow"}


class FileEntity(BaseEntity):
    type: Literal["FILE"] = "FILE"
    path: str
    name: str
    extension: str = ""
    size: int
    sha256: str
    modified_at: str
    created_at: Optional[str] = None
    accessed_at: Optional[str] = None
    file_type: str = "other"
    error: Optional[str] = None


class ProcessEntity(BaseEntity):
    type: Literal["PROCESS"] = "PROCESS"
    pid: int
    name: str
    parent_pid: Optional[int] = None
    executable: Optional[str] = None
    username: Optional[str] = None
    start_time: Optional[str] = None
    status: str = "running"
    error: Optional[str] = None


class SystemEntity(BaseEntity):
    type: Literal["SYSTEM"] = "SYSTEM"
    hostname: str
    os: str
    architecture: str
    kernel: str
    runtime: str
    cpu_count: Optional[int] = None
    memory_total_bytes: Optional[int] = None
    boot_time: Optional[str] = None


class NetworkConnectionEntity(BaseEntity):
    type: Literal["NETWORK_CONNECTION"] = "NETWORK_CONNECTION"
    protocol: str = "TCP"
    local_address: str
    local_port: int
    remote_address: Optional[str] = None
    remote_port: Optional[int] = None
    status: str = "ESTABLISHED"
    pid: Optional[int] = None
    process_name: Optional[str] = None
    timestamp: Optional[str] = None
    direction: Optional[str] = None
    risk_indicators: List[str] = Field(default_factory=list)


class NetworkListenerEntity(BaseEntity):
    type: Literal["NETWORK_LISTENER"] = "NETWORK_LISTENER"
    protocol: str = "TCP"
    local_address: str
    local_port: int
    pid: Optional[int] = None
    process_name: Optional[str] = None
    status: str = "LISTEN"
    risk_indicators: List[str] = Field(default_factory=list)


class DNSRecordEntity(BaseEntity):
    type: Literal["DNS_RECORD"] = "DNS_RECORD"
    domain: str
    addresses: List[str] = Field(default_factory=list)
    query_time: Optional[str] = None
    status: str = "RESOLVED"
    error: Optional[str] = None


# ──────────────────────────────────────────────────────────
# Blockchain Forensic Entities (Phase 7)
# ──────────────────────────────────────────────────────────

class WalletEntity(BaseEntity):
    type: Literal["WALLET"] = "WALLET"
    address: str
    chain: str = "ethereum"
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    label: Optional[str] = None
    wallet_type: str = "unknown"
    confidence: float = 1.0
    balance: Optional[float] = 0.0


class TransactionEntity(BaseEntity):
    type: Literal["TRANSACTION"] = "TRANSACTION"
    tx_hash: str
    chain: str = "ethereum"
    block_number: Optional[int] = None
    timestamp: str
    from_address: str
    to_address: str
    asset: str = "ETH"
    amount: float
    status: str = "confirmed"
    transaction_type: str = "transfer"
    metadata: Dict[str, Any] = Field(default_factory=dict)


class VASPEntity(BaseEntity):
    type: Literal["VASP"] = "VASP"
    vasp_id: str
    name: str
    score: float = 1.0
    confidence: float = 1.0
    reasons: List[str] = Field(default_factory=list)
    matched_wallets: List[str] = Field(default_factory=list)
    supporting_tx_hashes: List[str] = Field(default_factory=list)
    scoring_breakdown: Dict[str, float] = Field(default_factory=dict)
    jurisdiction: Optional[str] = None
    risk_rating: Optional[str] = None


class BlockchainEventEntity(BaseEntity):
    type: Literal["BLOCKCHAIN_EVENT"] = "BLOCKCHAIN_EVENT"
    event_id: str = ""
    event_name: str
    contract_address: str
    chain: str = "ethereum"
    block_number: Optional[int] = None
    timestamp: Optional[str] = None
    parameters: Dict[str, Any] = Field(default_factory=dict)


AnyEntity = Union[
    FileEntity,
    ProcessEntity,
    SystemEntity,
    NetworkConnectionEntity,
    NetworkListenerEntity,
    DNSRecordEntity,
    WalletEntity,
    TransactionEntity,
    VASPEntity,
    BlockchainEventEntity,
    Dict[str, Any],
]


# ──────────────────────────────────────────────────────────
# Provenance & Integrity Models
# ──────────────────────────────────────────────────────────

class EvidenceProvenance(BaseModel):
    """
    Forensic chain of custody and origin metadata.
    """
    collector: str
    adapter: str
    source: str
    collection_method: str
    collected_at: str
    host: str
    case_id: Optional[str] = None

    model_config = {"frozen": True}


class EvidenceIntegrity(BaseModel):
    """
    Cryptographic integrity representation for the evidence record.
    """
    algorithm: Literal["SHA-256"] = "SHA-256"
    value: str

    model_config = {"frozen": True}


# ──────────────────────────────────────────────────────────
# Relationship Model
# ──────────────────────────────────────────────────────────

class Relationship(BaseModel):
    """
    Strictly evidence-grounded link between two entities/evidence items.
    """
    id: str
    type: RelationshipType
    source_id: str
    target_id: str
    timestamp: Optional[str] = None
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    supporting_evidence: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = {"frozen": True}

    @classmethod
    def create(
        cls,
        rel_type: Union[RelationshipType, str],
        source_id: str,
        target_id: str,
        timestamp: Optional[str] = None,
        confidence: float = 1.0,
        supporting_evidence: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Relationship:
        """Create a Relationship with a deterministic ID."""
        r_type = RelationshipType(rel_type) if isinstance(rel_type, str) else rel_type
        r_id = generate_relationship_id(r_type.value, source_id, target_id)
        return cls(
            id=r_id,
            type=r_type,
            source_id=source_id,
            target_id=target_id,
            timestamp=timestamp,
            confidence=confidence,
            supporting_evidence=supporting_evidence or [],
            metadata=metadata or {},
        )


# ──────────────────────────────────────────────────────────
# Universal Evidence Model
# ──────────────────────────────────────────────────────────

class UniversalEvidence(BaseModel):
    """
    Universal Evidence Model: Unified, strongly typed, and verifiable
    representation of forensic facts across JOCKY modules.
    """
    id: str
    type: EvidenceType
    source: str
    timestamp: str
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    entity: AnyEntity
    relationships: List[Relationship] = Field(default_factory=list)
    provenance: EvidenceProvenance
    integrity: EvidenceIntegrity

    model_config = {"frozen": True}

    @field_validator("confidence")
    @classmethod
    def validate_confidence_range(cls, v: float) -> float:
        if not (0.0 <= v <= 1.0):
            raise ValueError(f"Confidence must be between 0.0 and 1.0, got {v}")
        return round(float(v), 4)

    @property
    def hash(self) -> str:
        """Convenience property for integrity hash value."""
        return self.integrity.value

    def compute_integrity_hash(self) -> str:
        """
        Compute the SHA-256 digest of the canonical JSON representation
        of this evidence record, excluding the mutable integrity field.
        """
        raw_dict = self.to_dict()
        raw_dict.pop("integrity", None)
        return canonical_hash(raw_dict)

    def verify_integrity(self) -> bool:
        """Verify that the current data matches the recorded integrity hash."""
        return self.compute_integrity_hash() == self.integrity.value

    def to_dict(self) -> Dict[str, Any]:
        """Convert to clean, JSON-serializable Python dictionary."""
        d = self.model_dump()
        d["type"] = self.type.value
        if hasattr(self.entity, "model_dump"):
            d["entity"] = self.entity.model_dump()
        d["provenance"] = self.provenance.model_dump()
        d["integrity"] = self.integrity.model_dump()
        d["relationships"] = [r.model_dump() for r in self.relationships]
        return d


# ──────────────────────────────────────────────────────────
# Evidence Package Model
# ──────────────────────────────────────────────────────────

class EvidencePackage(BaseModel):
    """
    Comprehensive collection of universal evidence items, grounded relationships,
    and correlation findings for a given investigation case.

    Fields
    ------
    evidence:
        All UniversalEvidence items collected by the investigation.
    relationships:
        Grounded evidence-to-evidence relationships (PID match, DNS resolution, etc.)
    correlations:
        Cross-domain correlation findings produced by the Correlation Engine.
        Stored as plain dicts to avoid circular imports; validated by the engine.
        Original evidence records are NOT duplicated — correlations reference IDs only.
    metadata:
        Arbitrary case-level metadata.
    package_hash:
        SHA-256 of the canonical JSON of the full package (excluding this field).
    """
    case_id: str
    host: str
    created_at: str
    evidence: List[UniversalEvidence] = Field(default_factory=list)
    relationships: List[Relationship] = Field(default_factory=list)
    correlations: List[Dict[str, Any]] = Field(default_factory=list)
    graph: Optional[Dict[str, Any]] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    package_hash: str = ""

    model_config = {"frozen": True}

    def compute_package_hash(self) -> str:
        """
        Compute the SHA-256 digest of the package contents excluding package_hash and graph.
        The InvestigationGraph is a derived view and does not affect package integrity.
        """
        raw_dict = self.to_dict()
        raw_dict.pop("package_hash", None)
        raw_dict.pop("graph", None)
        return canonical_hash(raw_dict)

    def verify_package_integrity(self) -> bool:
        """Verify the package hash against its contents."""
        return self.compute_package_hash() == self.package_hash

    def to_dict(self) -> Dict[str, Any]:
        """Convert to JSON-serializable dictionary."""
        d = self.model_dump()
        d["evidence"] = [e.to_dict() for e in self.evidence]
        d["relationships"] = [r.model_dump() for r in self.relationships]
        # correlations already serialized as plain dicts
        if self.graph is None:
            d.pop("graph", None)
        return d



    def to_json(self, indent: int = 2) -> str:
        """Serialize package to formatted JSON string."""
        import json
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)


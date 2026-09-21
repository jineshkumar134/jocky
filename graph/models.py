"""
JOCKY Investigation Graph — Data Models
=======================================
Defines strongly typed Pydantic v2 models for:
- GraphNodeType: Enum matching Universal Evidence types (no synthetic HOST node).
- GraphNode: Nodes referencing existing UniversalEvidence items.
- GraphEdge: Directed edges derived strictly from grounded relationships or Phase 8 correlations.
- InvestigationGraph: Directed graph with adjacency indexing and canonical integrity hashing.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


class GraphNodeType(str, Enum):
    """
    Standardized classification of graph nodes matching UniversalEvidence types.
    Note: 'host' is metadata on the graph container, not a synthetic node.
    """
    FILE = "FILE"
    PROCESS = "PROCESS"
    SYSTEM = "SYSTEM"
    NETWORK_CONNECTION = "NETWORK_CONNECTION"
    NETWORK_LISTENER = "NETWORK_LISTENER"
    DNS_RECORD = "DNS_RECORD"
    WALLET = "WALLET"
    TRANSACTION = "TRANSACTION"
    VASP = "VASP"
    BLOCKCHAIN_EVENT = "BLOCKCHAIN_EVENT"


class GraphNode(BaseModel):
    """
    Graph node representing a UniversalEvidence entity in the investigation.

    ID is guaranteed to match the UniversalEvidence ID.
    """
    id: str
    node_type: GraphNodeType
    evidence_id: str
    label: str
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = {"frozen": True}

    @field_validator("confidence", mode="before")
    @classmethod
    def clamp_confidence(cls, v: float) -> float:
        return round(max(0.0, min(1.0, float(v))), 4)

    def to_dict(self) -> Dict[str, Any]:
        d = self.model_dump()
        d["node_type"] = self.node_type.value
        return d


class GraphEdge(BaseModel):
    """
    Directed relationship between two forensic graph nodes.

    Edges are derived strictly from:
    1. Grounded relationships in EvidencePackage (Phase 6)
    2. Grounded correlation findings from CorrelationEngine (Phase 8)
    """
    id: str
    source_id: str
    target_id: str
    relationship_type: str
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    evidence_ids: List[str] = Field(default_factory=list)
    correlation_id: Optional[str] = None
    timestamp: Optional[str] = None
    label: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = {"frozen": True}

    @field_validator("confidence", mode="before")
    @classmethod
    def clamp_confidence(cls, v: float) -> float:
        return round(max(0.0, min(1.0, float(v))), 4)

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()


class InvestigationGraph(BaseModel):
    """
    In-memory representation of an interconnected investigation graph.

    Maintains nodes, edges, adjacency lookups, and a deterministic graph hash.
    """
    case_id: str
    host: str
    nodes: List[GraphNode] = Field(default_factory=list)
    edges: List[GraphEdge] = Field(default_factory=list)
    generated_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    graph_hash: str = ""
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = {"frozen": True}

    # Fast in-memory lookup indices (initialized dynamically or cached)
    def _get_node_map(self) -> Dict[str, GraphNode]:
        return {n.id: n for n in self.nodes}

    def _get_edge_map(self) -> Dict[str, GraphEdge]:
        return {e.id: e for e in self.edges}

    def _get_outgoing_map(self) -> Dict[str, List[GraphEdge]]:
        adj: Dict[str, List[GraphEdge]] = {n.id: [] for n in self.nodes}
        for e in self.edges:
            if e.source_id in adj:
                adj[e.source_id].append(e)
            else:
                adj[e.source_id] = [e]
        return adj

    def _get_incoming_map(self) -> Dict[str, List[GraphEdge]]:
        adj: Dict[str, List[GraphEdge]] = {n.id: [] for n in self.nodes}
        for e in self.edges:
            if e.target_id in adj:
                adj[e.target_id].append(e)
            else:
                adj[e.target_id] = [e]
        return adj

    def get_node(self, node_id: str) -> Optional[GraphNode]:
        """Look up a node by its ID."""
        for n in self.nodes:
            if n.id == node_id:
                return n
        return None

    def get_edge(self, edge_id: str) -> Optional[GraphEdge]:
        """Look up an edge by its ID."""
        for e in self.edges:
            if e.id == edge_id:
                return e
        return None

    def verify_integrity(self) -> bool:
        """Verify that the recorded graph_hash matches the computed graph hash."""
        from graph.serialization import compute_graph_hash
        return compute_graph_hash(self) == self.graph_hash

    def to_dict(self) -> Dict[str, Any]:
        """Convert graph to a JSON-serializable dictionary."""
        return {
            "case_id": self.case_id,
            "host": self.host,
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
            "generated_at": self.generated_at,
            "graph_hash": self.graph_hash,
            "metadata": self.metadata,
        }

    def to_json(self, indent: int = 2) -> str:
        """Serialize to formatted JSON string."""
        import json
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

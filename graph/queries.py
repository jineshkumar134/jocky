"""
JOCKY Investigation Graph — Query Engine
========================================
Provides deterministic graph traversal and query capabilities:
- Neighbor, incoming, and outgoing edge lookups
- Node filtering by type and edge filtering by relationship/confidence
- Deterministic BFS path finding (sorted neighbor ordering)
- Cross-domain investigation chain discovery (PROCESS -> ... -> VASP)
- Weakest-link path confidence calculation:
    path_confidence = min(edge.confidence for edge in path_edges)
"""

from __future__ import annotations

from collections import deque
from typing import Any, Dict, List, Optional, Set, Tuple

from pydantic import BaseModel, Field

from graph.models import GraphEdge, GraphNode, GraphNodeType, InvestigationGraph


class PathResult(BaseModel):
    """
    Structured outcome of traversing an investigation chain.

    Confidence is strictly determined by the weakest-link principle:
        confidence = min(edge.confidence for edge in edges)
    """
    node_ids: List[str]
    nodes: List[GraphNode]
    edge_ids: List[str]
    edges: List[GraphEdge]
    edge_confidences: List[float]
    confidence: float

    model_config = {"frozen": True}

    def format_chain(self) -> str:
        """Return a human-readable chain representation."""
        if not self.nodes:
            return "(Empty Path)"
        parts = []
        for i, node in enumerate(self.nodes):
            parts.append(f"{node.node_type.value} ({node.label})")
            if i < len(self.edges):
                edge = self.edges[i]
                parts.append(f"  ↓ {edge.relationship_type} [conf: {edge.confidence:.2f}]")
        return "\n".join(parts)


def get_outgoing_edges(graph: InvestigationGraph, node_id: str) -> List[GraphEdge]:
    """Return all directed edges originating from node_id, sorted deterministically by ID."""
    edges = [e for e in graph.edges if e.source_id == node_id]
    return sorted(edges, key=lambda e: (e.id, e.target_id))


def get_incoming_edges(graph: InvestigationGraph, node_id: str) -> List[GraphEdge]:
    """Return all directed edges terminating at node_id, sorted deterministically by ID."""
    edges = [e for e in graph.edges if e.target_id == node_id]
    return sorted(edges, key=lambda e: (e.id, e.source_id))


def get_neighbors(graph: InvestigationGraph, node_id: str) -> List[GraphNode]:
    """
    Return all directly adjacent nodes (both outgoing and incoming),
    sorted deterministically by node ID.
    """
    node_map = graph._get_node_map()
    neighbor_ids: Set[str] = set()

    for e in graph.edges:
        if e.source_id == node_id:
            neighbor_ids.add(e.target_id)
        elif e.target_id == node_id:
            neighbor_ids.add(e.source_id)

    neighbors = [node_map[nid] for nid in neighbor_ids if nid in node_map]
    return sorted(neighbors, key=lambda n: n.id)


def find_nodes_by_type(graph: InvestigationGraph, node_type: Any) -> List[GraphNode]:
    """Find all graph nodes matching the specified GraphNodeType, sorted by ID."""
    target_val = node_type.value if hasattr(node_type, "value") else str(node_type)
    matched = [n for n in graph.nodes if n.node_type.value == target_val]
    return sorted(matched, key=lambda n: n.id)


def find_edges_by_relationship(graph: InvestigationGraph, relationship_type: str) -> List[GraphEdge]:
    """Find all graph edges matching the specified relationship type, sorted by ID."""
    matched = [e for e in graph.edges if e.relationship_type.upper() == relationship_type.upper()]
    return sorted(matched, key=lambda e: e.id)


def get_high_confidence_edges(graph: InvestigationGraph, threshold: float = 0.8) -> List[GraphEdge]:
    """Return edges with confidence greater than or equal to threshold, sorted descending by confidence then ID."""
    matched = [e for e in graph.edges if e.confidence >= threshold]
    return sorted(matched, key=lambda e: (-e.confidence, e.id))


def find_path(
    graph: InvestigationGraph,
    source_id: str,
    target_id: str,
    max_depth: int = 15,
) -> Optional[PathResult]:
    """
    Find the shortest directed path from source_id to target_id using BFS.
    Enforces deterministic traversal by sorting outgoing candidate edges by (target_id, edge_id).
    Calculates path confidence using the weakest-link principle: min(edge.confidence).
    """
    node_map = graph._get_node_map()
    if source_id not in node_map or target_id not in node_map:
        return None

    if source_id == target_id:
        node = node_map[source_id]
        return PathResult(
            node_ids=[node.id],
            nodes=[node],
            edge_ids=[],
            edges=[],
            edge_confidences=[],
            confidence=1.0,
        )

    # Queue contains: (current_node_id, [visited_node_ids], [path_edges])
    queue = deque([(source_id, [source_id], [])])
    visited: Set[str] = {source_id}

    while queue:
        curr_id, path_nodes, path_edges = queue.popleft()

        if len(path_nodes) > max_depth:
            continue

        outgoing = get_outgoing_edges(graph, curr_id)
        for edge in outgoing:
            nxt_id = edge.target_id

            if nxt_id == target_id:
                final_node_ids = path_nodes + [nxt_id]
                final_nodes = [node_map[nid] for nid in final_node_ids if nid in node_map]
                final_edges = path_edges + [edge]
                confidences = [round(e.confidence, 4) for e in final_edges]
                # Weakest-link principle: path confidence is min of edge confidences
                path_conf = round(min(confidences), 4) if confidences else 1.0

                return PathResult(
                    node_ids=final_node_ids,
                    nodes=final_nodes,
                    edge_ids=[e.id for e in final_edges],
                    edges=final_edges,
                    edge_confidences=confidences,
                    confidence=path_conf,
                )

            if nxt_id not in visited:
                visited.add(nxt_id)
                queue.append((nxt_id, path_nodes + [nxt_id], path_edges + [edge]))

    return None


def get_cross_domain_paths(graph: InvestigationGraph) -> List[PathResult]:
    """
    Discover all grounded cross-domain investigation chains connecting
    any PROCESS node to any VASP node.

    Results are sorted deterministically:
    1. Descending by path confidence (strongest path first)
    2. Ascending by path length
    3. Ascending by source node ID
    """
    processes = find_nodes_by_type(graph, GraphNodeType.PROCESS)
    vasps = find_nodes_by_type(graph, GraphNodeType.VASP)

    paths: List[PathResult] = []

    for proc in processes:
        for vasp in vasps:
            path = find_path(graph, proc.id, vasp.id)
            if path is not None and len(path.edges) >= 2:
                paths.append(path)

    # Sort deterministically
    paths.sort(key=lambda p: (-p.confidence, len(p.edges), p.node_ids[0] if p.node_ids else ""))
    return paths

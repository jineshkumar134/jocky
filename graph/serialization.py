"""
JOCKY Investigation Graph — Serialization & Integrity Hashing
=============================================================
Provides deterministic canonical hashing and serialization utilities for
InvestigationGraph instances.

Deterministic Hash Formula:
---------------------------
  payload = {
      "case_id": graph.case_id,
      "host": graph.host,
      "nodes": sorted([node.to_dict() for node in graph.nodes], key=lambda x: x["id"]),
      "edges": sorted([edge.to_dict() for edge in graph.edges], key=lambda x: x["id"]),
      "metadata": graph.metadata,
  }
  graph_hash = canonical_hash(payload)

Notice that volatile timestamps (like `generated_at`) are omitted from the
integrity digest to ensure exact determinism across repeated executions.
"""

from __future__ import annotations

import json
from typing import Any, Dict

from forensic.evidence.canonical import canonical_hash, canonical_json


def compute_graph_hash(graph_or_dict: Any) -> str:
    """
    Compute a deterministic SHA-256 digest over graph nodes, edges, case_id, host,
    and metadata. Omits generated_at and graph_hash.
    """
    if hasattr(graph_or_dict, "to_dict"):
        raw = graph_or_dict.to_dict()
    elif isinstance(graph_or_dict, dict):
        raw = dict(graph_or_dict)
    else:
        raise TypeError(f"Cannot compute graph hash for type {type(graph_or_dict)}")

    nodes = sorted(raw.get("nodes", []), key=lambda n: n.get("id", ""))
    edges = sorted(raw.get("edges", []), key=lambda e: e.get("id", ""))

    payload: Dict[str, Any] = {
        "case_id": raw.get("case_id", ""),
        "host": raw.get("host", ""),
        "nodes": nodes,
        "edges": edges,
        "metadata": raw.get("metadata", {}),
    }

    return canonical_hash(payload)


def graph_to_dict(graph: Any) -> Dict[str, Any]:
    """Serialize graph to dictionary."""
    if hasattr(graph, "to_dict"):
        return graph.to_dict()
    raise TypeError(f"Cannot serialize {type(graph)} to dict")


def graph_to_json(graph: Any, indent: int = 2) -> str:
    """Serialize graph to formatted JSON."""
    return json.dumps(graph_to_dict(graph), indent=indent, ensure_ascii=False)

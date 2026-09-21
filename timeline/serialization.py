"""
JOCKY Investigation Timeline — Serialization & Integrity Hashing
================================================================
Provides deterministic canonical hashing and serialization utilities for
InvestigationTimeline instances.

Deterministic Hash Formula:
---------------------------
  payload = {
      "case_id": timeline.case_id,
      "host": timeline.host,
      "events": [event.to_dict() for event in timeline.events],
      "summary": timeline.summary,
  }
  timeline_hash = canonical_hash(payload)

Notice that volatile timestamps (like `generated_at`) are strictly omitted
from the integrity digest to guarantee exact determinism.
"""

from __future__ import annotations

import json
from typing import Any, Dict

from forensic.evidence.canonical import canonical_hash


def compute_timeline_hash(timeline_or_dict: Any) -> str:
    """
    Compute a deterministic SHA-256 digest over timeline case_id, host,
    ordered events, and summary metrics. Omits volatile runtime timestamps.
    """
    if hasattr(timeline_or_dict, "to_dict"):
        raw = timeline_or_dict.to_dict()
    elif isinstance(timeline_or_dict, dict):
        raw = dict(timeline_or_dict)
    else:
        raise TypeError(f"Cannot compute timeline hash for type {type(timeline_or_dict)}")

    # Events are already in deterministic order; preserve fields
    events_payload = []
    for ev in raw.get("events", []):
        events_payload.append({
            "id": ev.get("id", ""),
            "timestamp": ev.get("timestamp"),
            "event_type": ev.get("event_type", ""),
            "title": ev.get("title", ""),
            "description": ev.get("description", ""),
            "evidence_ids": sorted(ev.get("evidence_ids", [])),
            "relationship_ids": sorted(ev.get("relationship_ids", [])),
            "correlation_ids": sorted(ev.get("correlation_ids", [])),
            "confidence": ev.get("confidence", 1.0),
            "source": ev.get("source", ""),
            "metadata": ev.get("metadata", {}),
        })

    payload: Dict[str, Any] = {
        "case_id": raw.get("case_id", ""),
        "host": raw.get("host", ""),
        "events": events_payload,
        "summary": raw.get("summary", {}),
    }

    return canonical_hash(payload)


def timeline_to_dict(timeline: Any) -> Dict[str, Any]:
    """Serialize timeline to dictionary."""
    if hasattr(timeline, "to_dict"):
        return timeline.to_dict()
    raise TypeError(f"Cannot serialize {type(timeline)} to dict")


def timeline_to_json(timeline: Any, indent: int = 2) -> str:
    """Serialize timeline to formatted JSON."""
    return json.dumps(timeline_to_dict(timeline), indent=indent, ensure_ascii=False)

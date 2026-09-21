"""
JOCKY Investigation Timeline — Queries
======================================
Provides deterministic filtering, temporal range queries, and evidence lookups
for InvestigationTimeline instances.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from timeline.models import InvestigationTimeline, TimelineEvent, TimelineEventType


def get_events_by_type(
    timeline: InvestigationTimeline, event_type: Any
) -> List[TimelineEvent]:
    """Return all events matching event_type."""
    target = event_type.value if hasattr(event_type, "value") else str(event_type)
    return [e for e in timeline.events if e.event_type.value == target]


def get_events_between(
    timeline: InvestigationTimeline, start_iso: str, end_iso: str
) -> List[TimelineEvent]:
    """Return timed events occurring within [start_iso, end_iso] inclusive."""
    matched = []
    for e in timeline.events:
        if e.timestamp and start_iso <= e.timestamp <= end_iso:
            matched.append(e)
    return matched


def get_events_for_evidence(
    timeline: InvestigationTimeline, evidence_id: str
) -> List[TimelineEvent]:
    """Return events referencing the given evidence_id."""
    return [e for e in timeline.events if evidence_id in e.evidence_ids]


def get_events_for_host(
    timeline: InvestigationTimeline, host: str
) -> List[TimelineEvent]:
    """Return events associated with host."""
    if timeline.host == host:
        return list(timeline.events)
    # Check event metadata
    return [e for e in timeline.events if e.metadata.get("host") == host]


def get_high_confidence_events(
    timeline: InvestigationTimeline, threshold: float = 0.8
) -> List[TimelineEvent]:
    """Return events with confidence >= threshold."""
    return [e for e in timeline.events if e.confidence >= threshold]


def get_latest_events(
    timeline: InvestigationTimeline, limit: int = 10
) -> List[TimelineEvent]:
    """Return the most recent timed events (or trailing events if untimed)."""
    timed = [e for e in timeline.events if e.timestamp is not None]
    if timed:
        return timed[-limit:]
    return timeline.events[-limit:]


def get_timeline_summary(timeline: InvestigationTimeline) -> Dict[str, Any]:
    """Return the summary dictionary for the timeline."""
    return dict(timeline.summary)


def get_events_for_correlation(
    timeline: InvestigationTimeline, correlation_id: str
) -> List[TimelineEvent]:
    """Return events referencing the given correlation_id."""
    return [e for e in timeline.events if correlation_id in e.correlation_ids]


def get_timed_events(timeline: InvestigationTimeline) -> List[TimelineEvent]:
    """Return all events with a non-null timestamp."""
    return [e for e in timeline.events if e.timestamp is not None]


def get_untimed_events(timeline: InvestigationTimeline) -> List[TimelineEvent]:
    """Return all events without a timestamp."""
    return [e for e in timeline.events if e.timestamp is None]

"""
JOCKY Investigation Timeline — Timeline Builder
===============================================
Constructs an InvestigationTimeline from an EvidencePackage, optional InvestigationGraph,
and optional CorrelationResult.

Ordering Rules:
---------------
1. Timed events appear first, sorted by ISO 8601 timestamp ascending.
2. Untimed events (timestamp = None) follow timed events.
3. Secondary sort key: event_type ascending.
4. Tertiary sort key: event ID ascending.

Safety & Integrity Rules:
-------------------------
- Never fabricate timestamps. If entity timestamp is missing, timestamp = None.
- Collection timestamp (provenance.collected_at) is preserved strictly in metadata.
- Identical input yields identical timeline_hash.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from forensic.evidence.canonical import canonical_hash
from forensic.evidence.models import EvidencePackage, EvidenceType, UniversalEvidence
from correlation.models import CorrelationFinding, CorrelationResult, CorrelationType
from graph.models import InvestigationGraph

from timeline.models import InvestigationTimeline, TimelineEvent, TimelineEventType
from timeline.serialization import compute_timeline_hash


class TimelineBuilder:
    """
    Constructs a deterministic InvestigationTimeline from evidence and correlations.
    """

    def build_from_package(
        self,
        package: EvidencePackage,
        graph: Optional[InvestigationGraph] = None,
        correlation_result: Optional[CorrelationResult] = None,
    ) -> InvestigationTimeline:
        """
        Build an InvestigationTimeline from an EvidencePackage.
        """
        events: List[TimelineEvent] = []

        # Index relationships by participant evidence IDs
        rel_map: Dict[str, List[str]] = {}
        for r in package.relationships:
            rel_map.setdefault(r.source_id, []).append(r.id)
            rel_map.setdefault(r.target_id, []).append(r.id)
            for supp in r.supporting_evidence:
                rel_map.setdefault(supp, []).append(r.id)

        # Index correlations by participant evidence IDs
        corr_map: Dict[str, List[str]] = {}
        findings_to_process: List[CorrelationFinding] = []
        if correlation_result and correlation_result.findings:
            findings_to_process.extend(correlation_result.findings)
        elif hasattr(package, "correlations") and package.correlations:
            for c_dict in package.correlations:
                try:
                    findings_to_process.append(CorrelationFinding(**c_dict))
                except Exception:
                    pass

        for f in findings_to_process:
            for eid in f.source_evidence_ids:
                corr_map.setdefault(eid, []).append(f.id)
            for eid in f.target_evidence_ids:
                corr_map.setdefault(eid, []).append(f.id)

        # 1. Convert UniversalEvidence items into TimelineEvents
        for ev in package.evidence:
            event = self._evidence_to_event(ev, rel_map, corr_map)
            if event:
                events.append(event)

        # 2. Add high-level synthetic correlation events (e.g. CROSS_DOMAIN)
        for f in findings_to_process:
            if f.correlation_type == CorrelationType.CROSS_DOMAIN:
                cross_ev = self._create_cross_domain_event(f, package.host)
                events.append(cross_ev)

        # 3. Deterministic Sorting:
        # Timed events first (timestamp asc), untimed events after (timestamp is None),
        # then event_type asc, then event ID asc.
        events.sort(
            key=lambda e: (
                1 if e.timestamp is None else 0,
                e.timestamp or "",
                e.event_type.value,
                e.id,
            )
        )

        # 4. Compute Summary
        summary = self._compute_summary(events)

        # 5. Build Prelim Timeline and Compute Hash
        prelim = InvestigationTimeline(
            case_id=package.case_id,
            host=package.host,
            events=events,
            summary=summary,
        )
        timeline_hash = compute_timeline_hash(prelim)

        return InvestigationTimeline(
            case_id=package.case_id,
            host=package.host,
            events=events,
            generated_at=prelim.generated_at,
            timeline_hash=timeline_hash,
            summary=summary,
        )

    def _evidence_to_event(
        self,
        ev: UniversalEvidence,
        rel_map: Dict[str, List[str]],
        corr_map: Dict[str, List[str]],
    ) -> Optional[TimelineEvent]:
        """Extract a TimelineEvent from an evidence item."""
        entity = ev.entity
        ev_type = ev.type

        timestamp: Optional[str] = None
        event_type: TimelineEventType
        def _get_val(key: str, default: Any = None) -> Any:
            if isinstance(entity, dict):
                return entity.get(key, default)
            return getattr(entity, key, default)

        title: str
        description: str

        if ev_type == EvidenceType.FILE:
            event_type = TimelineEventType.FILE
            name = _get_val("name", "File")
            # Files have modified_at or created_at
            timestamp = _get_val("modified_at") or _get_val("created_at")
            title = f"File Artifact: {name}"
            size = _get_val("size", 0)
            sha = str(_get_val("sha256", ""))[:12]
            description = f"Observed file '{name}' ({size} bytes, SHA256: {sha})."

        elif ev_type == EvidenceType.PROCESS:
            event_type = TimelineEventType.PROCESS
            name = _get_val("name", "Process")
            pid = _get_val("pid", "")
            # Processes have start_time if captured
            timestamp = _get_val("start_time")
            title = f"Process Activity: {name}"
            description = f"Process '{name}' (PID {pid}) executing on system."

        elif ev_type == EvidenceType.NETWORK_CONNECTION:
            event_type = TimelineEventType.NETWORK_CONNECTION
            rem = _get_val("remote_address", "unknown")
            rport = _get_val("remote_port", "")
            lport = _get_val("local_port", "")
            timestamp = _get_val("timestamp")
            title = f"Network Connection: {rem}:{rport}"
            description = f"TCP socket established from local port {lport} to {rem}:{rport}."

        elif ev_type == EvidenceType.NETWORK_LISTENER:
            event_type = TimelineEventType.NETWORK_LISTENER
            loc = _get_val("local_address", "0.0.0.0")
            port = _get_val("local_port", "")
            timestamp = None  # listeners are static sockets; do not fabricate
            title = f"Listening Socket: {loc}:{port}"
            description = f"Server socket listening on {loc}:{port}."

        elif ev_type == EvidenceType.DNS_RECORD:
            event_type = TimelineEventType.DNS_RECORD
            dom = _get_val("domain", "unknown")
            timestamp = _get_val("query_time")
            addrs = _get_val("addresses", [])
            title = f"DNS Resolution: {dom}"
            description = f"Domain '{dom}' resolved to: {', '.join(addrs)}."

        elif ev_type == EvidenceType.TRANSACTION:
            event_type = TimelineEventType.TRANSACTION
            tx = _get_val("tx_hash", "0xTX")
            amt = _get_val("amount", 0)
            asset = _get_val("asset", "ETH")
            from_a = _get_val("from_address", "")
            to_a = _get_val("to_address", "")
            timestamp = _get_val("timestamp")
            title = f"On-Chain Transaction: {tx[:10]}..."
            description = f"Transfer of {amt} {asset} from {from_a[:10]}... to {to_a[:10]}... (TX: {tx})."

        elif ev_type == EvidenceType.WALLET:
            event_type = TimelineEventType.WALLET
            addr = _get_val("address", "0x")
            lbl = _get_val("label", "Wallet")
            timestamp = None  # wallets have no single event timestamp
            title = f"Wallet Observed: {lbl}"
            description = f"Address {addr} identified as {lbl}."

        elif ev_type == EvidenceType.VASP:
            event_type = TimelineEventType.VASP_ATTRIBUTION
            name = _get_val("name", "VASP")
            timestamp = None  # VASP attributions are analytical views
            title = f"VASP Attribution: {name}"
            description = f"Institutional entity '{name}' attributed from transaction routing."

        elif ev_type == EvidenceType.SYSTEM:
            event_type = TimelineEventType.SYSTEM
            host = _get_val("hostname", "Host")
            timestamp = None  # do not use boot_time as event time without explicit reason
            title = f"System Profile: {host}"
            description = f"Hardware and operating system profile recorded for {host}."

        else:
            event_type = TimelineEventType.SYSTEM
            title = f"Evidence Item: {ev.id}"
            description = f"Universal evidence of type {ev_type}."
            timestamp = None

        # Build deterministic ID
        event_id = self._generate_event_id(event_type.value, ev.id, timestamp, title)

        # Provenance collection time in metadata only (never substituted as event timestamp)
        coll_time = ev.provenance.collected_at if ev.provenance else None
        meta = {
            "evidence_type": ev_type.value if hasattr(ev_type, "value") else str(ev_type),
            "collection_time": coll_time,
            "collector": ev.source,
        }

        # Matched relationships and correlations
        matched_rels = sorted(list(set(rel_map.get(ev.id, []))))
        matched_corrs = sorted(list(set(corr_map.get(ev.id, []))))

        return TimelineEvent(
            id=event_id,
            timestamp=timestamp,
            event_type=event_type,
            title=title,
            description=description,
            evidence_ids=[ev.id],
            relationship_ids=matched_rels,
            correlation_ids=matched_corrs,
            confidence=ev.confidence,
            source=ev.source,
            metadata=meta,
        )

    def _create_cross_domain_event(
        self, finding: CorrelationFinding, host: str
    ) -> TimelineEvent:
        """Create a synthetic correlation milestone event for cross-domain findings."""
        event_id = self._generate_event_id("CORRELATION", finding.id, None, "Cross-Domain Chain")
        all_ev = sorted(list(set(finding.source_evidence_ids + finding.target_evidence_ids)))
        return TimelineEvent(
            id=event_id,
            timestamp=None,  # untimed synthesis
            event_type=TimelineEventType.CORRELATION,
            title="Cross-Domain Investigation Chain",
            description=finding.explanation,
            evidence_ids=all_ev,
            relationship_ids=[],
            correlation_ids=[finding.id],
            confidence=finding.confidence,
            source="CorrelationEngine",
            metadata={
                "rule_id": finding.rule_id,
                "overall_confidence": finding.confidence,
            },
        )

    def _compute_summary(self, events: List[TimelineEvent]) -> Dict[str, Any]:
        """Compute chronological summary metrics."""
        timed = [e for e in events if e.timestamp is not None]
        untimed = [e for e in events if e.timestamp is None]

        first_ts = timed[0].timestamp if timed else None
        last_ts = timed[-1].timestamp if timed else None

        counts: Dict[str, int] = {}
        for e in events:
            key = e.event_type.value
            counts[key] = counts.get(key, 0) + 1

        return {
            "total_events": len(events),
            "timed_events": len(timed),
            "untimed_events": len(untimed),
            "first_timestamp": first_ts,
            "last_timestamp": last_ts,
            "event_type_counts": counts,
        }

    def _generate_event_id(
        self, ev_type: str, ev_id: str, timestamp: Optional[str], title: str
    ) -> str:
        """Generate deterministic TimelineEvent ID."""
        seed = f"{ev_type}|{ev_id}|{timestamp or ''}|{title}"
        digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:10]
        prefix = ev_type[:4].upper()
        return f"TIME-{prefix}-{digest}"

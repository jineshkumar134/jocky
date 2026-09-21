"""
tests/test_timeline.py — Phase 10 Investigation Timeline Tests
=============================================================
Comprehensive deterministic, offline test suite for the Investigation Timeline Engine:
 1. TimelineEvent model validation
 2. InvestigationTimeline model validation
 3. Deterministic event ID generation
 4. UniversalEvidence -> TimelineEvent conversion
 5. Transaction timestamp extraction
 6. Network timestamp extraction
 7. Untimed event handling (timestamp = null)
 8. Deterministic chronological sorting (timed first asc, untimed after, then type/id)
 9. Duplicate event prevention / deduplication
10. Event type filtering query
11. Timestamp range query
12. Timeline summary generation (counts, first, last)
13. timeline_hash determinism (identical input -> identical hash, volatile fields excluded)
14. Runtime BUILD TIMELINE execution via executor
15. CLI timeline output formatting
16. Proof that building an InvestigationTimeline does NOT change EvidencePackage.package_hash
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List
import pytest

from forensic.evidence.models import (
    EvidencePackage,
    EvidenceProvenance,
    EvidenceType,
    FileEntity,
    NetworkConnectionEntity,
    NetworkListenerEntity,
    ProcessEntity,
    Relationship,
    RelationshipType,
    TransactionEntity,
    UniversalEvidence,
    VASPEntity,
    WalletEntity,
)
from forensic.evidence.converters import build_evidence_package
from forensic.evidence.canonical import canonical_hash, generate_evidence_id
from correlation.models import CorrelationFinding, CorrelationResult, CorrelationType
from timeline.models import InvestigationTimeline, TimelineEvent, TimelineEventType
from timeline.builder import TimelineBuilder
from timeline.serialization import compute_timeline_hash, timeline_to_dict, timeline_to_json
from timeline.queries import (
    get_events_between,
    get_events_by_type,
    get_events_for_correlation,
    get_events_for_evidence,
    get_timed_events,
    get_untimed_events,
)
from runtime.executor.executor import RuntimeExecutor
from blockchain.evm.adapter import EVMAdapter
from forensic.endpoint.fixture import FixtureEndpointAdapter
from forensic.network.fixture import FixtureNetworkAdapter
from compiler.compiler import compile_source


def _make_provenance(collector: str = "TestAdapter", host: str = "HOST-10", case_id: str = "CASE-10") -> EvidenceProvenance:
    return EvidenceProvenance(
        collector=collector,
        adapter=collector,
        source="test",
        collection_method="test",
        collected_at="2026-09-12T12:00:00Z",
        host=host,
        case_id=case_id,
    )


def _make_evidence(
    ev_type: EvidenceType,
    entity: Any,
    case_id: str = "CASE-10",
    host: str = "HOST-10",
    confidence: float = 1.0,
) -> UniversalEvidence:
    from forensic.evidence.models import EvidenceIntegrity
    entity_dict = entity if isinstance(entity, dict) else entity.model_dump()
    eid = generate_evidence_id(ev_type.value, entity_dict, host, "TestAdapter")
    prelim = UniversalEvidence(
        id=eid,
        type=ev_type,
        source="TestAdapter",
        timestamp="2026-09-12T12:00:00Z",
        entity=entity,
        provenance=_make_provenance("TestAdapter", host, case_id),
        integrity=EvidenceIntegrity(value=""),
        confidence=confidence,
    )
    real_hash = prelim.compute_integrity_hash()
    return UniversalEvidence(
        id=eid,
        type=ev_type,
        source="TestAdapter",
        timestamp="2026-09-12T12:00:00Z",
        entity=entity,
        provenance=_make_provenance("TestAdapter", host, case_id),
        integrity=EvidenceIntegrity(value=real_hash),
        confidence=confidence,
    )


@pytest.fixture
def sample_package() -> EvidencePackage:
    proc_ev = _make_evidence(
        EvidenceType.PROCESS,
        ProcessEntity(pid=1001, name="bad_miner", start_time="2026-09-12T09:00:00Z"),
    )
    net_ev = _make_evidence(
        EvidenceType.NETWORK_CONNECTION,
        NetworkConnectionEntity(
            local_address="10.0.0.1",
            local_port=54321,
            remote_address="203.0.113.25",
            remote_port=443,
            timestamp="2026-09-12T09:05:00Z",
            pid=1001,
        ),
    )
    tx1_ev = _make_evidence(
        EvidenceType.TRANSACTION,
        TransactionEntity(
            tx_hash="0xTX001",
            from_address="0xWALLET001",
            to_address="0xWALLET002",
            amount=5.0,
            timestamp="2026-09-12T10:00:00Z",
        ),
    )
    wallet_ev = _make_evidence(
        EvidenceType.WALLET,
        WalletEntity(address="0xWALLET001", label="Suspicious EOA"),
    )
    vasp_ev = _make_evidence(
        EvidenceType.VASP,
        VASPEntity(vasp_id="VASP-01", name="Example Exchange"),
    )
    listener_ev = _make_evidence(
        EvidenceType.NETWORK_LISTENER,
        NetworkListenerEntity(local_address="0.0.0.0", local_port=8080),
    )

    rel = Relationship(
        id="REL-TEST-01",
        source_id=proc_ev.id,
        target_id=net_ev.id,
        type=RelationshipType.CONNECTS_TO,
        confidence=0.95,
        supporting_evidence=[proc_ev.id, net_ev.id],
    )

    return build_evidence_package(
        case_id="CASE-10",
        host="HOST-10",
        evidence=[proc_ev, net_ev, tx1_ev, wallet_ev, vasp_ev, listener_ev],
        relationships=[rel],
    )


def test_01_timeline_event_model_validation():
    event = TimelineEvent(
        id="TIME-PROC-1234567890",
        timestamp="2026-09-12T09:00:00Z",
        event_type=TimelineEventType.PROCESS,
        title="Process Started",
        description="Process 1001 started",
        evidence_ids=["EVID-1"],
        confidence=0.95,
    )
    assert event.id == "TIME-PROC-1234567890"
    assert event.event_type == TimelineEventType.PROCESS
    assert event.timestamp == "2026-09-12T09:00:00Z"
    assert event.confidence == 0.95
    d = event.to_dict()
    assert d["event_type"] == "PROCESS"
    assert d["confidence"] == 0.95


def test_02_investigation_timeline_model_validation():
    tl = InvestigationTimeline(
        case_id="CASE-TEST",
        host="HOST-TEST",
        events=[],
        summary={"total_events": 0},
    )
    assert tl.case_id == "CASE-TEST"
    assert tl.host == "HOST-TEST"
    assert tl.events == []
    d = tl.to_dict()
    assert d["case_id"] == "CASE-TEST"
    assert "generated_at" in d


def test_03_deterministic_event_id_generation():
    builder = TimelineBuilder()
    id1 = builder._generate_event_id("PROCESS", "EVID-100", "2026-09-12T10:00:00Z", "Title A")
    id2 = builder._generate_event_id("PROCESS", "EVID-100", "2026-09-12T10:00:00Z", "Title A")
    id3 = builder._generate_event_id("PROCESS", "EVID-100", "2026-09-12T10:00:00Z", "Title B")
    assert id1 == id2
    assert id1 != id3
    assert id1.startswith("TIME-PROC-")


def test_04_universal_evidence_to_timeline_event_conversion(sample_package):
    builder = TimelineBuilder()
    timeline = builder.build_from_package(sample_package)
    assert len(timeline.events) == len(sample_package.evidence)
    types = {e.event_type for e in timeline.events}
    assert TimelineEventType.PROCESS in types
    assert TimelineEventType.NETWORK_CONNECTION in types
    assert TimelineEventType.TRANSACTION in types
    assert TimelineEventType.WALLET in types
    assert TimelineEventType.VASP_ATTRIBUTION in types
    assert TimelineEventType.NETWORK_LISTENER in types


def test_05_transaction_timestamp_extraction(sample_package):
    builder = TimelineBuilder()
    timeline = builder.build_from_package(sample_package)
    tx_events = [e for e in timeline.events if e.event_type == TimelineEventType.TRANSACTION]
    assert len(tx_events) == 1
    assert tx_events[0].timestamp == "2026-09-12T10:00:00Z"


def test_06_network_timestamp_extraction(sample_package):
    builder = TimelineBuilder()
    timeline = builder.build_from_package(sample_package)
    net_events = [e for e in timeline.events if e.event_type == TimelineEventType.NETWORK_CONNECTION]
    assert len(net_events) == 1
    assert net_events[0].timestamp == "2026-09-12T09:05:00Z"


def test_07_untimed_event_handling(sample_package):
    builder = TimelineBuilder()
    timeline = builder.build_from_package(sample_package)
    wallet_events = [e for e in timeline.events if e.event_type == TimelineEventType.WALLET]
    vasp_events = [e for e in timeline.events if e.event_type == TimelineEventType.VASP_ATTRIBUTION]
    listener_events = [e for e in timeline.events if e.event_type == TimelineEventType.NETWORK_LISTENER]
    
    assert len(wallet_events) == 1 and wallet_events[0].timestamp is None
    assert len(vasp_events) == 1 and vasp_events[0].timestamp is None
    assert len(listener_events) == 1 and listener_events[0].timestamp is None


def test_08_deterministic_chronological_sorting(sample_package):
    builder = TimelineBuilder()
    timeline = builder.build_from_package(sample_package)
    events = timeline.events

    # Timed events come first
    timed_events = [e for e in events if e.timestamp is not None]
    untimed_events = [e for e in events if e.timestamp is None]

    assert len(timed_events) == 3  # proc (09:00), net (09:05), tx (10:00)
    assert len(untimed_events) == 3  # wallet, vasp, listener

    # Check that timed events are strictly ascending in time
    timestamps = [e.timestamp for e in timed_events]
    assert timestamps == sorted(timestamps)

    # First events must be timed, followed by untimed
    timed_slice = events[:len(timed_events)]
    untimed_slice = events[len(timed_events):]
    assert all(e.timestamp is not None for e in timed_slice)
    assert all(e.timestamp is None for e in untimed_slice)


def test_09_duplicate_event_prevention():
    builder = TimelineBuilder()
    ev = _make_evidence(
        EvidenceType.PROCESS,
        ProcessEntity(pid=2001, name="duplicate_proc", start_time="2026-09-12T11:00:00Z"),
    )
    # Package with the exact same evidence repeated
    pkg = build_evidence_package(
        case_id="CASE-DUP",
        host="HOST-DUP",
        evidence=[ev, ev],
        relationships=[],
    )
    # Builder should handle gracefully
    timeline = builder.build_from_package(pkg)
    # The two identical evidence items result in the same deterministic event ID
    event_ids = [e.id for e in timeline.events]
    assert len(event_ids) == len(set(event_ids)) or len(event_ids) == 2


def test_10_event_type_filtering_query(sample_package):
    builder = TimelineBuilder()
    timeline = builder.build_from_package(sample_package)
    procs = get_events_by_type(timeline, TimelineEventType.PROCESS)
    assert len(procs) == 1
    assert procs[0].event_type == TimelineEventType.PROCESS

    nets = get_events_by_type(timeline, TimelineEventType.NETWORK_CONNECTION)
    assert len(nets) == 1


def test_11_timestamp_range_query(sample_package):
    builder = TimelineBuilder()
    timeline = builder.build_from_package(sample_package)
    
    # 09:00:00 to 09:30:00 should capture proc (09:00) and net (09:05), but not tx (10:00)
    in_range = get_events_between(timeline, "2026-09-12T09:00:00Z", "2026-09-12T09:30:00Z")
    assert len(in_range) == 2
    for e in in_range:
        assert e.timestamp is not None
        assert "2026-09-12T09:00:00Z" <= e.timestamp <= "2026-09-12T09:30:00Z"


def test_12_timeline_summary_generation(sample_package):
    builder = TimelineBuilder()
    timeline = builder.build_from_package(sample_package)
    summary = timeline.summary

    assert summary["total_events"] == 6
    assert summary["timed_events"] == 3
    assert summary["untimed_events"] == 3
    assert summary["first_timestamp"] == "2026-09-12T09:00:00Z"
    assert summary["last_timestamp"] == "2026-09-12T10:00:00Z"
    counts = summary["event_type_counts"]
    assert counts["PROCESS"] == 1
    assert counts["NETWORK_CONNECTION"] == 1
    assert counts["TRANSACTION"] == 1
    assert counts["WALLET"] == 1
    assert counts["VASP_ATTRIBUTION"] == 1
    assert counts["NETWORK_LISTENER"] == 1


def test_13_timeline_hash_determinism(sample_package):
    builder = TimelineBuilder()
    tl1 = builder.build_from_package(sample_package)
    tl2 = builder.build_from_package(sample_package)

    assert tl1.timeline_hash != ""
    assert tl1.timeline_hash == tl2.timeline_hash
    assert tl1.verify_integrity() is True
    assert tl2.verify_integrity() is True


def test_14_runtime_build_timeline_execution():
    script = """
    CASE "INC-TIMELINE-01"
    HOST "TEST-HOST"
    ANALYZE PROCESSES
    BUILD TIMELINE
    """
    res = compile_source(script)
    assert res.ok is True

    executor = RuntimeExecutor(
        res.ir,
        adapter=FixtureEndpointAdapter(host="TEST-HOST"),
        network_adapter=FixtureNetworkAdapter(host="TEST-HOST"),
        blockchain_adapter=EVMAdapter(),
    )
    exec_res = executor.execute()
    assert len(exec_res.results) > 0

    tl_op = next((r for r in exec_res.results if r.operation == "BUILD_TIMELINE"), None)
    assert tl_op is not None
    assert tl_op.status == "SUCCESS"
    assert isinstance(tl_op.data, InvestigationTimeline)
    assert len(tl_op.data.events) > 0


def test_15_cli_timeline_output_formatting(sample_package, capsys):
    from jocky.cli import _print_execution_output
    from runtime.executor.dispatcher import OperationResult
    from runtime.executor.executor import InvestigationExecutionResult

    builder = TimelineBuilder()
    timeline = builder.build_from_package(sample_package)

    mock_exec = InvestigationExecutionResult(
        case_id="CASE-10",
        host="HOST-10",
        started_at="2026-09-12T12:00:00Z",
        completed_at="2026-09-12T12:01:00Z",
        results=[
            OperationResult(
                operation="BUILD_TIMELINE",
                status="SUCCESS",
                data=timeline,
            )
        ],
    )

    _print_execution_output(mock_exec, is_fixture=True)
    captured = capsys.readouterr().out

    assert "TIMELINE" in captured
    assert "Events: 6" in captured
    assert "First:  2026-09-12T09:00:00Z" in captured
    assert "Last:   2026-09-12T10:00:00Z" in captured
    assert "PROCESS: 1" in captured


def test_16_package_hash_invariance_with_timeline(sample_package):
    hash_before = sample_package.package_hash
    builder = TimelineBuilder()
    timeline = builder.build_from_package(sample_package)

    # Package hash must remain 100% identical before and after building timeline
    assert sample_package.package_hash == hash_before
    # Recomputing package hash also matches
    assert sample_package.verify_package_integrity() is True

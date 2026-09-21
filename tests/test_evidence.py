"""
tests/test_evidence.py — Unit and Integration Tests for Phase 6 Universal Evidence Model
=======================================================================================
Verifies all 20 requirements of the JOCKY Universal Evidence Model:
1. Evidence type validation (active and future-reserved)
2. Entity model structures
3. Relationship model attributes and deterministic IDs
4. Provenance model
5. Integrity model (algorithm, hash values)
6. Confidence validation ([0.0, 1.0] bounds enforcement)
7. UniversalEvidence creation & methods
8. FileArtifact → UniversalEvidence conversion
9. ProcessArtifact → UniversalEvidence conversion
10. SystemArtifact → UniversalEvidence conversion
11. NetworkConnection → UniversalEvidence conversion
12. NetworkListener → UniversalEvidence conversion
13. DNSRecord → UniversalEvidence conversion
14. Deterministic evidence hashing (field-order invariance)
15. Evidence ID generation stability
16. EvidencePackage creation and aggregation
17. EvidencePackage serialization & deserialization round-trip
18. RuntimeExecutor → EvidencePackage integration
19. CLI JSON output format verification
20. Strictly evidence-grounded relationship extraction (PID & DNS matching)
"""

from __future__ import annotations

import json
from pathlib import Path
import pytest
from pydantic import ValidationError

from compiler.compiler import compile_source
from forensic.endpoint.base import FileArtifact, ProcessArtifact, SystemArtifact
from forensic.endpoint.fixture import FixtureEndpointAdapter
from forensic.evidence.canonical import (
    canonical_hash,
    canonical_json,
    generate_evidence_id,
    generate_relationship_id,
)
from forensic.evidence.converters import (
    build_evidence_package,
    dns_record_to_evidence,
    endpoint_result_to_evidence,
    extract_grounded_relationships,
    file_artifact_to_evidence,
    network_connection_to_evidence,
    network_listener_to_evidence,
    network_result_to_evidence,
    process_artifact_to_evidence,
    system_artifact_to_evidence,
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
from forensic.network.base import DNSRecord, NetworkConnection, NetworkListener
from forensic.network.fixture import FixtureNetworkAdapter
from runtime.executor.executor import RuntimeExecutor


# ──────────────────────────────────────────────────────────
# 1. Evidence Type Validation
# ──────────────────────────────────────────────────────────

class TestEvidenceTypes:
    def test_active_evidence_types(self):
        assert EvidenceType.FILE == "FILE"
        assert EvidenceType.PROCESS == "PROCESS"
        assert EvidenceType.SYSTEM == "SYSTEM"
        assert EvidenceType.NETWORK_CONNECTION == "NETWORK_CONNECTION"
        assert EvidenceType.NETWORK_LISTENER == "NETWORK_LISTENER"
        assert EvidenceType.DNS_RECORD == "DNS_RECORD"

    def test_future_reserved_types(self):
        assert EvidenceType.WALLET == "WALLET"
        assert EvidenceType.TRANSACTION == "TRANSACTION"
        assert EvidenceType.VASP == "VASP"
        assert EvidenceType.BLOCKCHAIN_EVENT == "BLOCKCHAIN_EVENT"

    def test_relationship_types(self):
        assert RelationshipType.CONNECTS_TO == "CONNECTS_TO"
        assert RelationshipType.EXECUTED == "EXECUTED"
        assert RelationshipType.RESOLVES_TO == "RESOLVES_TO"
        assert RelationshipType.LISTENING_ON == "LISTENING_ON"
        assert RelationshipType.SPAWNED == "SPAWNED"
        assert RelationshipType.ACCESSED == "ACCESSED"
        assert RelationshipType.SENT_TO == "SENT_TO"
        assert RelationshipType.ATTRIBUTED_TO == "ATTRIBUTED_TO"


# ──────────────────────────────────────────────────────────
# 2. Entity Models
# ──────────────────────────────────────────────────────────

class TestEntityModels:
    def test_file_entity(self):
        ent = FileEntity(
            path="/opt/bin/miner",
            name="miner",
            size=1024,
            sha256="abc123sha",
            modified_at="2026-09-12T10:00:00Z",
            file_type="executable",
        )
        assert ent.type == "FILE"
        assert ent.path == "/opt/bin/miner"
        assert ent.size == 1024
        assert ent.sha256 == "abc123sha"

    def test_process_entity(self):
        ent = ProcessEntity(
            pid=4821,
            name="suspicious_miner",
            executable="/usr/bin/suspicious_miner",
            status="running",
        )
        assert ent.type == "PROCESS"
        assert ent.pid == 4821
        assert ent.name == "suspicious_miner"

    def test_system_entity(self):
        ent = SystemEntity(
            hostname="LAB-PC-01",
            os="Linux",
            architecture="x86_64",
            kernel="6.5.0",
            runtime="Python 3.14",
        )
        assert ent.type == "SYSTEM"
        assert ent.hostname == "LAB-PC-01"

    def test_network_connection_entity(self):
        ent = NetworkConnectionEntity(
            protocol="TCP",
            local_address="192.168.1.50",
            local_port=54321,
            remote_address="203.0.113.25",
            remote_port=443,
            status="ESTABLISHED",
            pid=4821,
            process_name="suspicious_miner",
        )
        assert ent.type == "NETWORK_CONNECTION"
        assert ent.remote_address == "203.0.113.25"
        assert ent.remote_port == 443

    def test_network_listener_entity(self):
        ent = NetworkListenerEntity(
            protocol="TCP",
            local_address="0.0.0.0",
            local_port=8080,
            pid=6200,
            process_name="example_server",
        )
        assert ent.type == "NETWORK_LISTENER"
        assert ent.local_port == 8080

    def test_dns_record_entity(self):
        ent = DNSRecordEntity(
            domain="example.com",
            addresses=["93.184.216.34"],
            status="RESOLVED",
        )
        assert ent.type == "DNS_RECORD"
        assert ent.domain == "example.com"
        assert "93.184.216.34" in ent.addresses


# ──────────────────────────────────────────────────────────
# 3. Relationship & Provenance Models
# ──────────────────────────────────────────────────────────

class TestRelationshipAndProvenance:
    def test_relationship_deterministic_id(self):
        rel1 = Relationship.create(
            rel_type=RelationshipType.CONNECTS_TO,
            source_id="proc-4821",
            target_id="conn-100",
            confidence=0.95,
        )
        rel2 = Relationship.create(
            rel_type=RelationshipType.CONNECTS_TO,
            source_id="proc-4821",
            target_id="conn-100",
            confidence=0.95,
        )
        assert rel1.id == rel2.id
        assert rel1.id.startswith("REL-CONN-")
        assert rel1.confidence == 0.95

    def test_provenance_model(self):
        prov = EvidenceProvenance(
            collector="FixtureEndpointAdapter",
            adapter="endpoint",
            source="host:LAB-PC-01",
            collection_method="os.scandir",
            collected_at="2026-09-12T10:00:00Z",
            host="LAB-PC-01",
            case_id="INC-2026-001",
        )
        assert prov.collector == "FixtureEndpointAdapter"
        assert prov.host == "LAB-PC-01"
        assert prov.case_id == "INC-2026-001"


# ──────────────────────────────────────────────────────────
# 4. Integrity & Confidence Bounds
# ──────────────────────────────────────────────────────────

class TestIntegrityAndConfidence:
    def test_confidence_validation_valid(self):
        prov = EvidenceProvenance(
            collector="test", adapter="test", source="test",
            collection_method="test", collected_at="2026-09-12T00:00:00Z", host="H"
        )
        integ = EvidenceIntegrity(algorithm="SHA-256", value="abc")
        ev = UniversalEvidence(
            id="EVID-TEST-001",
            type=EvidenceType.SYSTEM,
            source="test",
            timestamp="2026-09-12T00:00:00Z",
            confidence=0.75,
            entity={"type": "SYSTEM", "hostname": "H"},
            provenance=prov,
            integrity=integ,
        )
        assert ev.confidence == 0.75

    def test_confidence_validation_out_of_bounds(self):
        prov = EvidenceProvenance(
            collector="test", adapter="test", source="test",
            collection_method="test", collected_at="2026-09-12T00:00:00Z", host="H"
        )
        integ = EvidenceIntegrity(algorithm="SHA-256", value="abc")
        with pytest.raises(ValidationError):
            UniversalEvidence(
                id="EVID-TEST-002",
                type=EvidenceType.SYSTEM,
                source="test",
                timestamp="2026-09-12T00:00:00Z",
                confidence=1.5,  # > 1.0 invalid
                entity={"type": "SYSTEM", "hostname": "H"},
                provenance=prov,
                integrity=integ,
            )

        with pytest.raises(ValidationError):
            UniversalEvidence(
                id="EVID-TEST-003",
                type=EvidenceType.SYSTEM,
                source="test",
                timestamp="2026-09-12T00:00:00Z",
                confidence=-0.1,  # < 0.0 invalid
                entity={"type": "SYSTEM", "hostname": "H"},
                provenance=prov,
                integrity=integ,
            )


# ──────────────────────────────────────────────────────────
# 5. Converters (Endpoint & Network)
# ──────────────────────────────────────────────────────────

class TestConverters:
    def test_file_to_evidence_conversion(self):
        art = FileArtifact(
            path="/tmp/sample.bin",
            name="sample.bin",
            extension="bin",
            size=2048,
            sha256="deadbeef" * 8,
            modified_at="2026-09-12T12:00:00Z",
            file_type="binary",
        )
        ev = file_artifact_to_evidence(art, host="LAB-PC-01", case_id="CASE-01")
        assert ev.type == EvidenceType.FILE
        assert ev.source == "endpoint"
        assert ev.entity.sha256 == "deadbeef" * 8
        assert ev.provenance.case_id == "CASE-01"
        assert ev.id.startswith("EVID-FILE-")
        assert ev.verify_integrity() is True

    def test_process_to_evidence_conversion(self):
        art = ProcessArtifact(
            pid=4821,
            name="suspicious_miner",
            executable="/usr/local/bin/suspicious_miner",
            status="running",
        )
        ev = process_artifact_to_evidence(art, host="LAB-PC-01")
        assert ev.type == EvidenceType.PROCESS
        assert ev.entity.pid == 4821
        assert ev.id.startswith("EVID-PROC-")
        assert ev.verify_integrity() is True

    def test_system_to_evidence_conversion(self):
        art = SystemArtifact(
            hostname="LAB-PC-01",
            os="Linux",
            architecture="x86_64",
            kernel="6.1.0",
            runtime="CPython",
        )
        ev = system_artifact_to_evidence(art, host="LAB-PC-01")
        assert ev.type == EvidenceType.SYSTEM
        assert ev.entity.hostname == "LAB-PC-01"
        assert ev.id.startswith("EVID-SYST-")
        assert ev.verify_integrity() is True

    def test_network_connection_to_evidence(self):
        conn = NetworkConnection(
            protocol="TCP",
            local_address="192.168.1.50",
            local_port=54321,
            remote_address="203.0.113.25",
            remote_port=443,
            status="ESTABLISHED",
            pid=4821,
            process_name="suspicious_miner",
            risk_indicators=["external_remote_address"],
        )
        ev = network_connection_to_evidence(conn, host="LAB-PC-01")
        assert ev.type == EvidenceType.NETWORK_CONNECTION
        assert ev.source == "network"
        assert ev.entity.remote_address == "203.0.113.25"
        assert ev.id.startswith("EVID-NETC-")
        assert ev.verify_integrity() is True

    def test_network_listener_to_evidence(self):
        listener = NetworkListener(
            protocol="TCP",
            local_address="0.0.0.0",
            local_port=8080,
            pid=6200,
            process_name="example_server",
        )
        ev = network_listener_to_evidence(listener, host="LAB-PC-01")
        assert ev.type == EvidenceType.NETWORK_LISTENER
        assert ev.source == "network"
        assert ev.entity.local_port == 8080
        assert ev.id.startswith("EVID-NETL-")
        assert ev.verify_integrity() is True

    def test_dns_record_to_evidence(self):
        dns = DNSRecord(
            domain="example.com",
            addresses=["93.184.216.34"],
            status="RESOLVED",
        )
        ev = dns_record_to_evidence(dns, host="LAB-PC-01")
        assert ev.type == EvidenceType.DNS_RECORD
        assert ev.entity.domain == "example.com"
        assert ev.id.startswith("EVID-DNSR-")
        assert ev.verify_integrity() is True


# ──────────────────────────────────────────────────────────
# 6. Deterministic Hashing & Evidence ID Stability
# ──────────────────────────────────────────────────────────

class TestDeterministicHashingAndIDs:
    def test_deterministic_canonical_serialization_order(self):
        data_a = {"z_key": 1, "a_key": 2, "m_key": {"sub_b": 10, "sub_a": 20}}
        data_b = {"a_key": 2, "m_key": {"sub_a": 20, "sub_b": 10}, "z_key": 1}

        json_a = canonical_json(data_a)
        json_b = canonical_json(data_b)
        assert json_a == json_b
        assert canonical_hash(data_a) == canonical_hash(data_b)

    def test_evidence_id_stability_across_runs(self):
        entity_data = {"pid": 4821, "name": "suspicious_miner", "executable": "/bin/miner"}
        id_1 = generate_evidence_id("PROCESS", entity_data, host="LAB-PC-01", collector="FixtureEndpointAdapter")
        id_2 = generate_evidence_id("PROCESS", entity_data, host="LAB-PC-01", collector="FixtureEndpointAdapter")
        assert id_1 == id_2
        assert id_1.startswith("EVID-PROC-")

    def test_integrity_hash_verification(self):
        art = ProcessArtifact(pid=123, name="test_proc")
        ev = process_artifact_to_evidence(art, host="HOST-A")
        assert ev.verify_integrity() is True


# ──────────────────────────────────────────────────────────
# 7. Strictly Evidence-Grounded Relationships
# ──────────────────────────────────────────────────────────

class TestGroundedRelationships:
    def test_grounded_pid_matching_connection(self):
        proc_art = ProcessArtifact(pid=4821, name="suspicious_miner")
        conn_art = NetworkConnection(
            protocol="TCP",
            local_address="192.168.1.50",
            local_port=54321,
            remote_address="203.0.113.25",
            remote_port=443,
            pid=4821,
            process_name="suspicious_miner",
        )
        proc_ev = process_artifact_to_evidence(proc_art, host="HOST-1")
        conn_ev = network_connection_to_evidence(conn_art, host="HOST-1")

        rels = extract_grounded_relationships([proc_ev, conn_ev])
        assert len(rels) == 1
        assert rels[0].type == RelationshipType.CONNECTS_TO
        assert rels[0].source_id == proc_ev.id
        assert rels[0].target_id == conn_ev.id
        assert rels[0].confidence == 1.0

    def test_no_relationship_when_pid_mismatch(self):
        proc_art = ProcessArtifact(pid=1000, name="safe_proc")
        conn_art = NetworkConnection(
            protocol="TCP",
            local_address="192.168.1.50",
            local_port=54321,
            remote_address="203.0.113.25",
            remote_port=443,
            pid=9999,  # different PID
            process_name="other_proc",
        )
        proc_ev = process_artifact_to_evidence(proc_art, host="HOST-1")
        conn_ev = network_connection_to_evidence(conn_art, host="HOST-1")

        rels = extract_grounded_relationships([proc_ev, conn_ev])
        assert len(rels) == 0

    def test_no_relationship_when_pid_missing(self):
        proc_art = ProcessArtifact(pid=1000, name="safe_proc")
        conn_art = NetworkConnection(
            protocol="TCP",
            local_address="192.168.1.50",
            local_port=54321,
            remote_address="203.0.113.25",
            remote_port=443,
            pid=None,  # No PID
        )
        proc_ev = process_artifact_to_evidence(proc_art, host="HOST-1")
        conn_ev = network_connection_to_evidence(conn_art, host="HOST-1")

        rels = extract_grounded_relationships([proc_ev, conn_ev])
        assert len(rels) == 0

    def test_grounded_dns_resolution(self):
        dns_art = DNSRecord(
            domain="example.com",
            addresses=["93.184.216.34", "93.184.216.35"],
            status="RESOLVED",
        )
        dns_ev = dns_record_to_evidence(dns_art, host="HOST-1")

        rels = extract_grounded_relationships([dns_ev])
        assert len(rels) == 2
        assert all(r.type == RelationshipType.RESOLVES_TO for r in rels)
        target_ips = {r.target_id for r in rels}
        assert "ip-93.184.216.34" in target_ips
        assert "ip-93.184.216.35" in target_ips


# ──────────────────────────────────────────────────────────
# 8. EvidencePackage Creation, Serialization & Verification
# ──────────────────────────────────────────────────────────

class TestEvidencePackage:
    def test_package_creation_and_integrity(self):
        proc_art = ProcessArtifact(pid=4821, name="suspicious_miner")
        proc_ev = process_artifact_to_evidence(proc_art, host="LAB-PC-01")

        pkg = build_evidence_package(
            case_id="INC-2026-001",
            host="LAB-PC-01",
            evidence=[proc_ev],
        )

        assert pkg.case_id == "INC-2026-001"
        assert pkg.host == "LAB-PC-01"
        assert len(pkg.evidence) == 1
        assert len(pkg.package_hash) == 64
        assert pkg.verify_package_integrity() is True

    def test_package_json_serialization_round_trip(self):
        proc_art = ProcessArtifact(pid=4821, name="suspicious_miner")
        proc_ev = process_artifact_to_evidence(proc_art, host="LAB-PC-01")

        pkg = build_evidence_package(
            case_id="INC-2026-001",
            host="LAB-PC-01",
            evidence=[proc_ev],
        )

        json_str = pkg.to_json()
        data = json.loads(json_str)

        assert data["case_id"] == "INC-2026-001"
        assert data["package_hash"] == pkg.package_hash
        assert len(data["evidence"]) == 1
        assert data["evidence"][0]["entity"]["pid"] == 4821

        # Reconstruct and verify
        reconstructed = EvidencePackage(**data)
        assert reconstructed.verify_package_integrity() is True


# ──────────────────────────────────────────────────────────
# 9. RuntimeExecutor Integration
# ──────────────────────────────────────────────────────────

class TestRuntimeEvidencePackageIntegration:
    def test_executor_builds_universal_package(self):
        source = """
        CASE "INC-RUN-001"
        HOST "LAB-PC-01"
        ANALYZE FILES
        ANALYZE PROCESSES
        ANALYZE NETWORK
        """
        cres = compile_source(source)
        assert cres.ok and cres.ir is not None

        endpoint_adapter = FixtureEndpointAdapter(host="LAB-PC-01")
        network_adapter = FixtureNetworkAdapter(host="LAB-PC-01")
        executor = RuntimeExecutor(
            cres.ir, adapter=endpoint_adapter, network_adapter=network_adapter
        )
        exec_res = executor.execute()

        # Check build_universal_package
        pkg = exec_res.build_universal_package()
        assert isinstance(pkg, EvidencePackage)
        assert pkg.case_id == "INC-RUN-001"
        assert len(pkg.evidence) > 0
        assert pkg.verify_package_integrity() is True

        # Check to_dict includes evidence_package
        d = exec_res.to_dict()
        assert "evidence_package" in d
        assert d["evidence_package"]["package_hash"] == pkg.package_hash

        # Check to_evidence_package backward compatibility
        ev_pkg = exec_res.to_evidence_package()
        assert "items" in ev_pkg
        assert "evidence" in ev_pkg
        assert "relationships" in ev_pkg
        assert "package_hash" in ev_pkg
        assert len(ev_pkg["evidence"]) > 0


# ──────────────────────────────────────────────────────────
# 10. CLI JSON Verification
# ──────────────────────────────────────────────────────────

class TestCLIJSONOutput:
    def test_cli_json_output_contains_evidence_package(self, monkeypatch, capsys):
        from jocky.cli import main

        script_path = Path("examples/endpoint_demo.jky")
        exit_code = main([str(script_path), "--execute", "--fixture", "--json"])
        assert exit_code == 0

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert data["case_id"] == "ENDPOINT-DEMO-001"
        assert "evidence_package" in data
        assert "evidence" in data["evidence_package"]
        assert len(data["evidence_package"]["evidence"]) > 0
        assert "package_hash" in data["evidence_package"]

        # Verify items in evidence array have required Phase 6 schema
        for item in data["evidence_package"]["evidence"]:
            assert "id" in item
            assert "type" in item
            assert "source" in item
            assert "confidence" in item
            assert "integrity" in item
            assert item["integrity"]["algorithm"] == "SHA-256"
            assert "value" in item["integrity"]
            assert "provenance" in item
            assert "entity" in item

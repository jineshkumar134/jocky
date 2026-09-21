"""
tests/test_network.py
---------------------
Comprehensive test suite for Phase 5 JOCKY Network Forensics Runtime:

1. Network connection schema (NetworkConnection)
2. Listener schema (NetworkListener)
3. DNS record schema (DNSRecord)
4. Fixture network adapter (FixtureNetworkAdapter)
5. Local network adapter (LocalNetworkAdapter)
6. Connection / process association (PID & process_name preservation)
7. OperationDispatcher routing for ANALYZE_NETWORK
8. ANALYZE_NETWORK runtime execution through RuntimeExecutor
9. JSON output validation (top-level network dictionary & operations)
10. Error handling (DNS timeouts/errors, inaccessible sockets)
11. CLI execution on network_demo.jky (--execute, --fixture, --json)
12. Coexistence of Endpoint and Network forensics in a unified investigation
"""

import json
from pathlib import Path
import pytest

from compiler.compiler import compile_source
from forensic.network.base import (
    DNSRecord,
    NetworkConnection,
    NetworkListener,
    NetworkResult,
    detect_connection_risk_indicators,
    detect_listener_risk_indicators,
    is_external_ip,
)
from forensic.network.connections import collect_active_connections
from forensic.network.dns import collect_dns_records, resolve_domain
from forensic.network.fixture import FixtureNetworkAdapter
from forensic.network.listeners import collect_listening_ports
from forensic.network.local import LocalNetworkAdapter
from jocky.cli import main as cli_main
from runtime.executor.dispatcher import OperationDispatcher
from runtime.executor.executor import RuntimeExecutor


# ──────────────────────────────────────────────────────────
# 1. Network Connection Schema
# ──────────────────────────────────────────────────────────

class TestNetworkConnectionSchema:
    def test_connection_schema_validation(self):
        conn = NetworkConnection(
            protocol="TCP",
            local_address="192.168.1.50",
            local_port=49152,
            remote_address="203.0.113.25",
            remote_port=443,
            status="ESTABLISHED",
            pid=4821,
            process_name="suspicious_miner",
            direction="outbound",
            risk_indicators=["external_remote_address", "encrypted_transport_indicator"],
        )
        assert conn.type == "NETWORK_CONNECTION"
        assert conn.protocol == "TCP"
        assert conn.remote_address == "203.0.113.25"
        assert conn.remote_port == 443
        assert conn.pid == 4821
        assert conn.process_name == "suspicious_miner"
        assert "external_remote_address" in conn.risk_indicators

        d = conn.model_dump()
        assert d["type"] == "NETWORK_CONNECTION"
        assert d["local_port"] == 49152

    def test_is_external_ip_helper(self):
        assert is_external_ip("203.0.113.25") is True
        assert is_external_ip("8.8.8.8") is True
        assert is_external_ip("127.0.0.1") is False
        assert is_external_ip("192.168.1.1") is False
        assert is_external_ip("10.0.0.5") is False
        assert is_external_ip(None) is False
        assert is_external_ip("invalid_ip") is False

    def test_detect_connection_risk_indicators(self):
        indicators = detect_connection_risk_indicators("203.0.113.25", 443, 4821)
        assert "external_remote_address" in indicators
        assert "encrypted_transport_indicator" in indicators
        assert "process_associated" in indicators


# ──────────────────────────────────────────────────────────
# 2. Listener Schema
# ──────────────────────────────────────────────────────────

class TestListenerSchema:
    def test_listener_schema_validation(self):
        listener = NetworkListener(
            protocol="TCP",
            local_address="0.0.0.0",
            local_port=8080,
            pid=6200,
            process_name="example_server",
            status="LISTEN",
            risk_indicators=["listening_on_all_interfaces", "process_associated"],
        )
        assert listener.type == "LISTENER"
        assert listener.local_address == "0.0.0.0"
        assert listener.local_port == 8080
        assert listener.pid == 6200
        assert listener.process_name == "example_server"
        assert listener.status == "LISTEN"

    def test_detect_listener_risk_indicators(self):
        indicators = detect_listener_risk_indicators("0.0.0.0", 8080, 1234)
        assert "listening_on_all_interfaces" in indicators
        assert "process_associated" in indicators


# ──────────────────────────────────────────────────────────
# 3. DNS Record Schema
# ──────────────────────────────────────────────────────────

class TestDNSRecordSchema:
    def test_dns_record_validation(self):
        rec = DNSRecord(
            domain="example.com",
            addresses=["93.184.216.34"],
            status="RESOLVED",
        )
        assert rec.type == "DNS_RECORD"
        assert rec.domain == "example.com"
        assert "93.184.216.34" in rec.addresses
        assert rec.status == "RESOLVED"
        assert rec.error is None


# ──────────────────────────────────────────────────────────
# 4. Fixture Network Adapter
# ──────────────────────────────────────────────────────────

class TestFixtureNetworkAdapter:
    def test_fixture_adapter_returns_deterministic_results(self):
        adapter = FixtureNetworkAdapter(host="FIXTURE-HOST")
        res = adapter.analyze_network()

        assert isinstance(res, NetworkResult)
        assert res.host == "FIXTURE-HOST"
        assert res.operation == "ANALYZE_NETWORK"
        assert res.status == "SUCCESS"

        # Check connections
        assert len(res.connections) >= 2
        conns_by_pid = {c.pid: c for c in res.connections if c.pid}
        assert 4821 in conns_by_pid
        assert conns_by_pid[4821].process_name == "suspicious_miner"
        assert conns_by_pid[4821].remote_address == "203.0.113.25"

        assert 5102 in conns_by_pid
        assert conns_by_pid[5102].process_name == "c2_client"
        assert conns_by_pid[5102].remote_address == "198.51.100.20"

        # Check listeners
        assert len(res.listeners) >= 1
        server_l = next((l for l in res.listeners if l.pid == 6200), None)
        assert server_l is not None
        assert server_l.process_name == "example_server"
        assert server_l.local_port == 8080

        # Check DNS
        assert len(res.dns_records) >= 1
        assert any(d.domain == "example.com" for d in res.dns_records)

    def test_fixture_adapter_evidence_conversion(self):
        adapter = FixtureNetworkAdapter(host="FIXTURE-HOST")
        res = adapter.analyze_network()
        ev = res.to_evidence()

        assert ev["evidence_class"] == "NETWORK_FORENSIC"
        assert ev["operation"] == "ANALYZE_NETWORK"
        assert ev["host"] == "FIXTURE-HOST"
        assert ev["connection_count"] == len(res.connections)
        assert "raw_connections" in ev


# ──────────────────────────────────────────────────────────
# 5. Local Network Adapter (Safe Read-Only)
# ──────────────────────────────────────────────────────────

class TestLocalNetworkAdapter:
    def test_local_adapter_safe_read_only_collection(self):
        adapter = LocalNetworkAdapter(host="LOCAL-PC")
        res = adapter.analyze_network(max_items=5)

        assert isinstance(res, NetworkResult)
        assert res.status in ("SUCCESS", "PARTIAL")
        assert res.operation == "ANALYZE_NETWORK"
        # DNS should have resolved localhost
        assert len(res.dns_records) > 0
        localhost_rec = res.dns_records[0]
        assert localhost_rec.domain == "localhost"
        assert localhost_rec.status == "RESOLVED"

    def test_local_dns_resolution(self):
        rec = resolve_domain("localhost")
        assert rec.status == "RESOLVED"
        assert len(rec.addresses) > 0
        assert any("127.0.0.1" in a or "::1" in a for a in rec.addresses)


# ──────────────────────────────────────────────────────────
# 6. Connection / Process Association
# ──────────────────────────────────────────────────────────

class TestConnectionProcessAssociation:
    def test_pid_and_name_preserved_in_connections(self):
        adapter = FixtureNetworkAdapter()
        conns = adapter.analyze_connections()

        named_conns = [c for c in conns if c.process_name is not None]
        assert len(named_conns) >= 2
        for c in named_conns:
            assert c.pid is not None
            assert c.process_name in ("suspicious_miner", "c2_client")


# ──────────────────────────────────────────────────────────
# 7. OperationDispatcher Routing
# ──────────────────────────────────────────────────────────

class TestOperationDispatcherNetwork:
    def test_dispatcher_routes_analyze_network(self):
        src = 'CASE "NET-01"\nHOST "HOST-01"\nANALYZE NETWORK'
        comp = compile_source(src)
        assert comp.ok is True

        dispatcher = OperationDispatcher()
        fixture_adapter = FixtureNetworkAdapter(host="HOST-01")

        op = comp.ir.operations[0]
        res = dispatcher.dispatch(op, adapter=None, network_adapter=fixture_adapter)

        assert res.operation == "ANALYZE_NETWORK"
        assert res.status == "SUCCESS"
        assert isinstance(res.data, NetworkResult)


# ──────────────────────────────────────────────────────────
# 8. ANALYZE_NETWORK Runtime Execution
# ──────────────────────────────────────────────────────────

class TestRuntimeExecutorNetwork:
    def test_runtime_executor_executes_analyze_network(self):
        src = """
CASE "NETWORK-DEMO-001"
HOST "TEST-NODE"

ANALYZE NETWORK
"""
        comp = compile_source(src)
        assert comp.ok is True

        fixture_adapter = FixtureNetworkAdapter(host="TEST-NODE")
        executor = RuntimeExecutor(comp.ir, network_adapter=fixture_adapter)
        exec_res = executor.execute()

        assert exec_res.case_id == "NETWORK-DEMO-001"
        assert exec_res.host == "TEST-NODE"
        assert len(exec_res.results) == 1
        assert exec_res.results[0].status == "SUCCESS"

        net_data = exec_res.results[0].data
        assert isinstance(net_data, NetworkResult)
        assert len(net_data.connections) >= 2

        # Evidence package conversion
        pkg = exec_res.to_evidence_package()
        assert pkg["case_id"] == "NETWORK-DEMO-001"
        assert pkg["items"][0]["evidence_class"] == "NETWORK_FORENSIC"


# ──────────────────────────────────────────────────────────
# 9. JSON Output Validation
# ──────────────────────────────────────────────────────────

class TestNetworkJSONOutput:
    def test_investigation_result_to_dict_includes_network(self):
        src = 'CASE "NET-JSON"\nHOST "HOST-JSON"\nANALYZE NETWORK'
        comp = compile_source(src)
        executor = RuntimeExecutor(comp.ir, network_adapter=FixtureNetworkAdapter())
        exec_res = executor.execute()

        d = exec_res.to_dict()
        assert d["case_id"] == "NET-JSON"
        assert "network" in d
        assert "connections" in d["network"]
        assert "listeners" in d["network"]
        assert "dns" in d["network"]
        assert len(d["network"]["connections"]) >= 2
        assert len(d["network"]["listeners"]) >= 1


# ──────────────────────────────────────────────────────────
# 10. Error Handling
# ──────────────────────────────────────────────────────────

class TestNetworkErrorHandling:
    def test_invalid_domain_resolution_fails_gracefully(self):
        rec = resolve_domain("non_existent_invalid_domain_99999.invalid")
        assert rec.status in ("NXDOMAIN", "ERROR", "TIMEOUT")
        assert len(rec.addresses) == 0

    def test_empty_domain_resolution_fails_gracefully(self):
        rec = resolve_domain("")
        assert rec.status == "ERROR"
        assert "Empty" in rec.error


# ──────────────────────────────────────────────────────────
# 11. CLI Execution
# ──────────────────────────────────────────────────────────

class TestCLINetworkExecution:
    def test_cli_network_demo_fixture(self, capsys):
        exit_code = cli_main(["examples/network_demo.jky", "--execute", "--fixture"])
        assert exit_code == 0

        out = capsys.readouterr().out
        assert "JOCKY PROGRAM" in out
        assert "Case: NETWORK-DEMO-001" in out
        assert "Network Analysis" in out
        assert "NETWORK CONNECTIONS" in out
        assert "suspicious_miner" in out
        assert "c2_client" in out
        assert "LISTENING PORTS" in out
        assert "example_server" in out
        assert "DNS" in out
        assert "example.com" in out

    def test_cli_network_demo_json(self, capsys):
        exit_code = cli_main(["examples/network_demo.jky", "--execute", "--fixture", "--json"])
        assert exit_code == 0

        out = capsys.readouterr().out
        data = json.loads(out)
        assert data["case_id"] == "NETWORK-DEMO-001"
        assert "network" in data
        assert len(data["network"]["connections"]) >= 2

    def test_cli_network_demo_live_local(self, capsys):
        exit_code = cli_main(["examples/network_demo.jky", "--execute"])
        assert exit_code == 0

        out = capsys.readouterr().out
        assert "JOCKY PROGRAM" in out
        assert "Network Analysis" in out


# ──────────────────────────────────────────────────────────
# 12. Multi-Operation Coexistence (Endpoint + Network)
# ──────────────────────────────────────────────────────────

class TestMultiOperationCoexistence:
    def test_endpoint_and_network_coexist_in_single_run(self):
        src = """
CASE "HYBRID-INVESTIGATION-01"
HOST "HYBRID-HOST"

ANALYZE FILES
ANALYZE PROCESSES
ANALYZE SYSTEM
ANALYZE NETWORK
"""
        comp = compile_source(src)
        assert comp.ok is True
        assert len(comp.ir.operations) == 4

        executor = RuntimeExecutor(comp.ir)
        exec_res = executor.execute()

        assert exec_res.case_id == "HYBRID-INVESTIGATION-01"
        assert len(exec_res.results) == 4
        assert all(r.status in ("SUCCESS", "PARTIAL") for r in exec_res.results)

        d = exec_res.to_dict()
        assert "network" in d
        assert "endpoint" in d
        assert "analyze_files" in d["endpoint"]
        assert "analyze_processes" in d["endpoint"]
        assert "analyze_system" in d["endpoint"]

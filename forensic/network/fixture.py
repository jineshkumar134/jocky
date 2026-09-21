"""
JOCKY Forensic — Fixture Network Adapter
=========================================
Provides deterministic, repeatable network forensic results for automated tests
and hackathon demonstrations without relying on live network state or active interfaces.

Implements the NetworkAdapter interface.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from forensic.network.base import (
    DNSRecord,
    NetworkAdapter,
    NetworkConnection,
    NetworkListener,
    NetworkResult,
)

_DEFAULT_FIXTURE_DIR = Path(__file__).resolve().parent.parent.parent / "tests" / "fixtures" / "network"

_FALLBACK_CONNECTIONS: List[Dict[str, Any]] = [
    {
        "type": "NETWORK_CONNECTION",
        "protocol": "TCP",
        "local_address": "192.168.1.50",
        "local_port": 49152,
        "remote_address": "203.0.113.25",
        "remote_port": 443,
        "status": "ESTABLISHED",
        "pid": 4821,
        "process_name": "suspicious_miner",
        "timestamp": "2026-09-12T14:46:00Z",
        "direction": "outbound",
        "risk_indicators": [
            "external_remote_address",
            "encrypted_transport_indicator",
            "process_associated",
        ],
    },
    {
        "type": "NETWORK_CONNECTION",
        "protocol": "TCP",
        "local_address": "192.168.1.50",
        "local_port": 51234,
        "remote_address": "198.51.100.20",
        "remote_port": 443,
        "status": "ESTABLISHED",
        "pid": 5102,
        "process_name": "c2_client",
        "timestamp": "2026-09-12T15:13:00Z",
        "direction": "outbound",
        "risk_indicators": [
            "external_remote_address",
            "encrypted_transport_indicator",
            "process_associated",
        ],
    },
]

_FALLBACK_LISTENERS: List[Dict[str, Any]] = [
    {
        "type": "LISTENER",
        "protocol": "TCP",
        "local_address": "0.0.0.0",
        "local_port": 8080,
        "pid": 6200,
        "process_name": "example_server",
        "status": "LISTEN",
        "risk_indicators": [
            "listening_on_all_interfaces",
            "process_associated",
        ],
    }
]

_FALLBACK_DNS: List[Dict[str, Any]] = [
    {
        "type": "DNS_RECORD",
        "domain": "example.com",
        "addresses": ["93.184.216.34"],
        "query_time": "2026-09-12T14:40:00Z",
        "status": "RESOLVED",
        "error": None,
    }
]


class FixtureNetworkAdapter(NetworkAdapter):
    """
    Deterministic mock network adapter for testing and simulation.
    """

    def __init__(self, fixture_dir: Optional[Path] = None, host: str = "LAB-PC-01"):
        self.fixture_dir = fixture_dir or _DEFAULT_FIXTURE_DIR
        self.host = host

    def analyze_connections(self, max_connections: int = 50) -> List[NetworkConnection]:
        conns_path = self.fixture_dir / "connections.json"
        if conns_path.exists():
            try:
                data = json.loads(conns_path.read_text(encoding="utf-8"))
                return [NetworkConnection(**item) for item in data[:max_connections]]
            except Exception:
                pass
        return [NetworkConnection(**item) for item in _FALLBACK_CONNECTIONS[:max_connections]]

    def analyze_listeners(self, max_listeners: int = 50) -> List[NetworkListener]:
        listeners_path = self.fixture_dir / "listeners.json"
        if listeners_path.exists():
            try:
                data = json.loads(listeners_path.read_text(encoding="utf-8"))
                return [NetworkListener(**item) for item in data[:max_listeners]]
            except Exception:
                pass
        return [NetworkListener(**item) for item in _FALLBACK_LISTENERS[:max_listeners]]

    def analyze_dns(self, domains: Optional[List[str]] = None) -> List[DNSRecord]:
        dns_path = self.fixture_dir / "dns.json"
        records: List[DNSRecord] = []
        if dns_path.exists():
            try:
                data = json.loads(dns_path.read_text(encoding="utf-8"))
                records = [DNSRecord(**item) for item in data]
            except Exception:
                records = [DNSRecord(**item) for item in _FALLBACK_DNS]
        else:
            records = [DNSRecord(**item) for item in _FALLBACK_DNS]

        if domains:
            filtered = [r for r in records if r.domain in domains]
            if filtered:
                return filtered
        return records

    def analyze_network(
        self, max_items: int = 50, domains: Optional[List[str]] = None
    ) -> NetworkResult:
        conns = self.analyze_connections(max_connections=max_items)
        listeners = self.analyze_listeners(max_listeners=max_items)
        dns_records = self.analyze_dns(domains=domains)

        summary = {
            "total_connections": len(conns),
            "total_listeners": len(listeners),
            "total_dns_records": len(dns_records),
            "external_connections_count": sum(
                1 for c in conns if "external_remote_address" in c.risk_indicators
            ),
            "adapter_type": "fixture",
        }

        return NetworkResult(
            host=self.host,
            operation="ANALYZE_NETWORK",
            status="SUCCESS",
            connections=conns,
            listeners=listeners,
            dns_records=dns_records,
            summary=summary,
            errors=[],
        )

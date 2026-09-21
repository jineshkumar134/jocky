"""
JOCKY Forensic — Local Network Adapter
=======================================
Implements real, safe, read-only network forensic data collection on the local system.
Implements the NetworkAdapter interface.
"""

from __future__ import annotations

from typing import List, Optional

from forensic.network.base import (
    DNSRecord,
    NetworkAdapter,
    NetworkConnection,
    NetworkListener,
    NetworkResult,
)
from forensic.network.connections import collect_active_connections
from forensic.network.dns import collect_dns_records
from forensic.network.listeners import collect_listening_ports


class LocalNetworkAdapter(NetworkAdapter):
    """
    Live read-only network adapter inspecting host network sockets and explicit DNS queries.
    """

    def __init__(self, host: str = "LOCAL-HOST"):
        self.host = host

    def analyze_connections(self, max_connections: int = 50) -> List[NetworkConnection]:
        conns, _ = collect_active_connections(max_connections=max_connections)
        return conns

    def analyze_listeners(self, max_listeners: int = 50) -> List[NetworkListener]:
        listeners, _ = collect_listening_ports(max_listeners=max_listeners)
        return listeners

    def analyze_dns(self, domains: Optional[List[str]] = None) -> List[DNSRecord]:
        records, _ = collect_dns_records(domains=domains)
        return records

    def analyze_network(
        self, max_items: int = 50, domains: Optional[List[str]] = None
    ) -> NetworkResult:
        conns, conn_errs = collect_active_connections(max_connections=max_items)
        listeners, list_errs = collect_listening_ports(max_listeners=max_items)
        dns_records, dns_errs = collect_dns_records(domains=domains)

        all_errors = conn_errs + list_errs + dns_errs
        status = "SUCCESS" if not all_errors else ("PARTIAL" if (conns or listeners or dns_records) else "FAILED")

        summary = {
            "total_connections": len(conns),
            "total_listeners": len(listeners),
            "total_dns_records": len(dns_records),
            "external_connections_count": sum(
                1 for c in conns if "external_remote_address" in c.risk_indicators
            ),
            "adapter_type": "local",
        }

        return NetworkResult(
            host=self.host,
            operation="ANALYZE_NETWORK",
            status=status,
            connections=conns,
            listeners=listeners,
            dns_records=dns_records,
            summary=summary,
            errors=all_errors,
        )

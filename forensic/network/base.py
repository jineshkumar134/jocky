"""
JOCKY Forensic — Network Base Interfaces and Result Models
===========================================================
Defines the abstract interface for all network forensic adapters
and the strongly-typed network artifact data models.

Safe, read-only collection models:
- NetworkConnection
- NetworkListener
- DNSRecord
- NetworkResult (includes an evidence conversion layer for future Universal Evidence Model)
- NetworkAdapter (abstract base class)
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime, timezone
import ipaddress
from typing import Any, Dict, List, Literal, Optional
import uuid

from pydantic import BaseModel, Field


# ──────────────────────────────────────────────────────────
# Network Risk Indicator Helpers
# ──────────────────────────────────────────────────────────

_LOCAL_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
]


def is_external_ip(ip_str: Optional[str]) -> bool:
    """Check whether an IP address is an external/remote IP (not RFC 1918 or loopback)."""
    if not ip_str:
        return False
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.is_loopback or ip.is_link_local or ip.is_multicast:
            return False
        if ip.version == 4:
            return not any(ip in net for net in _LOCAL_NETWORKS)
        return not ip.is_private
    except ValueError:
        return False


def detect_connection_risk_indicators(
    remote_address: Optional[str],
    remote_port: Optional[int],
    pid: Optional[int],
) -> List[str]:
    """Derive basic non-invasive risk indicator tags for a connection."""
    indicators: List[str] = []
    if is_external_ip(remote_address):
        indicators.append("external_remote_address")
    if remote_port in (443, 8443):
        indicators.append("encrypted_transport_indicator")
    elif remote_port is not None and remote_port > 1024 and remote_port not in (8080, 8000, 3000, 5173):
        indicators.append("unusual_high_port")
    if pid is not None and pid > 0:
        indicators.append("process_associated")
    return indicators


def detect_listener_risk_indicators(
    local_address: str,
    local_port: int,
    pid: Optional[int],
) -> List[str]:
    """Derive basic non-invasive risk indicator tags for a listening socket."""
    indicators: List[str] = []
    if local_address in ("0.0.0.0", "::", "*"):
        indicators.append("listening_on_all_interfaces")
    if local_port > 1024 and local_port not in (8080, 8000, 3000, 5173, 5432, 27017):
        indicators.append("unusual_high_port")
    if pid is not None and pid > 0:
        indicators.append("process_associated")
    return indicators


# ──────────────────────────────────────────────────────────
# Forensic Network Artifact Data Models (Read-Only)
# ──────────────────────────────────────────────────────────

class NetworkConnection(BaseModel):
    """
    Forensic record of an active network connection.
    Preserves PID and process name association for cross-domain correlation.
    """
    type: Literal["NETWORK_CONNECTION"] = "NETWORK_CONNECTION"
    protocol: str = "TCP"  # TCP, UDP
    local_address: str
    local_port: int
    remote_address: Optional[str] = None
    remote_port: Optional[int] = None
    status: str = "ESTABLISHED"
    pid: Optional[int] = None
    process_name: Optional[str] = None
    timestamp: Optional[str] = None
    direction: Optional[str] = None  # outbound, inbound, unknown
    risk_indicators: List[str] = Field(default_factory=list)

    model_config = {"frozen": True}


class NetworkListener(BaseModel):
    """
    Forensic record of an open / listening local socket.
    """
    type: Literal["LISTENER"] = "LISTENER"
    protocol: str = "TCP"  # TCP, UDP
    local_address: str
    local_port: int
    pid: Optional[int] = None
    process_name: Optional[str] = None
    status: str = "LISTEN"
    risk_indicators: List[str] = Field(default_factory=list)

    model_config = {"frozen": True}


class DNSRecord(BaseModel):
    """
    Safe record of an explicitly resolved domain name query.
    """
    type: Literal["DNS_RECORD"] = "DNS_RECORD"
    domain: str
    addresses: List[str] = Field(default_factory=list)
    query_time: Optional[str] = None
    status: str = "RESOLVED"  # RESOLVED, NXDOMAIN, TIMEOUT, ERROR
    error: Optional[str] = None

    model_config = {"frozen": True}


# ──────────────────────────────────────────────────────────
# Network Result Model & Evidence Conversion Layer
# ──────────────────────────────────────────────────────────

class NetworkResult(BaseModel):
    """
    Structured outcome of ANALYZE NETWORK.
    Combines active connections, listeners, and DNS records into a unified result.
    """
    host: str
    operation: str = "ANALYZE_NETWORK"
    status: Literal["SUCCESS", "PARTIAL", "FAILED"] = "SUCCESS"
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    connections: List[NetworkConnection] = Field(default_factory=list)
    listeners: List[NetworkListener] = Field(default_factory=list)
    dns_records: List[DNSRecord] = Field(default_factory=list)
    summary: Dict[str, Any] = Field(default_factory=dict)
    errors: List[str] = Field(default_factory=list)

    def to_universal_evidence(self, case_id: Optional[str] = None):
        """
        Convert this NetworkResult's artifacts into strongly-typed UniversalEvidence objects.
        """
        from forensic.evidence.converters import network_result_to_evidence
        return network_result_to_evidence(self, case_id=case_id)

    def to_evidence(self) -> Dict[str, Any]:
        """
        Evidence Conversion Layer (Section 11):
        Bridges network forensic results into a standardized evidence package
        for the Universal Evidence Model.
        """
        universal_items = self.to_universal_evidence()
        return {
            "evidence_id": f"EVID-NET-{uuid.uuid4().hex[:8].upper()}",
            "evidence_class": "NETWORK_FORENSIC",
            "operation": self.operation,
            "host": self.host,
            "collected_at": self.timestamp,
            "status": self.status,
            "connection_count": len(self.connections),
            "listener_count": len(self.listeners),
            "dns_record_count": len(self.dns_records),
            "summary": self.summary,
            "errors": self.errors,
            "raw_connections": [c.model_dump() for c in self.connections],
            "raw_listeners": [l.model_dump() for l in self.listeners],
            "raw_dns": [d.model_dump() for d in self.dns_records],
            "universal_evidence": [e.to_dict() for e in universal_items],
        }


# ──────────────────────────────────────────────────────────
# Abstract Network Adapter Interface
# ──────────────────────────────────────────────────────────

class NetworkAdapter(ABC):
    """
    Abstract adapter for performing read-only network forensics.
    Both LocalNetworkAdapter and FixtureNetworkAdapter implement this interface.
    """

    @abstractmethod
    def analyze_connections(self, max_connections: int = 50) -> List[NetworkConnection]:
        """Collect active established or pending network connections."""
        pass

    @abstractmethod
    def analyze_listeners(self, max_listeners: int = 50) -> List[NetworkListener]:
        """Collect open listening ports / sockets."""
        pass

    @abstractmethod
    def analyze_dns(self, domains: Optional[List[str]] = None) -> List[DNSRecord]:
        """Perform safe resolution of explicit domain queries."""
        pass

    @abstractmethod
    def analyze_network(
        self, max_items: int = 50, domains: Optional[List[str]] = None
    ) -> NetworkResult:
        """Perform comprehensive network analysis combining connections, listeners, and DNS."""
        pass

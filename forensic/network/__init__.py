"""forensic/network package — public re-exports."""
from .base import (
    DNSRecord,
    NetworkAdapter,
    NetworkConnection,
    NetworkListener,
    NetworkResult,
    detect_connection_risk_indicators,
    detect_listener_risk_indicators,
    is_external_ip,
)
from .connections import collect_active_connections
from .listeners import collect_listening_ports
from .dns import collect_dns_records, resolve_domain
from .local import LocalNetworkAdapter
from .fixture import FixtureNetworkAdapter

__all__ = [
    "DNSRecord",
    "NetworkAdapter",
    "NetworkConnection",
    "NetworkListener",
    "NetworkResult",
    "detect_connection_risk_indicators",
    "detect_listener_risk_indicators",
    "is_external_ip",
    "collect_active_connections",
    "collect_listening_ports",
    "collect_dns_records",
    "resolve_domain",
    "LocalNetworkAdapter",
    "FixtureNetworkAdapter",
]

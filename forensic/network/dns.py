"""
JOCKY Forensic — DNS & Domain Information Collector
===================================================
Performs safe, non-invasive DNS metadata resolution for explicitly queried domains.

Safety guarantees:
- Non-invasive: Resolves only explicitly targeted domains.
- No tunneling, covert communication, or bulk scanning.
- Handles network unavailability and resolution timeouts gracefully.
"""

from __future__ import annotations

from datetime import datetime, timezone
import socket
from typing import List, Optional, Tuple

from forensic.network.base import DNSRecord


def resolve_domain(domain: str, timeout: float = 3.0) -> DNSRecord:
    """
    Safely resolve an explicit domain name into IPv4/IPv6 addresses.
    Does not crash on network errors or NXDOMAIN.
    """
    query_time = datetime.now(timezone.utc).isoformat()
    clean_domain = domain.strip().lower()

    if not clean_domain:
        return DNSRecord(
            domain=domain,
            addresses=[],
            query_time=query_time,
            status="ERROR",
            error="Empty domain query",
        )

    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        # Use getaddrinfo for safe cross-platform resolution
        addr_info = socket.getaddrinfo(clean_domain, None, proto=socket.IPPROTO_TCP)
        addresses = sorted(list({entry[4][0] for entry in addr_info if entry[4]}))

        if addresses:
            return DNSRecord(
                domain=clean_domain,
                addresses=addresses,
                query_time=query_time,
                status="RESOLVED",
                error=None,
            )
        return DNSRecord(
            domain=clean_domain,
            addresses=[],
            query_time=query_time,
            status="NXDOMAIN",
            error="No IP addresses returned for host",
        )

    except socket.gaierror as exc:
        return DNSRecord(
            domain=clean_domain,
            addresses=[],
            query_time=query_time,
            status="NXDOMAIN",
            error=f"DNS resolution failed: {exc}",
        )
    except socket.timeout:
        return DNSRecord(
            domain=clean_domain,
            addresses=[],
            query_time=query_time,
            status="TIMEOUT",
            error="DNS resolution timed out",
        )
    except Exception as exc:
        return DNSRecord(
            domain=clean_domain,
            addresses=[],
            query_time=query_time,
            status="ERROR",
            error=f"Unexpected resolution error: {exc}",
        )
    finally:
        socket.setdefaulttimeout(old_timeout)


def collect_dns_records(
    domains: Optional[List[str]] = None,
) -> Tuple[List[DNSRecord], List[str]]:
    """
    Resolve a list of explicitly requested domains.
    Defaults to localhost if no domains are provided.
    """
    target_domains = domains if domains is not None else ["localhost"]
    records: List[DNSRecord] = []
    errors: List[str] = []

    for dom in target_domains:
        record = resolve_domain(dom)
        records.append(record)
        if record.error and record.status not in ("NXDOMAIN", "RESOLVED"):
            errors.append(f"{dom}: {record.error}")

    return records, errors

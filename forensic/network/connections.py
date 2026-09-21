"""
JOCKY Forensic — Active Network Connections Collector
======================================================
Collects and normalizes live active network connections in read-only mode.

Forensic metadata collected:
- Local address & port
- Remote address & port
- Protocol (TCP / UDP)
- Connection status (ESTABLISHED, TIME_WAIT, etc.)
- Owning PID & process name
- Direction heuristic (outbound / inbound / unknown)
- Non-invasive risk indicators

Safety guarantees:
- READ-ONLY: Never terminates connections, modifies routes, or injects packets.
- PERMISSION RESILIENT: Gracefully handles psutil.AccessDenied on privileged sockets.
"""

from __future__ import annotations

from datetime import datetime, timezone
import socket
from typing import Dict, List, Optional, Tuple

import psutil

from forensic.network.base import NetworkConnection, detect_connection_risk_indicators


def _get_process_name(pid: Optional[int], cache: Dict[int, str]) -> Optional[str]:
    """Safely look up process name by PID with memoization."""
    if pid is None or pid <= 0:
        return None
    if pid in cache:
        return cache[pid]
    try:
        proc = psutil.Process(pid)
        name = proc.name()
        cache[pid] = name
        return name
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return None
    except Exception:
        return None


def _derive_direction(local_port: int, remote_port: Optional[int]) -> str:
    """Heuristic for connection direction."""
    if remote_port in (80, 443, 8080, 8443, 53):
        return "outbound"
    if local_port in (80, 443, 8080, 8443, 22, 21):
        return "inbound"
    if local_port >= 32768 and remote_port and remote_port < 32768:
        return "outbound"
    return "unknown"


def collect_active_connections(
    max_connections: int = 50,
) -> Tuple[List[NetworkConnection], List[str]]:
    """
    Safely inspect active network connections using psutil.
    Returns (connections, errors).
    """
    connections: List[NetworkConnection] = []
    errors: List[str] = []
    proc_cache: Dict[int, str] = {}
    timestamp = datetime.now(timezone.utc).isoformat()

    try:
        raw_conns = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        errors.append("Elevated permissions required to inspect full socket tables; collecting accessible sockets")
        try:
            raw_conns = psutil.net_connections(kind="tcp")
        except Exception as exc:
            errors.append(f"Unable to read socket table: {exc}")
            return [], errors
    except Exception as exc:
        errors.append(f"Network socket enumeration error: {exc}")
        return [], errors

    count = 0
    for conn in raw_conns:
        if count >= max_connections:
            break

        # Exclude listeners (handled by listener collector)
        if conn.status == "LISTEN" or not conn.raddr:
            continue

        proto = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
        local_addr, local_port = conn.laddr.ip, conn.laddr.port
        remote_addr, remote_port = conn.raddr.ip, conn.raddr.port
        status = conn.status or "ESTABLISHED"
        pid = conn.pid
        proc_name = _get_process_name(pid, proc_cache)
        direction = _derive_direction(local_port, remote_port)
        indicators = detect_connection_risk_indicators(remote_addr, remote_port, pid)

        artifact = NetworkConnection(
            protocol=proto,
            local_address=local_addr,
            local_port=local_port,
            remote_address=remote_addr,
            remote_port=remote_port,
            status=status,
            pid=pid,
            process_name=proc_name,
            timestamp=timestamp,
            direction=direction,
            risk_indicators=indicators,
        )
        connections.append(artifact)
        count += 1

    return connections, errors

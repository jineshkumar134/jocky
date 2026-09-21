"""
JOCKY Forensic — Listening Ports Collector
===========================================
Collects open listening sockets and server endpoints on the target host.

Forensic metadata collected:
- Protocol (TCP / UDP)
- Local address & port
- PID & process name
- Status (LISTEN)
- Non-invasive risk indicators (e.g. listening on 0.0.0.0)

Safety guarantees:
- READ-ONLY: Never closes sockets, interferes with bindings, or modifies ports.
"""

from __future__ import annotations

import socket
from typing import Dict, List, Optional, Tuple

import psutil

from forensic.network.base import NetworkListener, detect_listener_risk_indicators


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


def collect_listening_ports(
    max_listeners: int = 50,
) -> Tuple[List[NetworkListener], List[str]]:
    """
    Safely inspect listening sockets using psutil.
    Returns (listeners, errors).
    """
    listeners: List[NetworkListener] = []
    errors: List[str] = []
    proc_cache: Dict[int, str] = {}

    try:
        raw_conns = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        errors.append("Elevated permissions required to inspect all listening sockets")
        try:
            raw_conns = psutil.net_connections(kind="tcp")
        except Exception as exc:
            errors.append(f"Unable to read socket table for listeners: {exc}")
            return [], errors
    except Exception as exc:
        errors.append(f"Listener socket enumeration error: {exc}")
        return [], errors

    count = 0
    for conn in raw_conns:
        if count >= max_listeners:
            break

        # Sockets in LISTEN state or UDP listeners
        if conn.status != "LISTEN" and not (conn.type == socket.SOCK_DGRAM and not conn.raddr):
            continue

        proto = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
        local_addr = conn.laddr.ip if conn.laddr else "0.0.0.0"
        local_port = conn.laddr.port if conn.laddr else 0
        status = conn.status or "LISTEN"
        pid = conn.pid
        proc_name = _get_process_name(pid, proc_cache)
        indicators = detect_listener_risk_indicators(local_addr, local_port, pid)

        artifact = NetworkListener(
            protocol=proto,
            local_address=local_addr,
            local_port=local_port,
            pid=pid,
            process_name=proc_name,
            status=status,
            risk_indicators=indicators,
        )
        listeners.append(artifact)
        count += 1

    return listeners, errors

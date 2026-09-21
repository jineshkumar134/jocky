"""
JOCKY Forensic — System Forensics Engine
=========================================
Implements safe, read-only system information collection.

Forensic metadata collected:
- Hostname
- Operating System
- Architecture
- Kernel version
- Python runtime details
- CPU core count
- Total physical memory
- System boot time

Cross-platform: Works uniformly on macOS, Linux, and Windows.
"""

from __future__ import annotations

from datetime import datetime, timezone
import os
import platform
import socket
from typing import Optional, Tuple

import psutil

from forensic.endpoint.base import SystemArtifact


def _format_timestamp(ts: Optional[float]) -> Optional[str]:
    """Convert POSIX float timestamp to ISO 8601 UTC string."""
    if ts is None:
        return None
    try:
        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
        return dt.isoformat()
    except (OSError, OverflowError, ValueError):
        return None


def collect_system_artifact(override_hostname: Optional[str] = None) -> Tuple[SystemArtifact, list[str]]:
    """
    Collect platform and operating system metadata.
    Returns (system_artifact, errors).
    """
    errors: list[str] = []

    try:
        hostname = override_hostname or socket.gethostname() or platform.node() or "UNKNOWN-HOST"
    except Exception as exc:
        hostname = "UNKNOWN-HOST"
        errors.append(f"Could not resolve hostname: {exc}")

    os_name = platform.system() or "Unknown OS"
    architecture = platform.machine() or "unknown"
    kernel = platform.release() or "unknown"
    runtime = f"Python {platform.python_version()} ({platform.python_implementation()})"

    cpu_count = os.cpu_count()

    memory_total: Optional[int] = None
    boot_time: Optional[str] = None

    try:
        vm = psutil.virtual_memory()
        memory_total = vm.total
    except Exception as exc:
        errors.append(f"Could not read memory metrics: {exc}")

    try:
        bt = psutil.boot_time()
        boot_time = _format_timestamp(bt)
    except Exception as exc:
        errors.append(f"Could not read boot time: {exc}")

    artifact = SystemArtifact(
        hostname=hostname,
        os=os_name,
        architecture=architecture,
        kernel=kernel,
        runtime=runtime,
        cpu_count=cpu_count,
        memory_total_bytes=memory_total,
        boot_time=boot_time,
    )

    return artifact, errors

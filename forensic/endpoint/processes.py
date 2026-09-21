"""
JOCKY Forensic — Process Forensics Engine
==========================================
Implements safe, read-only process enumeration.

Forensic metadata collected:
- PID
- Process name
- Parent PID (PPID)
- Executable path
- Username / owner
- Start time (formatted ISO 8601 UTC)
- Status (running, sleeping, etc.)

Safety guarantees:
- READ-ONLY: Never terminates, suspends, injects into, hollows, or modifies processes.
- GRACEFUL: Handles psutil.AccessDenied, psutil.NoSuchProcess, and psutil.ZombieProcess cleanly.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional, Tuple

import psutil

from forensic.endpoint.base import ProcessArtifact


def _format_timestamp(ts: Optional[float]) -> Optional[str]:
    """Convert POSIX float timestamp to ISO 8601 UTC string."""
    if ts is None:
        return None
    try:
        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
        return dt.isoformat()
    except (OSError, OverflowError, ValueError):
        return None


def collect_process_artifacts(max_processes: int = 50) -> Tuple[List[ProcessArtifact], List[str]]:
    """
    Safely enumerate running processes on the host.
    Returns (artifacts, errors).
    """
    artifacts: List[ProcessArtifact] = []
    errors: List[str] = []

    count = 0
    # Use psutil.process_iter with specified attributes for efficiency & safety
    attrs = ["pid", "name", "ppid", "exe", "username", "create_time", "status"]

    try:
        for proc in psutil.process_iter(attrs):
            if count >= max_processes:
                break

            try:
                info = proc.info
                pid = info.get("pid")
                name = info.get("name") or "unknown"
                parent_pid = info.get("ppid")
                executable = info.get("exe")
                username = info.get("username")
                start_time = _format_timestamp(info.get("create_time"))
                status = str(info.get("status") or "running")

                artifact = ProcessArtifact(
                    pid=pid,
                    name=name,
                    parent_pid=parent_pid,
                    executable=executable,
                    username=username,
                    start_time=start_time,
                    status=status,
                    error=None,
                )
                artifacts.append(artifact)
                count += 1

            except (psutil.NoSuchProcess, psutil.ZombieProcess):
                # Process terminated or became zombie during inspection
                continue

            except psutil.AccessDenied:
                # System or root-owned process where details are protected
                try:
                    artifacts.append(
                        ProcessArtifact(
                            pid=proc.pid,
                            name=f"pid_{proc.pid}",
                            parent_pid=None,
                            executable=None,
                            username=None,
                            start_time=None,
                            status="access_denied",
                            error="Access denied / elevated permissions required",
                        )
                    )
                    count += 1
                except Exception:
                    pass

            except Exception as proc_err:
                errors.append(f"Error inspecting process PID {proc.pid}: {proc_err}")

    except Exception as exc:
        errors.append(f"Global error during process enumeration: {exc}")

    return artifacts, errors

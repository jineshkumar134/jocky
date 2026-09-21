"""
JOCKY Forensic — Local Endpoint Adapter
========================================
Implements real, safe, read-only endpoint forensic data collection on the local system.
Implements the EndpointAdapter interface.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from forensic.endpoint.base import EndpointAdapter, EndpointResult
from forensic.endpoint.files import collect_file_artifacts
from forensic.endpoint.processes import collect_process_artifacts
from forensic.endpoint.system import collect_system_artifact


class LocalEndpointAdapter(EndpointAdapter):
    """
    Real local system endpoint adapter for live read-only analysis.
    """

    def __init__(self, host: str = "LOCAL-HOST", default_scan_dir: Optional[Path] = None):
        self.host = host
        self.default_scan_dir = default_scan_dir or Path.cwd()

    def analyze_files(self, target_dir: Optional[str] = None, max_files: int = 50) -> EndpointResult:
        scan_path = Path(target_dir).resolve() if target_dir else self.default_scan_dir
        artifacts, errors = collect_file_artifacts(scan_path, max_files=max_files)

        total_bytes = sum(a.size for a in artifacts if not a.error)
        status = "SUCCESS" if not errors else ("PARTIAL" if artifacts else "FAILED")

        summary = {
            "total_files_analyzed": len(artifacts),
            "total_bytes": total_bytes,
            "target": str(scan_path),
            "adapter_type": "local",
        }

        return EndpointResult(
            host=self.host,
            operation="ANALYZE_FILES",
            status=status,
            artifacts=artifacts,
            summary=summary,
            errors=errors,
        )

    def analyze_processes(self, max_processes: int = 50) -> EndpointResult:
        artifacts, errors = collect_process_artifacts(max_processes=max_processes)

        status = "SUCCESS" if not errors else ("PARTIAL" if artifacts else "FAILED")
        running_count = sum(1 for a in artifacts if a.status in ("running", "sleeping", "idle"))

        summary = {
            "total_processes_analyzed": len(artifacts),
            "running_count": running_count,
            "adapter_type": "local",
        }

        return EndpointResult(
            host=self.host,
            operation="ANALYZE_PROCESSES",
            status=status,
            artifacts=artifacts,
            summary=summary,
            errors=errors,
        )

    def analyze_system(self) -> EndpointResult:
        artifact, errors = collect_system_artifact(override_hostname=self.host)

        status = "SUCCESS" if not errors else "PARTIAL"
        summary = {
            "os": artifact.os,
            "architecture": artifact.architecture,
            "kernel": artifact.kernel,
            "runtime": artifact.runtime,
            "cpu_count": artifact.cpu_count,
            "adapter_type": "local",
        }

        return EndpointResult(
            host=artifact.hostname,
            operation="ANALYZE_SYSTEM",
            status=status,
            artifacts=[artifact],
            summary=summary,
            errors=errors,
        )

"""
JOCKY Forensic — Fixture Endpoint Adapter
==========================================
Provides deterministic, repeatable endpoint forensic results for automated tests
and hackathon demonstrations without relying on live host state.

Implements the EndpointAdapter interface.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from forensic.endpoint.base import (
    EndpointAdapter,
    EndpointResult,
    FileArtifact,
    ProcessArtifact,
    SystemArtifact,
)

_DEFAULT_FIXTURE_DIR = Path(__file__).resolve().parent.parent.parent / "tests" / "fixtures" / "endpoint"

# Fallback deterministic data if fixture JSON files are not accessible
_FALLBACK_FILES: List[Dict[str, Any]] = [
    {
        "type": "FILE",
        "path": "/opt/security_lab/payloads/ransomware_dropper.bin",
        "name": "ransomware_dropper.bin",
        "extension": ".bin",
        "size": 49152,
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "created_at": "2026-09-12T14:30:00Z",
        "modified_at": "2026-09-12T14:32:15Z",
        "accessed_at": "2026-09-12T14:35:00Z",
        "file_type": "binary",
        "error": None,
    },
    {
        "type": "FILE",
        "path": "/opt/security_lab/scripts/stealth_beacon.py",
        "name": "stealth_beacon.py",
        "extension": ".py",
        "size": 8192,
        "sha256": "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a",
        "created_at": "2026-09-12T15:10:00Z",
        "modified_at": "2026-09-12T15:11:22Z",
        "accessed_at": "2026-09-12T15:15:00Z",
        "file_type": "script",
        "error": None,
    },
    {
        "type": "FILE",
        "path": "/opt/security_lab/notes/ransom_note.txt",
        "name": "ransom_note.txt",
        "extension": ".txt",
        "size": 1024,
        "sha256": "ef2d127de37b942baad06145e54b0c619a1f22327b2ebbcfbec78f5564afe39d",
        "created_at": "2026-09-12T16:00:00Z",
        "modified_at": "2026-09-12T16:00:05Z",
        "accessed_at": "2026-09-12T16:01:00Z",
        "file_type": "text",
        "error": None,
    },
]

_FALLBACK_PROCESSES: List[Dict[str, Any]] = [
    {
        "type": "PROCESS",
        "pid": 1042,
        "name": "systemd",
        "parent_pid": 1,
        "executable": "/usr/lib/systemd/systemd",
        "username": "root",
        "start_time": "2026-09-12T08:00:00Z",
        "status": "running",
        "error": None,
    },
    {
        "type": "PROCESS",
        "pid": 4821,
        "name": "suspicious_miner",
        "parent_pid": 1042,
        "executable": "/tmp/suspicious_miner",
        "username": "lab_user",
        "start_time": "2026-09-12T14:45:10Z",
        "status": "running",
        "error": None,
    },
    {
        "type": "PROCESS",
        "pid": 5102,
        "name": "c2_client",
        "parent_pid": 4821,
        "executable": "/opt/security_lab/scripts/stealth_beacon.py",
        "username": "lab_user",
        "start_time": "2026-09-12T15:12:00Z",
        "status": "sleeping",
        "error": None,
    },
]

_FALLBACK_SYSTEM: Dict[str, Any] = {
    "type": "SYSTEM",
    "hostname": "LAB-PC-01",
    "os": "Linux",
    "architecture": "x86_64",
    "kernel": "6.8.0-40-generic",
    "runtime": "Python 3.12.3 (CPython)",
    "cpu_count": 8,
    "memory_total_bytes": 16777216000,
    "boot_time": "2026-09-12T08:00:00Z",
}


class FixtureEndpointAdapter(EndpointAdapter):
    """
    Deterministic mock endpoint adapter.
    """

    def __init__(self, fixture_dir: Optional[Path] = None, host: str = "LAB-PC-01"):
        self.fixture_dir = fixture_dir or _DEFAULT_FIXTURE_DIR
        self.host = host

    def analyze_files(self, target_dir: Optional[str] = None, max_files: int = 50) -> EndpointResult:
        files_json_path = self.fixture_dir / "files.json"
        artifacts: List[FileArtifact] = []

        if files_json_path.exists():
            try:
                data = json.loads(files_json_path.read_text(encoding="utf-8"))
                for item in data[:max_files]:
                    artifacts.append(FileArtifact(**item))
            except Exception:
                artifacts = [FileArtifact(**item) for item in _FALLBACK_FILES[:max_files]]
        else:
            artifacts = [FileArtifact(**item) for item in _FALLBACK_FILES[:max_files]]

        total_size = sum(a.size for a in artifacts)
        summary = {
            "total_files_analyzed": len(artifacts),
            "total_bytes": total_size,
            "target": target_dir or "/opt/security_lab",
            "adapter_type": "fixture",
        }

        return EndpointResult(
            host=self.host,
            operation="ANALYZE_FILES",
            status="SUCCESS",
            artifacts=artifacts,
            summary=summary,
            errors=[],
        )

    def analyze_processes(self, max_processes: int = 50) -> EndpointResult:
        proc_json_path = self.fixture_dir / "processes.json"
        artifacts: List[ProcessArtifact] = []

        if proc_json_path.exists():
            try:
                data = json.loads(proc_json_path.read_text(encoding="utf-8"))
                for item in data[:max_processes]:
                    artifacts.append(ProcessArtifact(**item))
            except Exception:
                artifacts = [ProcessArtifact(**item) for item in _FALLBACK_PROCESSES[:max_processes]]
        else:
            artifacts = [ProcessArtifact(**item) for item in _FALLBACK_PROCESSES[:max_processes]]

        summary = {
            "total_processes_analyzed": len(artifacts),
            "running_count": sum(1 for a in artifacts if a.status == "running"),
            "adapter_type": "fixture",
        }

        return EndpointResult(
            host=self.host,
            operation="ANALYZE_PROCESSES",
            status="SUCCESS",
            artifacts=artifacts,
            summary=summary,
            errors=[],
        )

    def analyze_system(self) -> EndpointResult:
        sys_json_path = self.fixture_dir / "system.json"
        artifact: SystemArtifact

        if sys_json_path.exists():
            try:
                data = json.loads(sys_json_path.read_text(encoding="utf-8"))
                artifact = SystemArtifact(**data)
            except Exception:
                artifact = SystemArtifact(**_FALLBACK_SYSTEM)
        else:
            artifact = SystemArtifact(**_FALLBACK_SYSTEM)

        summary = {
            "os": artifact.os,
            "architecture": artifact.architecture,
            "runtime": artifact.runtime,
            "adapter_type": "fixture",
        }

        return EndpointResult(
            host=artifact.hostname,
            operation="ANALYZE_SYSTEM",
            status="SUCCESS",
            artifacts=[artifact],
            summary=summary,
            errors=[],
        )

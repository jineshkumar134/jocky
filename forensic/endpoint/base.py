"""
JOCKY Forensic — Endpoint Base Interfaces and Result Models
============================================================
Defines the abstract interface for all endpoint forensic adapters
and the strongly-typed artifact data models.

Safe, read-only collection models:
- FileArtifact
- ProcessArtifact
- SystemArtifact
- EndpointResult (includes an evidence conversion layer for future Universal Evidence Model)
- EndpointAdapter (abstract base class)
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Annotated, Any, Dict, List, Literal, Optional, Union
import uuid

from pydantic import BaseModel, Field


# ──────────────────────────────────────────────────────────
# Forensic Artifact Data Models (Read-Only)
# ──────────────────────────────────────────────────────────

class FileArtifact(BaseModel):
    """
    Forensic metadata for an analyzed file.
    Does NOT execute, modify, or delete any analyzed file.
    """
    type: Literal["FILE"] = "FILE"
    path: str
    name: str
    extension: str
    size: int
    sha256: str
    created_at: Optional[str] = None
    modified_at: str
    accessed_at: Optional[str] = None
    file_type: str = "other"  # executable, script, text, archive, binary, document, other
    error: Optional[str] = None

    model_config = {"frozen": True}


class ProcessArtifact(BaseModel):
    """
    Forensic snapshot of a running or enumerated process.
    Does NOT modify, suspend, inject into, or terminate any process.
    """
    type: Literal["PROCESS"] = "PROCESS"
    pid: int
    name: str
    parent_pid: Optional[int] = None
    executable: Optional[str] = None
    username: Optional[str] = None
    start_time: Optional[str] = None
    status: str = "running"
    error: Optional[str] = None

    model_config = {"frozen": True}


class SystemArtifact(BaseModel):
    """
    Host and operating system configuration artifact.
    """
    type: Literal["SYSTEM"] = "SYSTEM"
    hostname: str
    os: str
    architecture: str
    kernel: str
    runtime: str
    cpu_count: Optional[int] = None
    memory_total_bytes: Optional[int] = None
    boot_time: Optional[str] = None

    model_config = {"frozen": True}


ArtifactItem = Annotated[
    Union[FileArtifact, ProcessArtifact, SystemArtifact],
    Field(discriminator="type"),
]


# ──────────────────────────────────────────────────────────
# Endpoint Result Model & Evidence Conversion Layer
# ──────────────────────────────────────────────────────────

class EndpointResult(BaseModel):
    """
    Encapsulates the structured output of an endpoint analysis operation.
    """
    host: str
    operation: str  # ANALYZE_FILES, ANALYZE_PROCESSES, ANALYZE_SYSTEM
    status: Literal["SUCCESS", "PARTIAL", "FAILED"] = "SUCCESS"
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    artifacts: List[Union[FileArtifact, ProcessArtifact, SystemArtifact, Dict[str, Any]]] = Field(
        default_factory=list
    )
    summary: Dict[str, Any] = Field(default_factory=dict)
    errors: List[str] = Field(default_factory=list)

    def to_universal_evidence(self, case_id: Optional[str] = None):
        """
        Convert this EndpointResult's artifacts into strongly-typed UniversalEvidence objects.
        """
        from forensic.evidence.converters import endpoint_result_to_evidence
        return endpoint_result_to_evidence(self, case_id=case_id)

    def to_evidence(self) -> Dict[str, Any]:
        """
        Evidence Conversion Layer (Section 6):
        Provides an extensible bridge to convert raw endpoint forensic results
        into structured evidence packages for the Universal Evidence Model.
        """
        serialized_artifacts = [
            a.model_dump() if hasattr(a, "model_dump") else a
            for a in self.artifacts
        ]
        universal_items = self.to_universal_evidence()
        return {
            "evidence_id": f"EVID-EP-{uuid.uuid4().hex[:8].upper()}",
            "evidence_class": "ENDPOINT_FORENSIC",
            "operation": self.operation,
            "host": self.host,
            "collected_at": self.timestamp,
            "status": self.status,
            "artifact_count": len(self.artifacts),
            "summary": self.summary,
            "errors": self.errors,
            "raw_artifacts": serialized_artifacts,
            "universal_evidence": [e.to_dict() for e in universal_items],
        }


# ──────────────────────────────────────────────────────────
# Abstract Endpoint Adapter Interface
# ──────────────────────────────────────────────────────────

class EndpointAdapter(ABC):
    """
    Abstract adapter for performing read-only endpoint forensics.
    Both LocalEndpointAdapter and FixtureEndpointAdapter implement this interface.
    """

    @abstractmethod
    def analyze_files(self, target_dir: Optional[str] = None, max_files: int = 50) -> EndpointResult:
        """
        Collect safe forensic metadata and SHA-256 hashes of files.
        """
        pass

    @abstractmethod
    def analyze_processes(self, max_processes: int = 50) -> EndpointResult:
        """
        Collect safe snapshot of running process metadata.
        """
        pass

    @abstractmethod
    def analyze_system(self) -> EndpointResult:
        """
        Collect safe host platform and runtime environment metadata.
        """
        pass

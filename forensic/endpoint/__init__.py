"""forensic/endpoint package — public re-exports."""
from .base import (
    EndpointAdapter,
    EndpointResult,
    FileArtifact,
    ProcessArtifact,
    SystemArtifact,
)
from .files import calculate_sha256, classify_file_type, collect_file_artifacts
from .processes import collect_process_artifacts
from .system import collect_system_artifact
from .local import LocalEndpointAdapter
from .fixture import FixtureEndpointAdapter

__all__ = [
    "EndpointAdapter",
    "EndpointResult",
    "FileArtifact",
    "ProcessArtifact",
    "SystemArtifact",
    "calculate_sha256",
    "classify_file_type",
    "collect_file_artifacts",
    "collect_process_artifacts",
    "collect_system_artifact",
    "LocalEndpointAdapter",
    "FixtureEndpointAdapter",
]

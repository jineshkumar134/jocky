"""
JOCKY Forensic — File Forensics Engine
=======================================
Implements safe, read-only file metadata collection and cryptographic hashing.

Forensic metadata collected:
- path, filename, extension
- size (bytes)
- SHA-256 hash (computed via streaming 64KB blocks)
- created timestamp (if supported by OS / filesystem)
- modified timestamp
- accessed timestamp
- basic file type category

Safety guarantees:
- READ-ONLY: Never executes, modifies, moves, or deletes files.
- GRACEFUL: Catches PermissionError, FileNotFoundError, and OSError cleanly.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
from typing import List, Optional, Tuple

from forensic.endpoint.base import FileArtifact


# ──────────────────────────────────────────────────────────
# File Extension Classification Map
# ──────────────────────────────────────────────────────────

_EXT_CATEGORIES = {
    # Executables & libraries
    ".exe": "executable",
    ".dll": "executable",
    ".so": "executable",
    ".dylib": "executable",
    ".bin": "binary",
    ".elf": "executable",
    ".mach-o": "executable",
    # Scripts
    ".py": "script",
    ".sh": "script",
    ".bash": "script",
    ".zsh": "script",
    ".ps1": "script",
    ".bat": "script",
    ".cmd": "script",
    ".vbs": "script",
    ".js": "script",
    ".ts": "script",
    ".jky": "jocky_script",
    # Documents
    ".txt": "text",
    ".md": "text",
    ".json": "data",
    ".csv": "data",
    ".xml": "data",
    ".yaml": "data",
    ".yml": "data",
    ".pdf": "document",
    ".doc": "document",
    ".docx": "document",
    # Archives
    ".zip": "archive",
    ".tar": "archive",
    ".gz": "archive",
    ".bz2": "archive",
    ".7z": "archive",
    ".rar": "archive",
}


def classify_file_type(path: Path) -> str:
    """Classify file type by extension or basic structure."""
    ext = path.suffix.lower()
    return _EXT_CATEGORIES.get(ext, "other")


def calculate_sha256(file_path: Path, chunk_size: int = 65536) -> str:
    """
    Safely stream and compute the SHA-256 digest of a file.
    Does not read the entire file into memory at once.
    """
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(chunk_size):
            hasher.update(chunk)
    return hasher.hexdigest()


def _format_timestamp(ts: Optional[float]) -> Optional[str]:
    """Convert a POSIX timestamp float to an ISO 8601 string in UTC."""
    if ts is None:
        return None
    try:
        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
        return dt.isoformat()
    except (OSError, OverflowError, ValueError):
        return None


def analyze_single_file(file_path: Path) -> FileArtifact:
    """
    Inspect a single file and return its FileArtifact.
    Handles permission/IO errors gracefully within the artifact object.
    """
    path_str = str(file_path.resolve())
    name = file_path.name
    ext = file_path.suffix.lower()
    file_type = classify_file_type(file_path)

    try:
        st = file_path.stat()
        size = st.st_size
        modified_at = _format_timestamp(st.st_mtime) or "UNKNOWN"
        accessed_at = _format_timestamp(st.st_atime)

        # OS birthtime if available (macOS / BSD / some Windows)
        created_ts = getattr(st, "st_birthtime", None)
        if created_ts is None:
            created_ts = st.st_ctime
        created_at = _format_timestamp(created_ts)

        sha256_hash = calculate_sha256(file_path)

        return FileArtifact(
            path=path_str,
            name=name,
            extension=ext,
            size=size,
            sha256=sha256_hash,
            created_at=created_at,
            modified_at=modified_at,
            accessed_at=accessed_at,
            file_type=file_type,
            error=None,
        )

    except PermissionError:
        return FileArtifact(
            path=path_str,
            name=name,
            extension=ext,
            size=0,
            sha256="UNREADABLE_PERMISSION_DENIED",
            modified_at="UNKNOWN",
            file_type=file_type,
            error="Permission denied accessing file",
        )
    except FileNotFoundError:
        return FileArtifact(
            path=path_str,
            name=name,
            extension=ext,
            size=0,
            sha256="FILE_NOT_FOUND",
            modified_at="UNKNOWN",
            file_type=file_type,
            error="File not found during analysis",
        )
    except Exception as exc:
        return FileArtifact(
            path=path_str,
            name=name,
            extension=ext,
            size=0,
            sha256="READ_ERROR",
            modified_at="UNKNOWN",
            file_type=file_type,
            error=f"Error analyzing file: {exc}",
        )


def collect_file_artifacts(
    target_dir: Path, max_files: int = 50
) -> Tuple[List[FileArtifact], List[str]]:
    """
    Safely enumerate files in a directory up to max_files.
    Returns (artifacts, errors).
    """
    artifacts: List[FileArtifact] = []
    errors: List[str] = []

    if not target_dir.exists():
        errors.append(f"Target directory does not exist: {target_dir}")
        return artifacts, errors

    if not target_dir.is_dir():
        # Target is a single file
        artifacts.append(analyze_single_file(target_dir))
        return artifacts, errors

    try:
        count = 0
        for root, dirs, files in os.walk(target_dir):
            # Skip hidden directories like .git, .venv to avoid noise
            dirs[:] = [d for d in dirs if not d.startswith(".") and d != "__pycache__"]

            for f in sorted(files):
                if count >= max_files:
                    break
                file_path = Path(root) / f
                if file_path.is_file():
                    artifact = analyze_single_file(file_path)
                    artifacts.append(artifact)
                    if artifact.error:
                        errors.append(f"{file_path.name}: {artifact.error}")
                    count += 1
            if count >= max_files:
                break

    except PermissionError as exc:
        errors.append(f"Permission denied scanning directory {target_dir}: {exc}")
    except Exception as exc:
        errors.append(f"Error enumerating directory {target_dir}: {exc}")

    return artifacts, errors

"""
JOCKY Evidence Anchoring — Serialization
=========================================
Handles deterministic serialization of EvidencePackages to bytes for IPFS anchoring.
"""

from forensic.evidence.models import EvidencePackage
from forensic.evidence.canonical import canonical_json, canonical_hash

def serialize_evidence_package(package: EvidencePackage) -> bytes:
    """
    Serializes an EvidencePackage deterministically to bytes.
    The resulting bytes must hash to package.package_hash.
    """
    # Exclude dynamic/derived fields just like in EvidencePackage.compute_package_hash
    data = package.to_dict()
    if "package_hash" in data:
        del data["package_hash"]
    if "graph" in data:
        del data["graph"]
        
    return canonical_json(data).encode("utf-8")

def compute_package_hash_from_bytes(raw_bytes: bytes) -> str:
    """
    Computes the SHA-256 hash of the given raw bytes.
    """
    import hashlib
    return hashlib.sha256(raw_bytes).hexdigest()

def verify_package_bytes_hash(raw_bytes: bytes, expected_hash: str) -> bool:
    """
    Verifies that the raw bytes hash exactly matches the expected hash.
    """
    return compute_package_hash_from_bytes(raw_bytes) == expected_hash

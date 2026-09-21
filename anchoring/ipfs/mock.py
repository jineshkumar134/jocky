"""
JOCKY Evidence Anchoring — Mock IPFS Adapter
=============================================
Provides a deterministic, in-memory IPFS simulator for offline tests and demos.
"""

import hashlib
import base64
from typing import Dict

from .base import IPFSAdapter

class MockIPFSAdapter(IPFSAdapter):
    """
    Simulates an IPFS node.
    Computes a deterministic CID (using a simplified base32 CIDv1 sha256 format).
    """
    
    def __init__(self):
        self._store: Dict[str, bytes] = {}
        self._pinned: set[str] = set()

    def _compute_mock_cid(self, content: bytes) -> str:
        """
        Compute a mock CIDv1.
        Format: base32( 0x01 (cidv1) + 0x55 (raw) + 0x12 (sha2-256) + 0x20 (32 bytes) + hash )
        Simplified for testing to just base32 of the hash, prefixed with 'bafk'.
        """
        h = hashlib.sha256(content).digest()
        # Create a plausible-looking base32 string
        b32 = base64.b32encode(h).decode("utf-8").lower().replace("=", "")
        return f"bafk{b32}"

    def add_bytes(self, content: bytes) -> str:
        cid = self._compute_mock_cid(content)
        self._store[cid] = content
        return cid

    def cat_bytes(self, cid: str) -> bytes:
        if cid not in self._store:
            raise ValueError(f"CID {cid} not found in mock IPFS store")
        return self._store[cid]

    def pin(self, cid: str) -> bool:
        if cid not in self._store:
            return False
        self._pinned.add(cid)
        return True

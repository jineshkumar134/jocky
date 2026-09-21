"""
JOCKY Evidence Anchoring — IPFS Base Adapter
=============================================
"""

import abc

class IPFSAdapter(abc.ABC):
    """Abstract base class for interacting with IPFS."""

    @abc.abstractmethod
    def add_bytes(self, content: bytes) -> str:
        """Add raw bytes to IPFS and return the CID."""
        pass

    @abc.abstractmethod
    def cat_bytes(self, cid: str) -> bytes:
        """Retrieve raw bytes from IPFS by CID."""
        pass

    @abc.abstractmethod
    def pin(self, cid: str) -> bool:
        """Pin a CID on the IPFS node."""
        pass

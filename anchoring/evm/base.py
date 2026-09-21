"""
JOCKY Evidence Anchoring — EVM Base Adapter
=============================================
"""

import abc
from typing import Optional, Dict, Any
from ..models import AnchorRecord

class EVMAnchorAdapter(abc.ABC):
    """Abstract base class for anchoring evidence on an EVM blockchain."""

    @abc.abstractmethod
    def anchor_hash(self, package_hash: str, ipfs_cid: str, metadata: Optional[Dict[str, Any]] = None) -> AnchorRecord:
        """
        Anchor the package hash and IPFS CID on-chain.
        Returns the transaction record.
        """
        pass

    @abc.abstractmethod
    def verify_anchor(self, package_hash: str, ipfs_cid: Optional[str] = None) -> bool:
        """
        Verify that a package hash (and optionally IPFS CID) exists on-chain.
        """
        pass

    @abc.abstractmethod
    def get_anchor_record(self, package_hash: str) -> Optional[AnchorRecord]:
        """
        Retrieve the full on-chain record for a given package hash.
        """
        pass

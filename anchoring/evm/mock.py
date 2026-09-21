"""
JOCKY Evidence Anchoring — Mock EVM Adapter
=============================================
Deterministic, in-memory EVM anchoring for tests and demos.
"""

import hashlib
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from .base import EVMAnchorAdapter
from ..models import AnchorRecord

class MockEVMAdapter(EVMAnchorAdapter):
    """
    Simulates anchoring to an EVM network.
    """
    
    def __init__(self, chain_id: int = 31337):
        self.chain_id = chain_id
        self.contract_address = "0x100000000000000000000000000000000000J0C1"
        self._block_counter = 1000000
        self._records: Dict[str, AnchorRecord] = {}

    def _compute_mock_tx_hash(self, package_hash: str, block_number: int) -> str:
        """Deterministic transaction hash."""
        data = f"{self.chain_id}:{package_hash}:{block_number}".encode("utf-8")
        return "0x" + hashlib.sha256(data).hexdigest()

    def anchor_hash(self, package_hash: str, ipfs_cid: str, metadata: Optional[Dict[str, Any]] = None) -> AnchorRecord:
        if package_hash in self._records:
            return self._records[package_hash]

        self._block_counter += 1
        tx_hash = self._compute_mock_tx_hash(package_hash, self._block_counter)
        
        record = AnchorRecord(
            package_hash=package_hash,
            ipfs_cid=ipfs_cid,
            chain_id=self.chain_id,
            tx_hash=tx_hash,
            block_number=self._block_counter,
            contract_address=self.contract_address,
            anchored_at=datetime.now(timezone.utc).isoformat(),
            metadata=metadata
        )
        self._records[package_hash] = record
        return record

    def verify_anchor(self, package_hash: str, ipfs_cid: Optional[str] = None) -> bool:
        record = self.get_anchor_record(package_hash)
        if not record:
            return False
        if ipfs_cid and record.ipfs_cid != ipfs_cid:
            return False
        return True

    def get_anchor_record(self, package_hash: str) -> Optional[AnchorRecord]:
        return self._records.get(package_hash)

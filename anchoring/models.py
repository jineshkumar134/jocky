"""
JOCKY Evidence Anchoring — Models
===================================
Models for representing anchored evidence, EVM anchor records, and verification results.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class EvidenceAnchor(BaseModel):
    """
    Represents the full anchor of an EvidencePackage on IPFS and EVM.
    """
    package_hash: str
    ipfs_cid: str
    chain_id: int
    tx_hash: str
    block_number: int
    contract_address: str
    anchored_at: str
    metadata: Optional[Dict[str, Any]] = None

    model_config = {"frozen": True}
    
    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()


class AnchorRecord(BaseModel):
    """
    Represents an individual EVM anchoring record.
    """
    package_hash: str
    ipfs_cid: str
    chain_id: int
    tx_hash: str
    block_number: int
    contract_address: str
    anchored_at: str
    metadata: Optional[Dict[str, Any]] = None

    model_config = {"frozen": True}


class VerificationResult(BaseModel):
    """
    Result of verifying an EvidencePackage against its IPFS and EVM anchors.
    """
    is_valid: bool
    package_hash_match: bool
    ipfs_match: bool
    evm_match: bool
    expected_package_hash: str
    actual_package_hash: str
    details: Dict[str, Any] = Field(default_factory=dict)
    errors: List[str] = Field(default_factory=list)
    
    model_config = {"frozen": True}
    
    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()

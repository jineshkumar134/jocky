"""
JOCKY Evidence Anchoring — Engine
===================================
Coordinates serialization, IPFS storage, and EVM anchoring of EvidencePackages.
"""

from typing import Optional, Dict, Any
from forensic.evidence.models import EvidencePackage

from .models import EvidenceAnchor, VerificationResult
from .evidence import serialize_evidence_package, compute_package_hash_from_bytes
from .ipfs.base import IPFSAdapter
from .ipfs.mock import MockIPFSAdapter
from .evm.base import EVMAnchorAdapter
from .evm.mock import MockEVMAdapter

class EvidenceAnchorEngine:
    """
    Engine for creating and verifying immutable anchors of EvidencePackages.
    """
    
    def __init__(self, ipfs_adapter: Optional[IPFSAdapter] = None, evm_adapter: Optional[EVMAnchorAdapter] = None):
        self.ipfs = ipfs_adapter or MockIPFSAdapter()
        self.evm = evm_adapter or MockEVMAdapter()

    def anchor(self, package: EvidencePackage, metadata: Optional[Dict[str, Any]] = None) -> EvidenceAnchor:
        """
        Anchor an EvidencePackage to IPFS and EVM.
        """
        # 1. Serialize package deterministically
        raw_bytes = serialize_evidence_package(package)
        
        # 2. Add to IPFS
        cid = self.ipfs.add_bytes(raw_bytes)
        self.ipfs.pin(cid)
        
        # 3. Anchor to EVM
        record = self.evm.anchor_hash(package.package_hash, cid, metadata)
        
        # 4. Construct EvidenceAnchor
        return EvidenceAnchor(
            package_hash=record.package_hash,
            ipfs_cid=record.ipfs_cid,
            chain_id=record.chain_id,
            tx_hash=record.tx_hash,
            block_number=record.block_number,
            contract_address=record.contract_address,
            anchored_at=record.anchored_at,
            metadata=record.metadata
        )

    def verify(self, package: EvidencePackage, anchor: Optional[EvidenceAnchor] = None) -> VerificationResult:
        """
        Verify the integrity of a package against its anchor and/or IPFS/EVM state.
        """
        errors = []
        details = {}
        
        expected_hash = package.package_hash
        actual_hash = expected_hash  # unless tampering is detected
        
        # 1. Verify internal package integrity
        if not package.verify_package_integrity():
            errors.append("EvidencePackage internal integrity check failed (package_hash does not match contents).")
            # Recompute to find the actual hash
            from forensic.evidence.models import EvidencePackage
            # This is a bit of a hack to safely recompute without touching original
            # but compute_package_hash is safe to call
            actual_hash = package.compute_package_hash()
            
        package_hash_match = (expected_hash == actual_hash)
        if not package_hash_match:
            errors.append(f"Package hash mismatch. Expected {expected_hash}, got {actual_hash}.")

        ipfs_match = False
        evm_match = False

        # If no anchor provided, try to find one on EVM using the package hash
        if not anchor:
            record = self.evm.get_anchor_record(actual_hash)
            if record:
                # We found an anchor on chain for this hash!
                evm_match = True
                details["evm_tx_hash"] = record.tx_hash
                details["ipfs_cid"] = record.ipfs_cid
                
                # Check IPFS using the CID from EVM
                try:
                    stored_bytes = self.ipfs.cat_bytes(record.ipfs_cid)
                    stored_hash = compute_package_hash_from_bytes(stored_bytes)
                    if stored_hash == actual_hash:
                        ipfs_match = True
                    else:
                        errors.append(f"IPFS content hash mismatch. IPFS={stored_hash}, Package={actual_hash}")
                except Exception as e:
                    errors.append(f"Failed to retrieve or verify from IPFS: {e}")
            else:
                errors.append(f"No EVM anchor found for package hash {actual_hash}")
        else:
            # We have a specific anchor to verify against
            # 2. Check EVM
            record = self.evm.get_anchor_record(anchor.package_hash)
            if record:
                if record.tx_hash == anchor.tx_hash and record.ipfs_cid == anchor.ipfs_cid:
                    evm_match = True
                    details["evm_tx_hash"] = record.tx_hash
                else:
                    errors.append("EVM anchor mismatch: on-chain record does not match provided anchor details.")
            else:
                errors.append(f"EVM anchor not found for package hash {anchor.package_hash}")
                
            # 3. Check IPFS
            try:
                stored_bytes = self.ipfs.cat_bytes(anchor.ipfs_cid)
                stored_hash = compute_package_hash_from_bytes(stored_bytes)
                if stored_hash == actual_hash:
                    ipfs_match = True
                else:
                    errors.append(f"IPFS content hash mismatch. IPFS={stored_hash}, Package={actual_hash}")
            except Exception as e:
                errors.append(f"Failed to retrieve or verify from IPFS: {e}")

        is_valid = package_hash_match and ipfs_match and evm_match
        
        return VerificationResult(
            is_valid=is_valid,
            package_hash_match=package_hash_match,
            ipfs_match=ipfs_match,
            evm_match=evm_match,
            expected_package_hash=expected_hash,
            actual_package_hash=actual_hash,
            details=details,
            errors=errors
        )

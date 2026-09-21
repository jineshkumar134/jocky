"""
JOCKY Blockchain — Universal Evidence Converters
================================================
Converts blockchain forensic models (Wallet, Transaction, VASP, BlockchainEvent)
into strongly typed UniversalEvidence items and extracts strictly evidence-grounded
blockchain relationships.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from blockchain.models import (
    BlockchainEvent,
    BlockchainTraceResult,
    Transaction,
    VASPAttributionResult,
    VASPResult,
    Wallet,
)
from forensic.evidence.canonical import (
    canonical_hash,
    generate_evidence_id,
)
from forensic.evidence.models import (
    BlockchainEventEntity,
    EvidenceIntegrity,
    EvidenceProvenance,
    EvidenceType,
    Relationship,
    RelationshipType,
    TransactionEntity,
    UniversalEvidence,
    VASPEntity,
    WalletEntity,
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def wallet_to_evidence(
    wallet: Wallet,
    host: str,
    case_id: Optional[str] = None,
    collector: str = "EVMAdapter",
) -> UniversalEvidence:
    """Convert a Wallet model into a UniversalEvidence item."""
    entity = WalletEntity(
        address=wallet.address,
        chain=wallet.chain,
        first_seen=wallet.first_seen,
        last_seen=wallet.last_seen,
        label=wallet.label,
        wallet_type=wallet.wallet_type,
        confidence=wallet.confidence,
        balance=wallet.balance,
    )
    ev_id = generate_evidence_id(
        evidence_type=EvidenceType.WALLET.value,
        entity_data=entity.model_dump(),
        host=host,
        collector=collector,
    )
    collected_at = wallet.last_seen or _utc_now()
    provenance = EvidenceProvenance(
        collector=collector,
        adapter="blockchain",
        source=f"chain:{wallet.chain}",
        collection_method="eth_getAccount",
        collected_at=collected_at,
        host=host,
        case_id=case_id,
    )
    record_payload = {
        "id": ev_id,
        "type": EvidenceType.WALLET.value,
        "source": "blockchain",
        "timestamp": collected_at,
        "confidence": wallet.confidence,
        "entity": entity.model_dump(),
        "relationships": [],
        "provenance": provenance.model_dump(),
    }
    digest = canonical_hash(record_payload)
    integrity = EvidenceIntegrity(algorithm="SHA-256", value=digest)

    return UniversalEvidence(
        id=ev_id,
        type=EvidenceType.WALLET,
        source="blockchain",
        timestamp=collected_at,
        confidence=wallet.confidence,
        entity=entity,
        relationships=[],
        provenance=provenance,
        integrity=integrity,
    )


def transaction_to_evidence(
    tx: Transaction,
    host: str,
    case_id: Optional[str] = None,
    collector: str = "EVMAdapter",
) -> UniversalEvidence:
    """Convert a Transaction model into a UniversalEvidence item."""
    entity = TransactionEntity(
        tx_hash=tx.tx_hash,
        chain=tx.chain,
        block_number=tx.block_number,
        timestamp=tx.timestamp,
        from_address=tx.from_address,
        to_address=tx.to_address,
        asset=tx.asset,
        amount=tx.amount,
        status=tx.status,
        transaction_type=tx.transaction_type,
        metadata=tx.metadata,
    )
    ev_id = generate_evidence_id(
        evidence_type=EvidenceType.TRANSACTION.value,
        entity_data=entity.model_dump(),
        host=host,
        collector=collector,
    )
    collected_at = tx.timestamp
    provenance = EvidenceProvenance(
        collector=collector,
        adapter="blockchain",
        source=f"chain:{tx.chain}",
        collection_method="eth_getTransaction",
        collected_at=collected_at,
        host=host,
        case_id=case_id,
    )
    record_payload = {
        "id": ev_id,
        "type": EvidenceType.TRANSACTION.value,
        "source": "blockchain",
        "timestamp": collected_at,
        "confidence": 1.0,
        "entity": entity.model_dump(),
        "relationships": [],
        "provenance": provenance.model_dump(),
    }
    digest = canonical_hash(record_payload)
    integrity = EvidenceIntegrity(algorithm="SHA-256", value=digest)

    return UniversalEvidence(
        id=ev_id,
        type=EvidenceType.TRANSACTION,
        source="blockchain",
        timestamp=collected_at,
        confidence=1.0,
        entity=entity,
        relationships=[],
        provenance=provenance,
        integrity=integrity,
    )


def vasp_attribution_to_evidence(
    attr: VASPAttributionResult,
    host: str,
    case_id: Optional[str] = None,
    collector: str = "VASPAttributionEngine",
) -> UniversalEvidence:
    """Convert a VASPAttributionResult into a UniversalEvidence item."""
    entity = VASPEntity(
        vasp_id=attr.vasp_id,
        name=attr.name,
        score=attr.score,
        confidence=attr.confidence,
        reasons=attr.reasons,
        matched_wallets=attr.matched_wallets,
        supporting_tx_hashes=attr.supporting_tx_hashes,
        scoring_breakdown=attr.scoring_breakdown,
    )
    ev_id = generate_evidence_id(
        evidence_type=EvidenceType.VASP.value,
        entity_data=entity.model_dump(),
        host=host,
        collector=collector,
    )
    collected_at = _utc_now()
    provenance = EvidenceProvenance(
        collector=collector,
        adapter="blockchain",
        source="vasp_intelligence",
        collection_method="analytical_scoring",
        collected_at=collected_at,
        host=host,
        case_id=case_id,
    )
    record_payload = {
        "id": ev_id,
        "type": EvidenceType.VASP.value,
        "source": "blockchain",
        "timestamp": collected_at,
        "confidence": attr.confidence,
        "entity": entity.model_dump(),
        "relationships": [],
        "provenance": provenance.model_dump(),
    }
    digest = canonical_hash(record_payload)
    integrity = EvidenceIntegrity(algorithm="SHA-256", value=digest)

    return UniversalEvidence(
        id=ev_id,
        type=EvidenceType.VASP,
        source="blockchain",
        timestamp=collected_at,
        confidence=attr.confidence,
        entity=entity,
        relationships=[],
        provenance=provenance,
        integrity=integrity,
    )


def blockchain_event_to_evidence(
    event: BlockchainEvent,
    host: str,
    case_id: Optional[str] = None,
    collector: str = "EVMAdapter",
) -> UniversalEvidence:
    """Convert a BlockchainEvent into a UniversalEvidence item."""
    entity = BlockchainEventEntity(
        event_id=event.event_id,
        event_name=event.event_name,
        contract_address=event.contract_address,
        chain=event.chain,
        block_number=event.block_number,
        timestamp=event.timestamp,
        parameters=event.parameters,
    )
    ev_id = generate_evidence_id(
        evidence_type=EvidenceType.BLOCKCHAIN_EVENT.value,
        entity_data=entity.model_dump(),
        host=host,
        collector=collector,
    )
    collected_at = event.timestamp or _utc_now()
    provenance = EvidenceProvenance(
        collector=collector,
        adapter="blockchain",
        source=f"chain:{event.chain}",
        collection_method="eth_getLogs",
        collected_at=collected_at,
        host=host,
        case_id=case_id,
    )
    record_payload = {
        "id": ev_id,
        "type": EvidenceType.BLOCKCHAIN_EVENT.value,
        "source": "blockchain",
        "timestamp": collected_at,
        "confidence": 1.0,
        "entity": entity.model_dump(),
        "relationships": [],
        "provenance": provenance.model_dump(),
    }
    digest = canonical_hash(record_payload)
    integrity = EvidenceIntegrity(algorithm="SHA-256", value=digest)

    return UniversalEvidence(
        id=ev_id,
        type=EvidenceType.BLOCKCHAIN_EVENT,
        source="blockchain",
        timestamp=collected_at,
        confidence=1.0,
        entity=entity,
        relationships=[],
        provenance=provenance,
        integrity=integrity,
    )


def extract_blockchain_relationships(
    evidence_items: List[UniversalEvidence],
) -> List[Relationship]:
    """
    Extract strictly evidence-grounded relationships between blockchain entities:
    - WALLET -> SENT_TO -> WALLET (referenced by TRANSACTION)
    - WALLET -> ASSOCIATED_WITH -> TRANSACTION
    - WALLET -> ATTRIBUTED_TO -> VASP
    """
    relationships: List[Relationship] = []
    rel_ids_seen = set()

    wallets_by_addr: Dict[str, UniversalEvidence] = {}
    tx_by_hash: Dict[str, UniversalEvidence] = {}
    vasp_items: List[UniversalEvidence] = []

    for ev in evidence_items:
        if ev.type == EvidenceType.WALLET and hasattr(ev.entity, "address"):
            wallets_by_addr[ev.entity.address.lower()] = ev
        elif ev.type == EvidenceType.TRANSACTION and hasattr(ev.entity, "tx_hash"):
            tx_by_hash[ev.entity.tx_hash.lower()] = ev
        elif ev.type == EvidenceType.VASP:
            vasp_items.append(ev)

    # 1. WALLET -> SENT_TO -> WALLET via confirmed transactions
    for tx_ev in tx_by_hash.values():
        from_addr = tx_ev.entity.from_address.lower()
        to_addr = tx_ev.entity.to_address.lower()

        w_from = wallets_by_addr.get(from_addr)
        w_to = wallets_by_addr.get(to_addr)

        if w_from and w_to:
            rel = Relationship.create(
                rel_type=RelationshipType.SENT_TO,
                source_id=w_from.id,
                target_id=w_to.id,
                timestamp=tx_ev.entity.timestamp,
                confidence=1.0,
                supporting_evidence=[w_from.id, tx_ev.id, w_to.id],
                metadata={
                    "tx_hash": tx_ev.entity.tx_hash,
                    "amount": tx_ev.entity.amount,
                    "asset": tx_ev.entity.asset,
                    "chain": tx_ev.entity.chain,
                },
            )
            if rel.id not in rel_ids_seen:
                rel_ids_seen.add(rel.id)
                relationships.append(rel)

        # Also link WALLET -> ASSOCIATED_WITH -> TRANSACTION
        if w_from:
            rel_assoc = Relationship.create(
                rel_type=RelationshipType.ASSOCIATED_WITH,
                source_id=w_from.id,
                target_id=tx_ev.id,
                timestamp=tx_ev.entity.timestamp,
                confidence=1.0,
                supporting_evidence=[w_from.id, tx_ev.id],
                metadata={"role": "sender", "tx_hash": tx_ev.entity.tx_hash},
            )
            if rel_assoc.id not in rel_ids_seen:
                rel_ids_seen.add(rel_assoc.id)
                relationships.append(rel_assoc)

        if w_to:
            rel_assoc = Relationship.create(
                rel_type=RelationshipType.ASSOCIATED_WITH,
                source_id=w_to.id,
                target_id=tx_ev.id,
                timestamp=tx_ev.entity.timestamp,
                confidence=1.0,
                supporting_evidence=[w_to.id, tx_ev.id],
                metadata={"role": "recipient", "tx_hash": tx_ev.entity.tx_hash},
            )
            if rel_assoc.id not in rel_ids_seen:
                rel_ids_seen.add(rel_assoc.id)
                relationships.append(rel_assoc)

    # 2. WALLET -> ATTRIBUTED_TO -> VASP
    for vasp_ev in vasp_items:
        matched_wallets = getattr(vasp_ev.entity, "matched_wallets", [])
        for m_addr in matched_wallets:
            w_ev = wallets_by_addr.get(m_addr.lower())
            if w_ev:
                supporting = [w_ev.id, vasp_ev.id]
                # Include supporting tx hashes if present
                for tx_h in getattr(vasp_ev.entity, "supporting_tx_hashes", []):
                    if tx_h.lower() in tx_by_hash:
                        supporting.append(tx_by_hash[tx_h.lower()].id)

                rel = Relationship.create(
                    rel_type=RelationshipType.ATTRIBUTED_TO,
                    source_id=w_ev.id,
                    target_id=vasp_ev.id,
                    confidence=vasp_ev.confidence,
                    supporting_evidence=supporting,
                    metadata={
                        "vasp_name": getattr(vasp_ev.entity, "name", ""),
                        "score": getattr(vasp_ev.entity, "score", 0.0),
                        "reasons": getattr(vasp_ev.entity, "reasons", []),
                    },
                )
                if rel.id not in rel_ids_seen:
                    rel_ids_seen.add(rel.id)
                    relationships.append(rel)

    return relationships

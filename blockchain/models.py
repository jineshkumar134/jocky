"""
JOCKY Blockchain — Strongly Typed Blockchain Data Models
========================================================
Defines strongly typed models for:
- Wallet
- Transaction
- BlockchainEvent
- TraceHop & BlockchainTraceResult
- VASPAttributionResult & VASPResult

All models follow Pydantic v2 conventions consistent with Phase 6.
"""

from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field


class Wallet(BaseModel):
    """
    Forensic representation of a blockchain wallet / address.
    """
    address: str
    chain: str = "ethereum"
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    label: Optional[str] = None
    wallet_type: str = "unknown"  # eoa, contract, exchange_deposit, exchange_hot_wallet, custodial, unknown
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    balance: Optional[float] = 0.0

    model_config = {"frozen": True}


class Transaction(BaseModel):
    """
    Forensic representation of an on-chain transaction.
    """
    tx_hash: str
    chain: str = "ethereum"
    block_number: Optional[int] = None
    timestamp: str
    from_address: str
    to_address: str
    asset: str = "ETH"
    amount: float
    status: str = "confirmed"  # confirmed, pending, failed
    transaction_type: str = "transfer"  # transfer, contract_call, deploy
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = {"frozen": True}


class BlockchainEvent(BaseModel):
    """
    Forensic representation of a smart contract event or log.
    """
    event_id: str
    chain: str = "ethereum"
    event_name: str
    contract_address: str
    block_number: Optional[int] = None
    timestamp: Optional[str] = None
    parameters: Dict[str, Any] = Field(default_factory=dict)

    model_config = {"frozen": True}


class TraceHop(BaseModel):
    """
    A single transaction hop in a multi-hop trace chain.
    """
    hop_number: int
    from_wallet: str
    to_wallet: str
    tx_hash: str
    amount: float
    asset: str
    timestamp: str

    model_config = {"frozen": True}


class BlockchainTraceResult(BaseModel):
    """
    Aggregate outcome of a multi-hop blockchain trace operation.
    """
    seed_address: str
    chain: str = "ethereum"
    wallets: List[Wallet] = Field(default_factory=list)
    transactions: List[Transaction] = Field(default_factory=list)
    hops: List[TraceHop] = Field(default_factory=list)
    summary: Dict[str, Any] = Field(default_factory=dict)

    model_config = {"frozen": True}


class VASPAttributionResult(BaseModel):
    """
    Explainable attribution of a wallet / transaction chain to a VASP.
    """
    vasp_id: str
    name: str
    score: float = Field(ge=0.0, le=1.0)
    confidence: float = Field(ge=0.0, le=1.0)
    reasons: List[str] = Field(default_factory=list)
    matched_wallets: List[str] = Field(default_factory=list)
    supporting_tx_hashes: List[str] = Field(default_factory=list)
    scoring_breakdown: Dict[str, float] = Field(default_factory=dict)

    model_config = {"frozen": True}


class VASPResult(BaseModel):
    """
    Outcome of an IDENTIFY VASP operation.
    """
    target_wallet: Optional[str] = None
    attributions: List[VASPAttributionResult] = Field(default_factory=list)
    summary: Dict[str, Any] = Field(default_factory=dict)

    model_config = {"frozen": True}

"""
JOCKY Blockchain — Abstract Blockchain Adapter Interface
========================================================
Defines the chain-agnostic interface for blockchain data acquisition.
Concrete implementations include EVMAdapter (with deterministic fixture mode
and optional live JSON-RPC capabilities).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from blockchain.models import Transaction, Wallet


class BlockchainAdapter(ABC):
    """
    Abstract adapter for performing read-only blockchain forensic intelligence.
    """

    @abstractmethod
    def get_wallet(self, address: str, chain: str = "ethereum") -> Optional[Wallet]:
        """Retrieve wallet metadata, label, and balance for an address."""
        pass

    @abstractmethod
    def get_transactions(self, address: str, chain: str = "ethereum") -> List[Transaction]:
        """Retrieve transactions involving the given wallet address."""
        pass

    @abstractmethod
    def get_transaction(self, tx_hash: str, chain: str = "ethereum") -> Optional[Transaction]:
        """Retrieve a specific transaction by its hash."""
        pass

    @abstractmethod
    def get_block(self, block_number: int, chain: str = "ethereum") -> Optional[Dict[str, Any]]:
        """Retrieve block metadata for a given block height."""
        pass

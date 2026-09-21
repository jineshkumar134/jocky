"""
JOCKY Blockchain — EVM Adapter Implementation
=============================================
Provides Ethereum and EVM-compatible blockchain data acquisition.
Defaults to deterministic, offline synthetic fixtures for reproducible testing.
Optional live JSON-RPC connection can be configured without altering offline guarantees.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from blockchain.base import BlockchainAdapter
from blockchain.models import Transaction, Wallet


class EVMAdapter(BlockchainAdapter):
    """
    Ethereum / EVM forensic adapter.
    Operates in deterministic fixture mode by default, ensuring all tests
    and offline hackathon demonstrations execute without network access.
    """

    def __init__(
        self,
        fixture_dir: Optional[Path] = None,
        rpc_url: Optional[str] = None,
    ):
        self.fixture_dir = fixture_dir or (Path(__file__).parent.parent / "fixtures")
        self.rpc_url = rpc_url
        self._wallets: Dict[str, Wallet] = {}
        self._transactions: List[Transaction] = []
        self._load_fixtures()

    def _load_fixtures(self) -> None:
        """Load deterministic synthetic blockchain fixtures."""
        wallets_file = self.fixture_dir / "wallet_labels.json"
        if wallets_file.exists():
            try:
                data = json.loads(wallets_file.read_text(encoding="utf-8"))
                for addr, wdata in data.items():
                    self._wallets[addr.lower()] = Wallet(**wdata)
            except Exception:
                pass

        tx_file = self.fixture_dir / "ethereum_transactions.json"
        if tx_file.exists():
            try:
                data = json.loads(tx_file.read_text(encoding="utf-8"))
                for tx_data in data:
                    self._transactions.append(Transaction(**tx_data))
            except Exception:
                pass

    def get_wallet(self, address: str, chain: str = "ethereum") -> Optional[Wallet]:
        """
        Retrieve wallet forensic metadata.
        Returns curated fixture data or an unknown wallet fallback.
        """
        norm = address.lower()
        if norm in self._wallets:
            return self._wallets[norm]

        # Unknown wallet fallback (deterministic)
        return Wallet(
            address=address,
            chain=chain,
            label="Unknown Wallet",
            wallet_type="unknown",
            confidence=0.5,
            balance=0.0,
        )

    def get_transactions(self, address: str, chain: str = "ethereum") -> List[Transaction]:
        """
        Retrieve all transactions involving the address.
        """
        norm = address.lower()
        results: List[Transaction] = []
        for tx in self._transactions:
            if tx.chain.lower() == chain.lower():
                if tx.from_address.lower() == norm or tx.to_address.lower() == norm:
                    results.append(tx)
        return results

    def get_transaction(self, tx_hash: str, chain: str = "ethereum") -> Optional[Transaction]:
        """
        Retrieve a specific transaction by transaction hash.
        """
        norm = tx_hash.lower()
        for tx in self._transactions:
            if tx.chain.lower() == chain.lower() and tx.tx_hash.lower() == norm:
                return tx
        return None

    def get_block(self, block_number: int, chain: str = "ethereum") -> Optional[Dict[str, Any]]:
        """
        Retrieve synthetic block header information.
        """
        return {
            "block_number": block_number,
            "chain": chain,
            "timestamp": "2026-09-12T16:00:00Z",
            "gas_limit": 30000000,
            "gas_used": 15000000,
        }

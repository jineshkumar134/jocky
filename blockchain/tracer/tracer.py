"""
JOCKY Blockchain — Safe Multi-Hop Blockchain Tracer
===================================================
Reconstructs transaction chains from a seed wallet address across
connected hops.
- Reconstructs forward and backward transaction flows.
- Grounded in factual on-chain / fixture transaction records.
- Deterministic exploration without evasive/mixing techniques.
"""

from __future__ import annotations

from typing import Any, Dict, List, Set

from blockchain.base import BlockchainAdapter
from blockchain.models import BlockchainTraceResult, TraceHop, Transaction, Wallet


class BlockchainTracer:
    """
    Forensic transaction flow reconstructor.
    Explores multi-hop transaction graphs up to a configurable hop limit.
    """

    def __init__(self, adapter: BlockchainAdapter):
        self.adapter = adapter

    def trace(
        self,
        seed_address: str,
        chain: str = "ethereum",
        max_hops: int = 3,
        direction: str = "forward",
    ) -> BlockchainTraceResult:
        """
        Execute multi-hop transaction tracing starting from seed_address.
        """
        wallets_map: Dict[str, Wallet] = {}
        transactions_map: Dict[str, Transaction] = {}
        hops: List[TraceHop] = []
        visited_addresses: Set[str] = set()

        seed_wallet = self.adapter.get_wallet(seed_address, chain=chain)
        if seed_wallet:
            wallets_map[seed_wallet.address.lower()] = seed_wallet

        # Breadth-first exploration
        current_layer = [seed_address]
        visited_addresses.add(seed_address.lower())

        for hop_idx in range(1, max_hops + 1):
            next_layer: List[str] = []
            for addr in current_layer:
                txs = self.adapter.get_transactions(addr, chain=chain)
                for tx in txs:
                    transactions_map[tx.tx_hash.lower()] = tx

                    if direction in ("forward", "both"):
                        if tx.from_address.lower() == addr.lower():
                            to_addr = tx.to_address
                            if to_addr.lower() not in wallets_map:
                                w = self.adapter.get_wallet(to_addr, chain=chain)
                                if w:
                                    wallets_map[to_addr.lower()] = w

                            hops.append(
                                TraceHop(
                                    hop_number=hop_idx,
                                    from_wallet=addr,
                                    to_wallet=to_addr,
                                    tx_hash=tx.tx_hash,
                                    amount=tx.amount,
                                    asset=tx.asset,
                                    timestamp=tx.timestamp,
                                )
                            )
                            if to_addr.lower() not in visited_addresses:
                                visited_addresses.add(to_addr.lower())
                                next_layer.append(to_addr)

                    if direction in ("backward", "both"):
                        if tx.to_address.lower() == addr.lower():
                            from_addr = tx.from_address
                            if from_addr.lower() not in wallets_map:
                                w = self.adapter.get_wallet(from_addr, chain=chain)
                                if w:
                                    wallets_map[from_addr.lower()] = w

                            hops.append(
                                TraceHop(
                                    hop_number=hop_idx,
                                    from_wallet=from_addr,
                                    to_wallet=addr,
                                    tx_hash=tx.tx_hash,
                                    amount=tx.amount,
                                    asset=tx.asset,
                                    timestamp=tx.timestamp,
                                )
                            )
                            if from_addr.lower() not in visited_addresses:
                                visited_addresses.add(from_addr.lower())
                                next_layer.append(from_addr)

            current_layer = next_layer
            if not current_layer:
                break

        summary: Dict[str, Any] = {
            "seed_address": seed_address,
            "chain": chain,
            "total_hops": len(hops),
            "wallets_discovered": len(wallets_map),
            "transactions_analyzed": len(transactions_map),
            "max_hop_depth": max((h.hop_number for h in hops), default=0),
        }

        return BlockchainTraceResult(
            seed_address=seed_address,
            chain=chain,
            wallets=list(wallets_map.values()),
            transactions=list(transactions_map.values()),
            hops=hops,
            summary=summary,
        )

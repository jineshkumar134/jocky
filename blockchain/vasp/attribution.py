"""
JOCKY Blockchain — Explainable VASP Attribution Engine
======================================================
Provides explainable, deterministic attribution of blockchain wallets
and transaction chains to known Virtual Asset Service Providers (VASPs).

Scoring Model:
Additive deterministic scoring model with a strict maximum bound of 1.00:
  - direct_label_match    = 0.45 (Curated label matches VASP name or keywords)
  - wallet_type_match     = 0.30 (Wallet type corresponds to exchange/custodial infra)
  - address_cluster_match = 0.20 (Address matches curated public VASP address pattern)
  - base_confidence       = 0.05 (Baseline analytical certainty when evidence is present)
  Total Max Score = 1.00 (Strictly bounded in [0.0, 1.0])

Important Compliance / Scope Boundary:
This engine performs analytical attribution based purely on public and curated fixture
labels. It does NOT perform private KYC retrieval, unauthorized exchange access,
or covert financial tracking.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from blockchain.models import Transaction, VASPAttributionResult, VASPResult, Wallet


# Strict additive score constants (sum = 1.00)
SCORE_DIRECT_LABEL_MATCH = 0.45
SCORE_WALLET_TYPE_MATCH = 0.30
SCORE_ADDRESS_CLUSTER_MATCH = 0.20
SCORE_BASE_CONFIDENCE = 0.05


class VASPProfile:
    """Curated public/synthetic profile for a known VASP."""

    def __init__(
        self,
        vasp_id: str,
        name: str,
        jurisdiction: str = "Synthetic Lab Jurisdiction",
        risk_rating: str = "low",
        public_deposit_patterns: Optional[List[str]] = None,
        keywords: Optional[List[str]] = None,
    ):
        self.vasp_id = vasp_id
        self.name = name
        self.jurisdiction = jurisdiction
        self.risk_rating = risk_rating
        self.public_deposit_patterns = [p.lower() for p in (public_deposit_patterns or [])]
        self.keywords = [k.lower() for k in (keywords or [name])]


class VASPAttributionEngine:
    """
    Forensic VASP attribution evaluator with explainability breakdown.
    """

    def __init__(self, fixture_dir: Optional[Path] = None):
        self.fixture_dir = fixture_dir or (Path(__file__).parent.parent / "fixtures")
        self._vasp_profiles: Dict[str, VASPProfile] = {}
        self._load_profiles()

    def _load_profiles(self) -> None:
        """Load synthetic VASP profiles from fixtures."""
        profiles_file = self.fixture_dir / "vasp_labels.json"
        if profiles_file.exists():
            try:
                data = json.loads(profiles_file.read_text(encoding="utf-8"))
                for vasp_id, pdata in data.items():
                    self._vasp_profiles[vasp_id] = VASPProfile(**pdata)
            except Exception:
                pass

    def attribute(
        self,
        wallets: List[Wallet],
        transactions: Optional[List[Transaction]] = None,
        target_wallet: Optional[str] = None,
    ) -> VASPResult:
        """
        Evaluate a collection of wallets and transactions against known VASP profiles.
        Returns a ranked list of explainable VASP attributions.
        """
        txs = transactions or []
        attributions: List[VASPAttributionResult] = []

        for vasp_id, profile in self._vasp_profiles.items():
            score = 0.0
            reasons: List[str] = []
            breakdown: Dict[str, float] = {}
            matched_wallets: List[str] = []
            supporting_tx_hashes: List[str] = []

            has_direct_label = False
            has_wallet_type = False
            has_cluster_match = False

            # 1. Evaluate Wallets
            for w in wallets:
                w_addr = w.address.lower()
                # A. Direct Label Match (0.45)
                if w.label:
                    label_lower = w.label.lower()
                    if any(kw in label_lower for kw in profile.keywords):
                        has_direct_label = True
                        matched_wallets.append(w.address)
                        reasons.append(
                            f"Wallet '{w.address}' label '{w.label}' matches VASP '{profile.name}' (+{SCORE_DIRECT_LABEL_MATCH})"
                        )

                # B. Wallet Type Match (0.30)
                if w.wallet_type in ("exchange_deposit", "exchange_hot_wallet", "custodial"):
                    has_wallet_type = True
                    if w.address not in matched_wallets:
                        matched_wallets.append(w.address)
                    reasons.append(
                        f"Wallet '{w.address}' type '{w.wallet_type}' represents institutional/exchange infrastructure (+{SCORE_WALLET_TYPE_MATCH})"
                    )

                # C. Address Cluster Match (0.20)
                if w_addr in profile.public_deposit_patterns:
                    has_cluster_match = True
                    if w.address not in matched_wallets:
                        matched_wallets.append(w.address)
                    reasons.append(
                        f"Wallet address '{w.address}' directly matches curated VASP address pattern (+{SCORE_ADDRESS_CLUSTER_MATCH})"
                    )

            # 2. Evaluate Transactions for counterparty cluster matches
            for tx in txs:
                to_addr = tx.to_address.lower()
                from_addr = tx.from_address.lower()
                if to_addr in profile.public_deposit_patterns or from_addr in profile.public_deposit_patterns:
                    has_cluster_match = True
                    supporting_tx_hashes.append(tx.tx_hash)
                    reasons.append(
                        f"Transaction '{tx.tx_hash}' routes to/from VASP address cluster ({tx.amount} {tx.asset})"
                    )

            # Calculate score using explicit additive formula
            if has_direct_label:
                score += SCORE_DIRECT_LABEL_MATCH
                breakdown["direct_label_match"] = SCORE_DIRECT_LABEL_MATCH

            if has_wallet_type:
                score += SCORE_WALLET_TYPE_MATCH
                breakdown["wallet_type_match"] = SCORE_WALLET_TYPE_MATCH

            if has_cluster_match:
                score += SCORE_ADDRESS_CLUSTER_MATCH
                breakdown["address_cluster_match"] = SCORE_ADDRESS_CLUSTER_MATCH

            # Base confidence (0.05) added only if at least one grounded indicator matched
            if score > 0.0:
                score += SCORE_BASE_CONFIDENCE
                breakdown["base_confidence"] = SCORE_BASE_CONFIDENCE
                reasons.append(
                    f"Grounded forensic indicators present; baseline certainty added (+{SCORE_BASE_CONFIDENCE})"
                )

            # Enforce strict [0.0, 1.0] bounds
            final_score = min(1.0, max(0.0, round(score, 4)))

            if final_score > 0.0:
                attributions.append(
                    VASPAttributionResult(
                        vasp_id=vasp_id,
                        name=profile.name,
                        score=final_score,
                        confidence=final_score,
                        reasons=reasons,
                        matched_wallets=list(set(matched_wallets)),
                        supporting_tx_hashes=list(set(supporting_tx_hashes)),
                        scoring_breakdown=breakdown,
                    )
                )

        # Sort attributions descending by score
        attributions.sort(key=lambda a: a.score, reverse=True)

        summary: Dict[str, Any] = {
            "target_wallet": target_wallet,
            "candidate_count": len(attributions),
            "top_candidate": attributions[0].name if attributions else None,
            "top_score": attributions[0].score if attributions else 0.0,
        }

        return VASPResult(
            target_wallet=target_wallet,
            attributions=attributions,
            summary=summary,
        )

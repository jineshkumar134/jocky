"""
JOCKY Correlation Engine — Confidence Scoring
=============================================

Deterministic, bounded confidence constants and scoring utilities.

Weakest-Link Principle
----------------------
For cross-domain correlation chains, the overall confidence equals the MINIMUM
confidence across all individual link findings.  This prevents strong evidence
in one domain from masking weak evidence in another.

Example::
    PROCESS → NETWORK = 0.95  (DIRECT_PID_MATCH)
    NETWORK → WALLET  = 0.65  (EXPLICIT_FIXTURE_MAPPING)
    WALLET  → TX      = 0.95  (TRANSACTION_ADDRESS_MATCH)
    TX      → VASP    = 0.91  (VASP_ATTRIBUTION)

    CROSS_DOMAIN confidence = min(0.95, 0.65, 0.95, 0.91) = 0.65

Rationale: An investigation chain is only as reliable as its weakest
evidential link.  Averaging would obscure weak evidence and inflate the
apparent confidence.
"""

from __future__ import annotations

from typing import List

# ── Per-rule confidence constants ─────────────────────────────────────────────

# Rule 1: PROCESS → NETWORK_CONNECTION (direct PID match in both records)
SCORE_DIRECT_PID_MATCH: float = 0.95

# Rule 2: NETWORK_CONNECTION → DNS_RECORD (remote IP is in DNS resolved addresses)
SCORE_EXPLICIT_DNS_MATCH: float = 0.90

# Rule 3: NETWORK_CONNECTION → WALLET (explicit curated fixture/public mapping)
# NOTE: This does NOT establish wallet ownership.  It reflects a curated
# fixture mapping from an observed IP to a known blockchain endpoint.
SCORE_EXPLICIT_FIXTURE_NETWORK_BLOCKCHAIN: float = 0.65

# Rule 4: WALLET → TRANSACTION (from_address or to_address equals wallet.address)
SCORE_TRANSACTION_ADDRESS_MATCH: float = 0.95

# Rule 5: TRANSACTION → VASP
# Score is taken directly from VASPAttributionResult.score (already bounded).
# No separate constant — use the live attribution score.

# ── Confidence type labels ────────────────────────────────────────────────────

CONFIDENCE_TYPE_DIRECT_OBSERVATION = "DIRECT_OBSERVATION"
CONFIDENCE_TYPE_EXPLICIT_MAPPING    = "EXPLICIT_MAPPING"
CONFIDENCE_TYPE_ATTRIBUTION         = "ATTRIBUTION"
CONFIDENCE_TYPE_INFERRED            = "INFERRED"


# ── Scoring utility ───────────────────────────────────────────────────────────

def weakest_link(confidences: List[float]) -> float:
    """
    Compute cross-domain confidence as the minimum of all link confidences.

    Returns 0.0 for an empty list.  All input values are clamped to [0.0, 1.0]
    before the minimum is taken.
    """
    if not confidences:
        return 0.0
    clamped = [max(0.0, min(1.0, c)) for c in confidences]
    return round(min(clamped), 4)

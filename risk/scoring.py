"""
JOCKY Investigation Risk — Scoring Configuration & Thresholds
=============================================================
Centralizes all numerical scoring constants, severity bands, and capping rules.
"""

from __future__ import annotations

from risk.models import RiskSeverity

# Maximum possible risk score
MAX_RISK_SCORE = 100

# Explicit, deterministic severity bands
SEVERITY_THRESHOLDS = {
    RiskSeverity.LOW: (0, 24),
    RiskSeverity.MEDIUM: (25, 49),
    RiskSeverity.HIGH: (50, 74),
    RiskSeverity.CRITICAL: (75, 100),
}

# Rule score contributions
SCORE_ENDPOINT_NETWORK = 15
SCORE_EXTERNAL_NETWORK = 10
SCORE_NETWORK_BLOCKCHAIN = 20
SCORE_TRANSACTION_CHAIN = 15
SCORE_VASP_ATTRIBUTION = 15
SCORE_CROSS_DOMAIN = 20


def calculate_severity(score: int) -> RiskSeverity:
    """
    Map an integer risk score to a RiskSeverity band:
      0–24   -> LOW
      25–49  -> MEDIUM
      50–74  -> HIGH
      75–100 -> CRITICAL
    """
    clamped = max(0, min(MAX_RISK_SCORE, score))
    if clamped <= 24:
        return RiskSeverity.LOW
    elif clamped <= 49:
        return RiskSeverity.MEDIUM
    elif clamped <= 74:
        return RiskSeverity.HIGH
    else:
        return RiskSeverity.CRITICAL

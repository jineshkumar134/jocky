"""
JOCKY Correlation Engine — Public API
"""

from correlation.engine import CorrelationEngine
from correlation.models import (
    CorrelationFinding,
    CorrelationResult,
    CorrelationType,
    generate_correlation_id,
)
from correlation.scoring import (
    CONFIDENCE_TYPE_ATTRIBUTION,
    CONFIDENCE_TYPE_DIRECT_OBSERVATION,
    CONFIDENCE_TYPE_EXPLICIT_MAPPING,
    CONFIDENCE_TYPE_INFERRED,
    SCORE_DIRECT_PID_MATCH,
    SCORE_EXPLICIT_DNS_MATCH,
    SCORE_EXPLICIT_FIXTURE_NETWORK_BLOCKCHAIN,
    SCORE_TRANSACTION_ADDRESS_MATCH,
    weakest_link,
)
from correlation.rules import (
    CrossDomainChainRule,
    NetworkBlockchainMappingRule,
    NetworkDnsRecordRule,
    ProcessNetworkPidRule,
    TransactionVaspRule,
    WalletTransactionRule,
)

__all__ = [
    "CorrelationEngine",
    "CorrelationFinding",
    "CorrelationResult",
    "CorrelationType",
    "generate_correlation_id",
    "SCORE_DIRECT_PID_MATCH",
    "SCORE_EXPLICIT_DNS_MATCH",
    "SCORE_EXPLICIT_FIXTURE_NETWORK_BLOCKCHAIN",
    "SCORE_TRANSACTION_ADDRESS_MATCH",
    "CONFIDENCE_TYPE_DIRECT_OBSERVATION",
    "CONFIDENCE_TYPE_EXPLICIT_MAPPING",
    "CONFIDENCE_TYPE_ATTRIBUTION",
    "CONFIDENCE_TYPE_INFERRED",
    "weakest_link",
    "ProcessNetworkPidRule",
    "NetworkDnsRecordRule",
    "NetworkBlockchainMappingRule",
    "WalletTransactionRule",
    "TransactionVaspRule",
    "CrossDomainChainRule",
]

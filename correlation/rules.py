"""
JOCKY Correlation Engine — Deterministic Rule System
======================================================
Six evidence-grounded correlation rules.

Each rule:
- Has a unique rule_id and description
- Operates on a list of UniversalEvidence items
- Produces zero or more CorrelationFinding instances
- Never fabricates relationships
- Documents the confidence_type of each finding

Rules
-----
1. PROCESS_NETWORK_PID_MATCH
   PROCESS.pid == NETWORK_CONNECTION.pid → CONNECTS_TO (conf 0.95)

2. NETWORK_DNS_RECORD_MATCH
   NETWORK_CONNECTION.remote_address in DNS_RECORD.addresses → RESOLVES_TO (conf 0.90)

3. NETWORK_BLOCKCHAIN_EXPLICIT_MAPPING
   NETWORK_CONNECTION.remote_address in curated fixture mapping → ASSOCIATED_WITH (conf 0.65)
   Explanation always states: does not establish wallet ownership.

4. WALLET_TRANSACTION_ADDRESS_MATCH
   TRANSACTION.from/to_address == WALLET.address → SENT_TO (conf 0.95)

5. TRANSACTION_VASP_ATTRIBUTION
   TRANSACTION.to_address in VASP.matched_wallets → ATTRIBUTED_TO (vasp.confidence)

6. CROSS_DOMAIN_CHAIN
   Chains rules 1–5 into an overall cross-domain finding (weakest-link confidence).
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from forensic.evidence.models import EvidenceType, UniversalEvidence

from correlation.models import (
    CorrelationFinding,
    CorrelationType,
    generate_correlation_id,
)
from correlation.scoring import (
    CONFIDENCE_TYPE_ATTRIBUTION,
    CONFIDENCE_TYPE_DIRECT_OBSERVATION,
    CONFIDENCE_TYPE_EXPLICIT_MAPPING,
    SCORE_DIRECT_PID_MATCH,
    SCORE_EXPLICIT_DNS_MATCH,
    SCORE_EXPLICIT_FIXTURE_NETWORK_BLOCKCHAIN,
    SCORE_TRANSACTION_ADDRESS_MATCH,
    weakest_link,
)

_NOW = lambda: datetime.now(timezone.utc).isoformat()  # noqa: E731

# Path to the network→blockchain fixture mapping
_NETWORK_BC_MAPPING_PATH = (
    Path(__file__).resolve().parent.parent
    / "blockchain" / "fixtures" / "network_blockchain_mapping.json"
)


def _load_network_blockchain_mapping() -> Dict[str, Any]:
    """Load the curated IP→wallet fixture mapping.  Returns {} on any error."""
    try:
        return json.loads(_NETWORK_BC_MAPPING_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}


# ──────────────────────────────────────────────────────────
# Base
# ──────────────────────────────────────────────────────────

class CorrelationRule(ABC):
    """Abstract base for all JOCKY correlation rules."""

    rule_id: str
    name: str
    description: str

    @abstractmethod
    def correlate(self, evidence_items: List[UniversalEvidence]) -> List[CorrelationFinding]:
        """Apply rule to evidence items; return zero or more findings."""


# ──────────────────────────────────────────────────────────
# Rule 1 — PROCESS → NETWORK_CONNECTION (PID match)
# ──────────────────────────────────────────────────────────

class ProcessNetworkPidRule(CorrelationRule):
    """
    When PROCESS.pid == NETWORK_CONNECTION.pid (and pid > 0),
    create a PROCESS → CONNECTS_TO → NETWORK_CONNECTION finding.

    Confidence: 0.95 (DIRECT_OBSERVATION — both records carry the same PID)
    """
    rule_id    = "PROCESS_NETWORK_PID_MATCH"
    name       = "Process ↔ Network PID Match"
    description = (
        "Correlates a process evidence record with a network connection evidence "
        "record when both carry the same non-zero PID."
    )

    def correlate(self, evidence_items: List[UniversalEvidence]) -> List[CorrelationFinding]:
        findings: List[CorrelationFinding] = []

        processes = [e for e in evidence_items if e.type == EvidenceType.PROCESS]
        connections = [e for e in evidence_items if e.type == EvidenceType.NETWORK_CONNECTION]

        for proc_ev in processes:
            proc_entity = proc_ev.entity
            proc_pid = getattr(proc_entity, "pid", None)
            if not proc_pid or proc_pid == 0:
                continue

            for conn_ev in connections:
                conn_entity = conn_ev.entity
                conn_pid = getattr(conn_entity, "pid", None)
                if not conn_pid or conn_pid != proc_pid:
                    continue

                proc_name = getattr(proc_entity, "name", "unknown")
                remote_addr = getattr(conn_entity, "remote_address", "unknown")
                remote_port = getattr(conn_entity, "remote_port", None)
                remote_str = f"{remote_addr}:{remote_port}" if remote_port else remote_addr

                explanation = (
                    f"Process {proc_name!r} (PID {proc_pid}) and network connection "
                    f"to {remote_str} share PID {proc_pid}.  "
                    f"This is a direct PID observation — both evidence records "
                    f"identify the same process ID."
                )

                corr_id = generate_correlation_id(
                    CorrelationType.PROCESS_NETWORK.value,
                    {
                        "proc_evidence_id": proc_ev.id,
                        "conn_evidence_id": conn_ev.id,
                        "pid": proc_pid,
                    },
                )

                findings.append(
                    CorrelationFinding(
                        id=corr_id,
                        correlation_type=CorrelationType.PROCESS_NETWORK,
                        source_evidence_ids=[proc_ev.id],
                        target_evidence_ids=[conn_ev.id],
                        relationship_type="CONNECTS_TO",
                        confidence=SCORE_DIRECT_PID_MATCH,
                        score=SCORE_DIRECT_PID_MATCH,
                        explanation=explanation,
                        rule_id=self.rule_id,
                        timestamp=_NOW(),
                        metadata={
                            "pid": proc_pid,
                            "process_name": proc_name,
                            "remote": remote_str,
                            "confidence_type": CONFIDENCE_TYPE_DIRECT_OBSERVATION,
                        },
                    )
                )
        return findings


# ──────────────────────────────────────────────────────────
# Rule 2 — NETWORK_CONNECTION → DNS_RECORD (IP in addresses)
# ──────────────────────────────────────────────────────────

class NetworkDnsRecordRule(CorrelationRule):
    """
    When NETWORK_CONNECTION.remote_address is found in DNS_RECORD.addresses,
    create NETWORK_CONNECTION → RESOLVES_TO → DNS_RECORD.

    Only fires on explicit fixture data — no live DNS lookups performed.
    Confidence: 0.90 (EXPLICIT_MAPPING — DNS record explicitly lists the IP)
    """
    rule_id    = "NETWORK_DNS_RECORD_MATCH"
    name       = "Network Connection ↔ DNS Record Match"
    description = (
        "Correlates a network connection with a DNS record when the connection's "
        "remote IP address appears in the DNS record's resolved addresses."
    )

    def correlate(self, evidence_items: List[UniversalEvidence]) -> List[CorrelationFinding]:
        findings: List[CorrelationFinding] = []

        connections = [e for e in evidence_items if e.type == EvidenceType.NETWORK_CONNECTION]
        dns_records  = [e for e in evidence_items if e.type == EvidenceType.DNS_RECORD]

        for conn_ev in connections:
            remote_addr: Optional[str] = getattr(conn_ev.entity, "remote_address", None)
            if not remote_addr:
                continue

            for dns_ev in dns_records:
                dns_addrs: List[str] = getattr(dns_ev.entity, "addresses", [])
                if remote_addr not in dns_addrs:
                    continue

                domain = getattr(dns_ev.entity, "domain", "unknown")
                explanation = (
                    f"Network connection to {remote_addr} is correlated with DNS "
                    f"record for {domain!r}, which resolves to {remote_addr}.  "
                    f"The IP address appears explicitly in the DNS record's address list."
                )

                corr_id = generate_correlation_id(
                    CorrelationType.NETWORK_BLOCKCHAIN.value + "_DNS",
                    {
                        "conn_evidence_id": conn_ev.id,
                        "dns_evidence_id": dns_ev.id,
                        "remote_addr": remote_addr,
                    },
                )

                findings.append(
                    CorrelationFinding(
                        id=corr_id,
                        correlation_type=CorrelationType.PROCESS_NETWORK,
                        source_evidence_ids=[conn_ev.id],
                        target_evidence_ids=[dns_ev.id],
                        relationship_type="RESOLVES_TO",
                        confidence=SCORE_EXPLICIT_DNS_MATCH,
                        score=SCORE_EXPLICIT_DNS_MATCH,
                        explanation=explanation,
                        rule_id=self.rule_id,
                        timestamp=_NOW(),
                        metadata={
                            "remote_address": remote_addr,
                            "domain": domain,
                            "confidence_type": CONFIDENCE_TYPE_EXPLICIT_MAPPING,
                        },
                    )
                )
        return findings


# ──────────────────────────────────────────────────────────
# Rule 3 — NETWORK_CONNECTION → WALLET (explicit fixture mapping)
# ──────────────────────────────────────────────────────────

class NetworkBlockchainMappingRule(CorrelationRule):
    """
    When a NETWORK_CONNECTION's remote_address appears in the curated
    network→blockchain fixture mapping AND the corresponding WALLET evidence
    exists in the package, create a NETWORK_CONNECTION → ASSOCIATED_WITH → WALLET.

    IMPORTANT: This does NOT establish wallet ownership.  The mapping is based
    on a curated fixture/public dataset that associates an IP with a blockchain
    endpoint.  The explanation always makes this limitation explicit.

    Confidence: 0.65 (EXPLICIT_MAPPING — fixture-based, not ownership proof)
    """
    rule_id    = "NETWORK_BLOCKCHAIN_EXPLICIT_MAPPING"
    name       = "Network Connection ↔ Blockchain Wallet Fixture Mapping"
    description = (
        "Correlates a network connection with a wallet when the connection's "
        "remote IP appears in the curated blockchain endpoint fixture mapping.  "
        "Does NOT establish wallet ownership."
    )

    def __init__(self) -> None:
        self._mapping = _load_network_blockchain_mapping()

    def correlate(self, evidence_items: List[UniversalEvidence]) -> List[CorrelationFinding]:
        findings: List[CorrelationFinding] = []
        if not self._mapping:
            return findings

        connections = [e for e in evidence_items if e.type == EvidenceType.NETWORK_CONNECTION]
        wallets     = [e for e in evidence_items if e.type == EvidenceType.WALLET]

        # Build a quick address→evidence index for wallets
        wallet_index: Dict[str, UniversalEvidence] = {}
        for w_ev in wallets:
            addr: Optional[str] = getattr(w_ev.entity, "address", None)
            if addr:
                wallet_index[addr.lower()] = w_ev

        for conn_ev in connections:
            remote_addr: Optional[str] = getattr(conn_ev.entity, "remote_address", None)
            if not remote_addr:
                continue

            mapping_entry = self._mapping.get(remote_addr)
            if not mapping_entry:
                continue

            mapped_wallet_addr: str = mapping_entry.get("wallet", "")
            wallet_ev = wallet_index.get(mapped_wallet_addr.lower())
            if not wallet_ev:
                # Wallet evidence not present in this package — skip (no fabrication)
                continue

            confidence    = float(mapping_entry.get("confidence", SCORE_EXPLICIT_FIXTURE_NETWORK_BLOCKCHAIN))
            mapping_note  = mapping_entry.get("note", "")
            mapping_type  = mapping_entry.get("mapping_type", "explicit_fixture")
            wallet_label  = getattr(wallet_ev.entity, "label", mapped_wallet_addr)

            explanation = (
                f"Network endpoint {remote_addr} is associated with wallet "
                f"{mapped_wallet_addr} ({wallet_label}) through an explicit fixture "
                f"mapping (mapping_type={mapping_type!r}).  "
                f"This correlation is based on a curated public/fixture dataset and "
                f"does NOT establish ownership of the wallet by the network operator."
            )
            if mapping_note:
                explanation += f"  Note: {mapping_note}"

            corr_id = generate_correlation_id(
                CorrelationType.NETWORK_BLOCKCHAIN.value,
                {
                    "conn_evidence_id": conn_ev.id,
                    "wallet_evidence_id": wallet_ev.id,
                    "remote_addr": remote_addr,
                },
            )

            findings.append(
                CorrelationFinding(
                    id=corr_id,
                    correlation_type=CorrelationType.NETWORK_BLOCKCHAIN,
                    source_evidence_ids=[conn_ev.id],
                    target_evidence_ids=[wallet_ev.id],
                    relationship_type="ASSOCIATED_WITH",
                    confidence=confidence,
                    score=confidence,
                    explanation=explanation,
                    rule_id=self.rule_id,
                    timestamp=_NOW(),
                    metadata={
                        "remote_address": remote_addr,
                        "wallet_address": mapped_wallet_addr,
                        "mapping_type": mapping_type,
                        "confidence_type": CONFIDENCE_TYPE_EXPLICIT_MAPPING,
                        "ownership_established": False,
                    },
                )
            )
        return findings


# ──────────────────────────────────────────────────────────
# Rule 4 — WALLET → TRANSACTION (address match)
# ──────────────────────────────────────────────────────────

class WalletTransactionRule(CorrelationRule):
    """
    When TRANSACTION.from_address or TRANSACTION.to_address equals WALLET.address,
    create WALLET → SENT_TO → WALLET (via the transaction evidence).

    Supporting evidence: wallet_from, transaction, wallet_to (when present).
    Confidence: 0.95 (DIRECT_OBSERVATION — address equality in blockchain records)
    """
    rule_id    = "WALLET_TRANSACTION_ADDRESS_MATCH"
    name       = "Wallet ↔ Transaction Address Match"
    description = (
        "Correlates wallet evidence with transaction evidence when the wallet "
        "address matches the transaction's from or to address."
    )

    def correlate(self, evidence_items: List[UniversalEvidence]) -> List[CorrelationFinding]:
        findings: List[CorrelationFinding] = []

        wallets      = [e for e in evidence_items if e.type == EvidenceType.WALLET]
        transactions = [e for e in evidence_items if e.type == EvidenceType.TRANSACTION]

        wallet_index: Dict[str, UniversalEvidence] = {}
        for w_ev in wallets:
            addr: Optional[str] = getattr(w_ev.entity, "address", None)
            if addr:
                wallet_index[addr.lower()] = w_ev

        for tx_ev in transactions:
            from_addr: Optional[str] = getattr(tx_ev.entity, "from_address", None)
            to_addr:   Optional[str] = getattr(tx_ev.entity, "to_address", None)
            tx_hash:   str = getattr(tx_ev.entity, "tx_hash", "unknown")
            amount:    float = getattr(tx_ev.entity, "amount", 0.0)
            asset:     str = getattr(tx_ev.entity, "asset", "ETH")
            chain:     str = getattr(tx_ev.entity, "chain", "ethereum")
            timestamp: str = getattr(tx_ev.entity, "timestamp", "")

            from_wallet_ev = wallet_index.get(from_addr.lower()) if from_addr else None
            to_wallet_ev   = wallet_index.get(to_addr.lower()) if to_addr else None

            if not (from_wallet_ev and to_wallet_ev):
                # Still emit partial correlation if at least one side is known
                if from_wallet_ev:
                    corr_id = generate_correlation_id(
                        CorrelationType.WALLET_TRANSACTION.value,
                        {"wallet_ev": from_wallet_ev.id, "tx_ev": tx_ev.id, "role": "sender"},
                    )
                    findings.append(CorrelationFinding(
                        id=corr_id,
                        correlation_type=CorrelationType.WALLET_TRANSACTION,
                        source_evidence_ids=[from_wallet_ev.id],
                        target_evidence_ids=[tx_ev.id],
                        relationship_type="SENT_TO",
                        confidence=SCORE_TRANSACTION_ADDRESS_MATCH,
                        score=SCORE_TRANSACTION_ADDRESS_MATCH,
                        explanation=(
                            f"Wallet {from_addr} sent {amount} {asset} via transaction "
                            f"{tx_hash} on {chain}.  The from_address in the transaction "
                            f"record matches this wallet's address exactly."
                        ),
                        rule_id=self.rule_id,
                        timestamp=_NOW(),
                        metadata={
                            "tx_hash": tx_hash, "chain": chain,
                            "amount": amount, "asset": asset,
                            "from_address": from_addr, "to_address": to_addr,
                            "role": "sender",
                            "confidence_type": CONFIDENCE_TYPE_DIRECT_OBSERVATION,
                        },
                    ))
                if to_wallet_ev:
                    corr_id = generate_correlation_id(
                        CorrelationType.WALLET_TRANSACTION.value,
                        {"wallet_ev": to_wallet_ev.id, "tx_ev": tx_ev.id, "role": "recipient"},
                    )
                    findings.append(CorrelationFinding(
                        id=corr_id,
                        correlation_type=CorrelationType.WALLET_TRANSACTION,
                        source_evidence_ids=[tx_ev.id],
                        target_evidence_ids=[to_wallet_ev.id],
                        relationship_type="SENT_TO",
                        confidence=SCORE_TRANSACTION_ADDRESS_MATCH,
                        score=SCORE_TRANSACTION_ADDRESS_MATCH,
                        explanation=(
                            f"Transaction {tx_hash} delivers {amount} {asset} to wallet "
                            f"{to_addr} on {chain}.  The to_address in the transaction "
                            f"record matches this wallet's address exactly."
                        ),
                        rule_id=self.rule_id,
                        timestamp=_NOW(),
                        metadata={
                            "tx_hash": tx_hash, "chain": chain,
                            "amount": amount, "asset": asset,
                            "from_address": from_addr, "to_address": to_addr,
                            "role": "recipient",
                            "confidence_type": CONFIDENCE_TYPE_DIRECT_OBSERVATION,
                        },
                    ))
                continue

            # Both sides known — emit combined WALLET→TX→WALLET correlation
            corr_id = generate_correlation_id(
                CorrelationType.WALLET_TRANSACTION.value,
                {
                    "from_wallet_ev": from_wallet_ev.id,
                    "tx_ev": tx_ev.id,
                    "to_wallet_ev": to_wallet_ev.id,
                },
            )
            explanation = (
                f"Wallet {from_addr} sent {amount} {asset} to wallet {to_addr} "
                f"via transaction {tx_hash} (chain: {chain}, timestamp: {timestamp}).  "
                f"Both from_address and to_address match known wallet evidence records."
            )
            findings.append(
                CorrelationFinding(
                    id=corr_id,
                    correlation_type=CorrelationType.WALLET_TRANSACTION,
                    source_evidence_ids=[from_wallet_ev.id, tx_ev.id],
                    target_evidence_ids=[to_wallet_ev.id],
                    relationship_type="SENT_TO",
                    confidence=SCORE_TRANSACTION_ADDRESS_MATCH,
                    score=SCORE_TRANSACTION_ADDRESS_MATCH,
                    explanation=explanation,
                    rule_id=self.rule_id,
                    timestamp=_NOW(),
                    metadata={
                        "tx_hash": tx_hash, "chain": chain,
                        "amount": amount, "asset": asset,
                        "from_address": from_addr, "to_address": to_addr,
                        "confidence_type": CONFIDENCE_TYPE_DIRECT_OBSERVATION,
                    },
                )
            )
        return findings


# ──────────────────────────────────────────────────────────
# Rule 5 — TRANSACTION → VASP (attribution)
# ──────────────────────────────────────────────────────────

class TransactionVaspRule(CorrelationRule):
    """
    When a TRANSACTION's to_address is in a VASP's matched_wallets list,
    create TRANSACTION → ATTRIBUTED_TO → VASP.

    Confidence: taken from the VASP evidence record's confidence field.
    Explanation always uses hedged language: "associated with", not "owned by".
    """
    rule_id    = "TRANSACTION_VASP_ATTRIBUTION"
    name       = "Transaction → VASP Attribution"
    description = (
        "Correlates a transaction with a VASP when the transaction destination "
        "wallet is in the VASP's curated matched_wallets list.  "
        "Attribution does not prove ownership."
    )

    def correlate(self, evidence_items: List[UniversalEvidence]) -> List[CorrelationFinding]:
        findings: List[CorrelationFinding] = []

        transactions = [e for e in evidence_items if e.type == EvidenceType.TRANSACTION]
        vasps        = [e for e in evidence_items if e.type == EvidenceType.VASP]

        for tx_ev in transactions:
            to_addr: Optional[str] = getattr(tx_ev.entity, "to_address", None)
            if not to_addr:
                continue
            tx_hash  = getattr(tx_ev.entity, "tx_hash", "unknown")
            amount   = getattr(tx_ev.entity, "amount", 0.0)
            asset    = getattr(tx_ev.entity, "asset", "ETH")

            for vasp_ev in vasps:
                matched: List[str] = getattr(vasp_ev.entity, "matched_wallets", [])
                if to_addr.lower() not in [m.lower() for m in matched]:
                    continue

                vasp_name  = getattr(vasp_ev.entity, "name", "unknown VASP")
                vasp_conf  = float(getattr(vasp_ev.entity, "confidence", 0.5))
                vasp_score = float(getattr(vasp_ev.entity, "score", vasp_conf))

                explanation = (
                    f"Transaction {tx_hash} terminates at wallet {to_addr}, which is "
                    f"in the matched_wallets list for {vasp_name!r} (VASP attribution "
                    f"confidence: {vasp_conf:.2f}).  "
                    f"Transaction destination is associated with the VASP based on "
                    f"curated attribution evidence.  This does not prove the VASP "
                    f"owns or controls the sending party."
                )

                corr_id = generate_correlation_id(
                    CorrelationType.TRANSACTION_VASP.value,
                    {
                        "tx_evidence_id": tx_ev.id,
                        "vasp_evidence_id": vasp_ev.id,
                        "to_address": to_addr,
                    },
                )

                findings.append(
                    CorrelationFinding(
                        id=corr_id,
                        correlation_type=CorrelationType.TRANSACTION_VASP,
                        source_evidence_ids=[tx_ev.id],
                        target_evidence_ids=[vasp_ev.id],
                        relationship_type="ATTRIBUTED_TO",
                        confidence=vasp_conf,
                        score=vasp_score,
                        explanation=explanation,
                        rule_id=self.rule_id,
                        timestamp=_NOW(),
                        metadata={
                            "tx_hash": tx_hash,
                            "to_address": to_addr,
                            "amount": amount,
                            "asset": asset,
                            "vasp_name": vasp_name,
                            "confidence_type": CONFIDENCE_TYPE_ATTRIBUTION,
                        },
                    )
                )
        return findings


# ──────────────────────────────────────────────────────────
# Rule 6 — Cross-Domain Investigation Chain
# ──────────────────────────────────────────────────────────

class CrossDomainChainRule:
    """
    Assembles a higher-level CROSS_DOMAIN correlation finding when a supported
    chain of individual findings connects at least two different domain types.

    Confidence uses the weakest-link principle: min of all participating link
    confidences.

    IMPORTANT: This finding does NOT assert a direct relationship between the
    first and last node.  It only states that the evidence forms a correlated
    chain.  The explanation uses hedged language accordingly.
    """
    rule_id    = "CROSS_DOMAIN_CHAIN"
    name       = "Cross-Domain Investigation Chain"
    description = (
        "Assembles a multi-domain correlation chain from individual findings "
        "spanning PROCESS → NETWORK → BLOCKCHAIN → VASP.  "
        "Confidence is the minimum of all link confidences (weakest-link)."
    )

    def correlate(
        self,
        evidence_items: List[UniversalEvidence],
        prior_findings: List[CorrelationFinding],
    ) -> List[CorrelationFinding]:
        if not prior_findings:
            return []

        # Only proceed if we have findings from at least 2 distinct domain pairs
        domain_types = {f.correlation_type for f in prior_findings}
        if len(domain_types) < 2:
            return []

        from collections import defaultdict

        # Index findings by evidence IDs
        ev_to_findings: Dict[str, List[CorrelationFinding]] = defaultdict(list)
        for f in prior_findings:
            for eid in (f.source_evidence_ids + f.target_evidence_ids):
                ev_to_findings[eid].append(f)

        # Search for multi-domain chains across connected findings
        discovered_chains: List[List[CorrelationFinding]] = []

        start_candidates = [
            f for f in prior_findings
            if f.correlation_type == CorrelationType.PROCESS_NETWORK
        ] or prior_findings

        def dfs(curr: CorrelationFinding, path: List[CorrelationFinding], visited: Set[str]):
            domains = {f.correlation_type for f in path}
            if len(domains) >= 2:
                discovered_chains.append(list(path))
            if len(path) >= 8:
                return
            for eid in (curr.source_evidence_ids + curr.target_evidence_ids):
                for nxt in ev_to_findings[eid]:
                    if nxt.id not in visited:
                        dfs(nxt, path + [nxt], visited | {nxt.id})

        for sf in start_candidates:
            dfs(sf, [sf], {sf.id})

        # If no multi-hop chain found via DFS, fallback to prior_findings as a single aggregate
        if not discovered_chains:
            discovered_chains = [prior_findings]

        # If TRANSACTION_VASP findings exist, chains should terminate at a VASP
        has_vasp_findings = any(f.correlation_type == CorrelationType.TRANSACTION_VASP for f in prior_findings)
        if has_vasp_findings:
            vasp_chains = [ch for ch in discovered_chains if ch[-1].correlation_type == CorrelationType.TRANSACTION_VASP]
            if vasp_chains:
                discovered_chains = vasp_chains

        # Group chains by terminal destination to avoid conflating different targets
        terminal_groups: Dict[tuple, List[List[CorrelationFinding]]] = defaultdict(list)
        for ch in discovered_chains:
            term = tuple(sorted(ch[-1].target_evidence_ids)) or tuple(sorted(ch[-1].source_evidence_ids))
            terminal_groups[term].append(ch)

        # Pick the best chain for each terminal target (max domains, max weakest-link, min length)
        best_per_terminal: List[List[CorrelationFinding]] = []
        for term, ch_list in terminal_groups.items():
            ch_list.sort(
                key=lambda c: (
                    -len({f.correlation_type for f in c}),
                    -weakest_link([f.confidence for f in c]),
                    len(c),
                    c[0].id,
                )
            )
            best_per_terminal.append(ch_list[0])

        # Filter to maximal domain coverage
        max_domains = max(len({f.correlation_type for f in c}) for c in best_per_terminal)
        maximal_chains = [c for c in best_per_terminal if len({f.correlation_type for f in c}) == max_domains]

        # Sort the terminal chains: highest weakest-link confidence first, then shortest length, then deterministic ID
        maximal_chains.sort(
            key=lambda c: (
                -weakest_link([f.confidence for f in c]),
                len(c),
                c[0].id,
            )
        )

        findings: List[CorrelationFinding] = []
        for idx, chain_findings in enumerate(maximal_chains):
            is_primary = (idx == 0)
            chain_confidences = [f.confidence for f in chain_findings]
            chain_confidence = weakest_link(chain_confidences)

            seen_eids: Set[str] = set()
            unique_ids: List[str] = []
            for f in chain_findings:
                for eid in (f.source_evidence_ids + f.target_evidence_ids):
                    if eid not in seen_eids:
                        seen_eids.add(eid)
                        unique_ids.append(eid)

            domain_types_in_chain = {f.correlation_type for f in chain_findings}
            domain_labels = sorted(dt.value for dt in domain_types_in_chain)
            chain_desc = " → ".join(dt.replace("_", " ↔ ") for dt in domain_labels)
            num_findings = len(chain_findings)
            tier_label = "primary" if is_primary else "secondary"

            explanation = (
                f"Evidence forms a supported {tier_label} multi-domain investigation chain "
                f"spanning: {chain_desc}.  "
                f"The chain is assembled from {num_findings} individual correlation "
                f"finding(s) across {len(domain_types_in_chain)} domain pair(s).  "
                f"Overall chain confidence: {chain_confidence:.2f} (weakest-link of "
                f"individual findings: {[round(c, 2) for c in chain_confidences]}).  "
                f"This finding represents correlated evidence — it does NOT assert "
                f"that the process, network endpoint, wallet, or VASP are the same "
                f"entity or that any party is directly responsible for another's actions."
            )

            corr_id = generate_correlation_id(
                CorrelationType.CROSS_DOMAIN.value,
                {
                    "participating_finding_ids": sorted(f.id for f in chain_findings),
                    "domain_types": domain_labels,
                    "tier": tier_label,
                },
            )

            findings.append(
                CorrelationFinding(
                    id=corr_id,
                    correlation_type=CorrelationType.CROSS_DOMAIN,
                    source_evidence_ids=unique_ids,
                    target_evidence_ids=[],
                    relationship_type="CROSS_DOMAIN_CHAIN",
                    confidence=chain_confidence,
                    score=chain_confidence,
                    explanation=explanation,
                    rule_id=self.rule_id,
                    timestamp=_NOW(),
                    metadata={
                        "num_findings": num_findings,
                        "domain_types": domain_labels,
                        "link_confidences": [round(c, 4) for c in chain_confidences],
                        "weakest_link_confidence": chain_confidence,
                        "confidence_type": "WEAKEST_LINK",
                        "chain_tier": tier_label,
                        "participating_finding_ids": [f.id for f in chain_findings],
                    },
                )
            )

        return findings

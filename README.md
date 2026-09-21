# JOCKY: Cybersecurity + Blockchain Forensic Investigation Framework

**JOCKY** is a domain-specific programming language (DSL) and forensic investigation runtime designed for automated endpoint artifact analysis, network correlation, multi-hop blockchain tracing, and decentralized evidence integrity anchoring.

---

## Current Status: Phase 16 — COMPLETE (Final Integration & Demo Ready)

**All 16 phases implemented and validated. 427 tests passing.**

The JOCKY pipeline spans the full forensic investigation lifecycle:

```
.jky source → Lexer → Parser → AST → JOCKY IR → LLVM IR
    → Runtime Executor → Universal Evidence Model
    → Correlation Engine → Investigation Graph
    → Timeline Builder → Risk Assessment Engine
    → Evidence Anchoring (IPFS + EVM) → Verification
    → Security Research Lab → Central Investigation Management
    → Investigation Dashboard (React/Vite)
```

### Phase Summary

| Phase | Name | Status |
|-------|------|--------|
| 0 | Project Scaffold | ✅ |
| 1 | Lexer | ✅ |
| 2 | Parser + AST | ✅ |
| 3 | IR + Lowering | ✅ |
| 4 | Endpoint Forensics | ✅ |
| 5 | Network Forensics | ✅ |
| 6 | Universal Evidence Model | ✅ |
| 7 | Blockchain Tracing + VASP | ✅ |
| 8 | Correlation Engine | ✅ |
| 9 | Investigation Graph | ✅ |
| 10 | Timeline Builder | ✅ |
| 11 | Evidence Anchoring (IPFS + EVM) | ✅ |
| 12 | Platform Security Pre-Check | ✅ |
| 13 | Central Investigation Management | ✅ |
| 14 | Investigation Dashboard | ✅ |
| 15 | Security Research Lab | ✅ |
| 16 | Final Integration + Demo Readiness | ✅ |

---

## Final Demo (Phase 16)

### Quick Start — One Command

```bash
# Install dependencies
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Run end-to-end demo
python -m jocky.cli examples/final_demo.jky --execute --fixture
```

### Complete Validation

```bash
# Run all 427 tests
PYTHONPATH=. .venv/bin/pytest -q

# Build dashboard
npm --prefix dashboard install
npm --prefix dashboard run build

# JSON output for machine consumption
python -m jocky.cli examples/final_demo.jky --execute --fixture --json | python -m json.tool | head -50
```

### Demo Script: `examples/final_demo.jky`

```jky
CASE "JOCKY-FINAL-2026"
HOST "LAB-PC-01"

CHECK SECURITY

REGISTER HOST "LAB-PC-01"
REGISTER HOST "LAB-PC-02"
REGISTER HOST "LAB-PC-03"

ANALYZE SYSTEM
ANALYZE FILES
ANALYZE PROCESSES
ANALYZE NETWORK

TRACE SUSPICIOUS CONNECTIONS

BLOCKCHAIN TRACE "0xWALLET001"
IDENTIFY VASP

CORRELATE EVIDENCE
BUILD ATTACK GRAPH
BUILD TIMELINE
ATTACH EVIDENCE
ASSESS RISK

ANCHOR EVIDENCE
VERIFY EVIDENCE
GENERATE REPORT

RESEARCH "synthetic_polymorphism"
RESEARCH "synthetic_memory_execution"
RESEARCH "synthetic_driver_risk"
RESEARCH "synthetic_security_controls"
RESEARCH "synthetic_network_behavior"
```

### Hackathon Acceptance Checklist

| # | Criterion | Status |
|---|-----------|--------|
| 1 | Custom DSL with lexer, parser, AST | ✅ |
| 2 | JOCKY IR (discriminated union) | ✅ |
| 3 | LLVM backend via llvmlite | ✅ |
| 4 | Endpoint forensics (files, processes, system) | ✅ |
| 5 | Network forensics (connections, listeners, DNS) | ✅ |
| 6 | Universal Evidence Model with canonical hashing | ✅ |
| 7 | Multi-hop blockchain tracing | ✅ |
| 8 | VASP attribution | ✅ |
| 9 | Correlation Engine (9+ rule types) | ✅ |
| 10 | Investigation Attack Graph | ✅ |
| 11 | Cross-domain paths PROCESS→NETWORK→WALLET→TX→VASP | ✅ |
| 12 | Investigation Timeline Builder | ✅ |
| 13 | Evidence Anchoring (IPFS + EVM blockchain) | ✅ |
| 14 | Deterministic package_hash invariance | ✅ |
| 15 | Platform Security Pre-Check (HVCI, VBS, Secure Boot) | ✅ |
| 16 | Central Investigation Management (multi-host case) | ✅ |
| 17 | case_hash isolated from package_hash | ✅ |
| 18 | graph_hash, timeline_hash, risk_hash isolated | ✅ |
| 19 | Security Research Lab (5 safe scenarios) | ✅ |
| 20 | result_hash isolated from all forensic hashes | ✅ |
| 21 | Investigation Dashboard (React/Vite) | ✅ |
| 22 | REST API (FastAPI) | ✅ |
| 23 | 427 tests, zero failures | ✅ |
| 24 | No offensive capabilities | ✅ |
| 25 | One-command reproducible demo | ✅ |

### Hash Isolation Guarantee

JOCKY maintains 5 independently computed, cryptographically isolated hashes:

```
package_hash   — EvidencePackage canonical hash (never mutated)
case_hash      — Central Investigation Case deterministic hash
graph_hash     — Investigation Graph topology hash
timeline_hash  — Investigation Timeline events hash
risk_hash      — Risk Assessment findings hash
result_hash    — Security Research result hash (per scenario)
```

No two hashes are equal; each reflects its own domain without cross-contamination.

---

### What Forensics Does

#### 1. Endpoint Forensics (Phase 4)
- **`ANALYZE FILES`**: Safe, streaming SHA-256 calculation, size, timestamps, path metadata, and file type classification.
- **`ANALYZE PROCESSES`**: Safe read-only process enumeration using `psutil`. Captures PID, name, PPID, executable path, username, start time, and status.
- **`ANALYZE SYSTEM`**: Cross-platform system and platform metadata collection (OS, kernel, CPU cores, RAM, boot time, Python runtime, hostname).

#### 2. Network Forensics (Phase 5)
- **`ANALYZE NETWORK`**: Safe, read-only network inspection:
  - **Active Connections**: Protocol, local/remote IP and ports, connection state, owning PID, process name, direction, and non-invasive risk indicators (`external_remote_address`, `encrypted_transport_indicator`, `unusual_high_port`, `process_associated`).
  - **Listening Sockets**: Open server ports, interfaces (`0.0.0.0`, `127.0.0.1`), owning process, and risk indicators (`listening_on_all_interfaces`).
  - **DNS Resolution**: Safe resolution of explicitly queried domains via standard OS resolvers without covert channels or bulk scanning.

#### 3. Universal Evidence Model (Phase 6)
- Standardized, strongly typed, and immutable evidence schema unifying Endpoint and Network artifacts.
- Deterministic canonical JSON serialization and cryptographic integrity hashing.
- Stable, reproducible evidence IDs derived from entity data, host, and collector seeds.
- Strictly evidence-grounded relationship extraction (linking processes to active connections, listeners, and DNS queries).
- Collation into an authenticated, verifiable `EvidencePackage`.

---

## Universal Evidence Model

### 1. Why a Universal Model is Needed
Forensic investigations collect disparate data from multiple layers: file system inodes, operating system processes, TCP/UDP sockets, DNS responses, and (in future phases) blockchain transactions and smart contract logs.
Without a unified representation:
- Correlation engines would require $O(N^2)$ cross-type adapters.
- Integrity verification and decentralized anchoring (IPFS/EVM) would lack canonical serialization.
- Chain-of-custody tracking across multi-host investigations would be fragmented.

The Universal Evidence Model provides a common, strongly typed substrate allowing any forensic collector to produce verifiable evidence items consumable by timeline builders, graph engines, and verification protocols.

### 2. Evidence Types
Categorized by the `EvidenceType` enum:
- **Active Types**:
  - `FILE`: File metadata and file content hash.
  - `PROCESS`: Operating system execution snapshot (PID, binary, user).
  - `SYSTEM`: Host hardware and operating system environment.
  - `NETWORK_CONNECTION`: Active TCP/UDP socket with process association.
  - `NETWORK_LISTENER`: Open listening socket / server port.
  - `DNS_RECORD`: Explicitly resolved domain-to-IP lookup.
- **Future-Reserved Types** (Phase 7+):
  - `WALLET`: Cryptocurrency wallet address and network.
  - `TRANSACTION`: On-chain transaction record.
  - `VASP`: Virtual Asset Service Provider attribution.
  - `BLOCKCHAIN_EVENT`: Smart contract event log.

### 3. Entity Model
Entities encapsulate domain-specific metadata without imposing unnatural homogeneity:
- `FileEntity`: path, name, extension, size, sha256, modified_at, created_at, accessed_at, file_type.
- `ProcessEntity`: pid, name, parent_pid, executable, username, start_time, status.
- `SystemEntity`: hostname, os, architecture, kernel, runtime, cpu_count, memory_total_bytes, boot_time.
- `NetworkConnectionEntity`: protocol, local_address, local_port, remote_address, remote_port, status, pid, process_name, timestamp, direction, risk_indicators.
- `NetworkListenerEntity`: protocol, local_address, local_port, pid, process_name, status, risk_indicators.
- `DNSRecordEntity`: domain, addresses, query_time, status.

### 4. Relationship Model
Relationships link entities together using strictly evidence-grounded associations.
Types:
- `CONNECTS_TO`: Grounded when a `PROCESS` and `NETWORK_CONNECTION` share an explicit, non-zero PID.
- `LISTENING_ON`: Grounded when a `PROCESS` and `NETWORK_LISTENER` share an explicit, non-zero PID.
- `RESOLVES_TO`: Grounded when a `DNS_RECORD` contains explicit resolved IP addresses.
- `EXECUTED`, `SPAWNED`, `ACCESSED`: Reserved for process tree and file access tracing.
- `SENT_TO`, `ATTRIBUTED_TO`: Reserved for future blockchain correlation.

### 5. Provenance
Every evidence record maintains an immutable chain-of-custody object (`EvidenceProvenance`):
- `collector`: Name of the collecting component (e.g. `FixtureEndpointAdapter`, `LocalNetworkAdapter`).
- `adapter`: Subsystem classification (`endpoint` or `network`).
- `source`: Host origin tag (e.g. `host:LAB-PC-01`).
- `collection_method`: Technique used (e.g. `psutil.net_connections`, `socket.getaddrinfo`, `os.scandir`).
- `collected_at`: ISO 8601 UTC timestamp of acquisition.
- `host`: Hostname where collection took place.
- `case_id`: Investigation case identifier.

### 6. Confidence
Confidence reflects observation certainty:
- Normalized float strictly validated between `0.0` and `1.0`.
- `1.0`: Directly observed fact (e.g. active kernel socket table, hash of local file on disk).
- `< 1.0`: Inferred or attributed metadata (validated by Pydantic bounds enforcement).

### 7. Integrity Hashing & Deterministic IDs
- **Deterministic Canonical Serialization**: Standardized JSON format (recursively sorted keys, compact delimiters `(',' , ':')`, ensure_ascii=False, consistent float/datetime formatting).
- **Evidence Item Integrity Hash**: SHA-256 computed over the canonical serialization of the evidence record *excluding* the mutable integrity field. Verified via `.verify_integrity()`.
- **Evidence IDs**: Deterministic and reproducible across executions on the same fixture data:
  $$\text{seed} = \text{type} \parallel \text{canonical\_json}(\text{entity}) \parallel (\text{host} : \text{collector})$$
  $$\text{id} = \text{EVID-}\{\text{TYPE}\}\text{-}\{\text{SHA256}(\text{seed})[:12]\}$$

### 8. EvidencePackage
An aggregate object collating all collected evidence items and grounded relationships for an entire investigation case:
- Contains `case_id`, `host`, `created_at`, `evidence[]`, `relationships[]`, `metadata`, and `package_hash`.
- `package_hash`: SHA-256 over canonical JSON of the package contents excluding `package_hash`.
- Ready for future IPFS DAG generation and EVM smart contract anchoring.

### 9. Endpoint Conversion
`FileArtifact`, `ProcessArtifact`, and `SystemArtifact` convert to `UniversalEvidence` with `source="endpoint"`, extracting SHA-256 digests, PIDs, and system platform values into `FileEntity`, `ProcessEntity`, and `SystemEntity`.

### 10. Network Conversion
`NetworkConnection`, `NetworkListener`, and `DNSRecord` convert to `UniversalEvidence` with `source="network"`, preserving risk indicator tags, socket endpoints, and resolved address lists.

---

### Example Universal Evidence Package (JSON Output)

Below is an authentic snippet generated via `python -m jocky.cli examples/hello.jky --execute --fixture --json`:

```json
{
  "case_id": "INC-2026-001",
  "host": "LAB-PC-01",
  "evidence_package": {
    "case_id": "INC-2026-001",
    "host": "LAB-PC-01",
    "created_at": "2026-09-14T00:05:52Z",
    "evidence": [
      {
        "id": "EVID-PROC-a1dd51837709",
        "type": "PROCESS",
        "source": "endpoint",
        "timestamp": "2026-09-12T10:00:00Z",
        "confidence": 1.0,
        "entity": {
          "type": "PROCESS",
          "pid": 4821,
          "name": "suspicious_miner",
          "parent_pid": 1102,
          "executable": "/usr/local/bin/suspicious_miner",
          "username": "labuser",
          "start_time": "2026-09-12T10:00:00Z",
          "status": "running",
          "error": null
        },
        "relationships": [],
        "provenance": {
          "collector": "EndpointAdapter:ANALYZE_PROCESSES",
          "adapter": "endpoint",
          "source": "host:LAB-PC-01",
          "collection_method": "psutil.process_iter",
          "collected_at": "2026-09-12T10:00:00Z",
          "host": "LAB-PC-01",
          "case_id": "INC-2026-001"
        },
        "integrity": {
          "algorithm": "SHA-256",
          "value": "249d3aece0fc76882c502b4bc66860010996b5ea1385f39e31d77a808064d50b"
        }
      },
      {
        "id": "EVID-NETC-2f6c94f692a6",
        "type": "NETWORK_CONNECTION",
        "source": "network",
        "timestamp": "2026-09-12T15:10:00Z",
        "confidence": 1.0,
        "entity": {
          "type": "NETWORK_CONNECTION",
          "protocol": "TCP",
          "local_address": "192.168.1.50",
          "local_port": 51234,
          "remote_address": "203.0.113.25",
          "remote_port": 443,
          "status": "ESTABLISHED",
          "pid": 4821,
          "process_name": "suspicious_miner",
          "timestamp": "2026-09-12T15:10:00Z",
          "direction": "outbound",
          "risk_indicators": [
            "external_remote_address",
            "encrypted_transport_indicator",
            "process_associated"
          ]
        },
        "relationships": [],
        "provenance": {
          "collector": "NetworkAdapter:ANALYZE_NETWORK",
          "adapter": "network",
          "source": "host:LAB-PC-01",
          "collection_method": "psutil.net_connections",
          "collected_at": "2026-09-12T15:10:00Z",
          "host": "LAB-PC-01",
          "case_id": "INC-2026-001"
        },
        "integrity": {
          "algorithm": "SHA-256",
          "value": "e0ca2b07e8efd8487770f1a56658d519b7a421b44aa4e2f928e18dbec44869ae"
        }
      }
    ],
    "relationships": [
      {
        "id": "REL-CONN-56508536c0",
        "type": "CONNECTS_TO",
        "source_id": "EVID-PROC-a1dd51837709",
        "target_id": "EVID-NETC-2f6c94f692a6",
        "timestamp": null,
        "confidence": 1.0,
        "supporting_evidence": [
          "EVID-PROC-a1dd51837709",
          "EVID-NETC-2f6c94f692a6"
        ],
        "metadata": {
          "pid": 4821,
          "process_name": "suspicious_miner",
          "remote": "203.0.113.25:443"
        }
      }
    ],
    "metadata": {},
    "package_hash": "9642a8b22235e5a64d772b3a05cf34433326faeee4a4f20f14fc38247d28e09f"
  }
}
```

---

## Phase 7: Blockchain Forensics & VASP Intelligence

### 1. Architecture
- **`BLOCKCHAIN TRACE <wallet>`**: Multi-hop Breadth-First Search (BFS) graph traversal through transaction logs. Discovers intermediate nodes, transaction hops, and terminal recipient wallets.
- **`IDENTIFY VASP`**: Explainable attribution engine resolving wallets to Virtual Asset Service Providers (exchanges, custodial services) with strictly bounded additive scoring.

### 2. Additive VASP Scoring Model
$$\text{Score} = \text{direct\_label\_match}\,(0.45) + \text{wallet\_type\_match}\,(0.30) + \text{address\_cluster\_match}\,(0.20) + \text{base\_confidence}\,(0.05)$$
$$\text{Max Score} = 1.00 \quad (0.0 \le \text{confidence} \le 1.0)$$

---

## Phase 8: JOCKY Correlation Engine

### 1. Overview & Architecture
The Correlation Engine transforms fragmented evidence records across Endpoint, Network, Blockchain, and VASP domains into a coherent, evidence-grounded cross-domain investigation.

$$\text{EvidencePackage} \longrightarrow \text{CorrelationEngine} \longrightarrow \text{Deterministic Rules} \longrightarrow \text{Findings} \longrightarrow \text{Weakest-Link Scoring} \longrightarrow \text{CorrelationResult}$$

### 2. Conceptual Investigation Chain
```
PROCESS (PID 4821, suspicious_miner)
   ↓ CONNECTS_TO  [Rule 1: DIRECT_PID_MATCH, Conf: 0.95]
NETWORK_CONNECTION (203.0.113.25:443)
   ↓ ASSOCIATED_WITH  [Rule 3: EXPLICIT_FIXTURE_MAPPING, Conf: 0.65]
WALLET (0xWALLET001, Synthetic Suspicious EOA)
   ↓ SENT_TO  [Rule 4: TRANSACTION_ADDRESS_MATCH, Conf: 0.95]
TRANSACTION (0xTX001 → 0xWALLET002 → 0xTX002 → 0xWALLET003)
   ↓ ATTRIBUTED_TO  [Rule 5: TRANSACTION_VASP_ATTRIBUTION, Conf: 1.00]
VASP (Example Exchange)
```

> [!IMPORTANT]
> **Correlated Evidence vs. Proof of Ownership:**
> The cross-domain chain demonstrates evidential correlation across observed artifacts. It does **NOT** claim or imply that the process operator owns the blockchain wallet, nor does it establish legal guilt. Network-to-blockchain associations reflect observed endpoints and public mapping records, not cryptographic proof of custody.

### 3. Correlation Rules
| Rule ID | Domain Pair | Relationship | Confidence | Confidence Type | Match Condition |
|---|---|---|---|---|---|
| `PROCESS_NETWORK_PID_MATCH` | Process ↔ Network | `CONNECTS_TO` | 0.95 | `DIRECT_OBSERVATION` | `PROCESS.pid == NETWORK_CONNECTION.pid` (non-zero) |
| `NETWORK_DNS_RECORD_MATCH` | Network ↔ DNS | `RESOLVES_TO` | 0.90 | `EXPLICIT_MAPPING` | `NETWORK_CONNECTION.remote_address in DNS.addresses` |
| `NETWORK_BLOCKCHAIN_EXPLICIT_MAPPING` | Network ↔ Wallet | `ASSOCIATED_WITH` | 0.65 | `EXPLICIT_MAPPING` | Remote IP in curated fixture/public endpoint dataset |
| `WALLET_TRANSACTION_ADDRESS_MATCH` | Wallet ↔ Transaction | `SENT_TO` | 0.95 | `DIRECT_OBSERVATION` | `TX.from_address == WALLET.address` or `TX.to_address == WALLET.address` |
| `TRANSACTION_VASP_ATTRIBUTION` | Transaction ↔ VASP | `ATTRIBUTED_TO` | VASP Conf | `ATTRIBUTION` | `TX.to_address in VASP.matched_wallets` |
| `CROSS_DOMAIN_CHAIN` | Cross-Domain Multi-hop | `CROSS_DOMAIN_CHAIN` | Min(Links) | `WEAKEST_LINK` | Supported multi-hop chain across $\ge 2$ domain pairs |

### 4. Weakest-Link Confidence Scoring
For multi-domain chains, overall confidence is defined as the minimum confidence among all participating links:
$$\text{Confidence}_{\text{chain}} = \min_{i \in \text{findings}} (\text{confidence}_i)$$
*Why weakest-link?* An investigation chain is only as strong as its least certain link. Averaging would mask weak evidence and create a false sense of certainty.

### 5. Deterministic Correlation IDs
Correlation IDs are derived deterministically using canonical JSON hashing:
$$\text{id} = \text{CORR-}\{\text{TAG}\}\text{-}\{\text{SHA256}(\text{canonical\_json}(\text{inputs}))[:12]\}$$
Identical evidence packages and rules produce identical correlation IDs, confidence scores, and explanations across repeated runs.

---

## Phase 9: JOCKY Investigation Graph Engine

### 1. Overview & Architecture
The Investigation Graph Engine models the entire evidence package and correlation findings as an interconnected, queryable in-memory directed graph.

$$\text{EvidencePackage} + \text{CorrelationResult} \longrightarrow \text{GraphBuilder} \longrightarrow \text{InvestigationGraph} \longrightarrow \text{Graph Queries} \longrightarrow \text{Path Discovery}$$

* **Phase 8** = Correlation intelligence (discovering why evidence is related).
* **Phase 9** = Graph representation and traversal (modeling the complete topology and discovering paths).
* **Phase 14** = Visual frontend dashboard.

### 2. Graph Node Model
Each `GraphNode` references an existing `UniversalEvidence` item:
- `id`: Exact `UniversalEvidence.id` (no duplicate or synthetic IDs).
- `node_type`: `FILE`, `PROCESS`, `SYSTEM`, `NETWORK_CONNECTION`, `NETWORK_LISTENER`, `DNS_RECORD`, `WALLET`, `TRANSACTION`, `VASP`, `BLOCKCHAIN_EVENT`.
- *Note:* `host` is stored as graph-level metadata, not as a synthetic node.
- `label`: Concise, human-readable identifier (e.g. `suspicious_miner`, `203.0.113.25:443`, `Example Exchange`).
- `confidence`: Bounded float in $[0.0, 1.0]$.

### 3. Graph Edge Model & Deduplication
- **From Grounded Relationships (Phase 6/7)**: Direct relationships (`CONNECTS_TO`, `RESOLVES_TO`, `SENT_TO`, `ATTRIBUTED_TO`) become directed graph edges.
- **From Correlation Findings (Phase 8)**: Single-hop correlations are either merged into existing edges (preserving strongest confidence and appending correlation metadata) or added as new edges (e.g. `NETWORK_CONNECTION -> WALLET`).
- **No Fabricated Cross-Domain Edge**: `CROSS_DOMAIN` correlation findings are stored as graph metadata (`cross_domain_findings`), preserving the true intermediate topology (`PROCESS -> NETWORK -> WALLET -> TX -> VASP`) without inventing direct `PROCESS -> VASP` edges.

### 4. Deterministic Graph Hashing
Graph integrity is verified using a canonical SHA-256 digest over sorted nodes, sorted edges, case_id, host, and metadata (omitting volatile generation timestamps):
$$\text{graph\_hash} = \text{SHA256}(\text{canonical\_json}(\{\text{case\_id}, \text{host}, \text{nodes}, \text{edges}, \text{metadata}\}))$$

### 5. Deterministic Path Queries & Weakest-Link Path Confidence
- `find_path(graph, src, tgt)`: Deterministic BFS traversal using sorted candidate edge ordering.
- `get_cross_domain_paths(graph)`: Discovers end-to-end paths from `PROCESS` nodes to `VASP` nodes.
- **Path Confidence Formula (Weakest-Link)**:
  $$\text{Confidence}_{\text{path}} = \min_{e \in \text{path\_edges}} (\text{confidence}_e)$$
  *Example:* A path with edge confidences $[0.95, 0.65, 0.95, 0.95, 1.00]$ yields an exact path confidence of $0.65$.

---

## Phase 10: JOCKY Investigation Timeline & Risk Engine

### 1. Overview & Architecture
Phase 10 adds two distinct, independent derived analytical views over the unified evidence package and correlation engine:
1. **Investigation Timeline (`timeline/`)**: Chronological reconstruction of verified investigation events across endpoint, network, blockchain, and VASP domains.
2. **Deterministic Risk Engine (`risk/`)**: Rule-based, explainable risk scoring with bounded additive accumulation and explicit severity bands.

$$\begin{aligned}
\text{EvidencePackage} + \text{CorrelationResult} &\longrightarrow \text{TimelineBuilder} \longrightarrow \text{InvestigationTimeline} (\text{timeline\_hash}) \\
&\longrightarrow \text{RiskEngine} \longrightarrow \text{RiskAssessment} (\text{risk\_hash})
\end{aligned}$$

* **Derived View Invariance**: Neither timeline nor risk assessment modifies the underlying evidence package or its canonical `package_hash`.
* **No Unnecessary External Dependencies**: Implemented natively in Python with zero external graph/risk database dependencies or unexplainable black-box ML models.

### 2. Investigation Timeline Engine
- **Event Categorization**: Events are categorized deterministically into `ENDPOINT_EVENT`, `NETWORK_EVENT`, `BLOCKCHAIN_EVENT`, `VASP_EVENT`, or `CORRELATION_EVENT`.
- **Event vs. Collection Timestamps**: Only authentic event timestamps present in evidence entities or provenance are used. If an event timestamp is unavailable, it is preserved as `None` (never fabricated from collection time).
- **Deterministic Event Ordering**:
  1. Timed events are ordered strictly chronologically (`timestamp ASC`).
  2. Untimed events are ordered deterministically after timed events using `(event_type, id)`.
- **Deterministic Event IDs**: Generated via canonical SHA-256 digests:
  $$\text{id} = \text{EVT-}\{\text{TAG}\}\text{-}\{\text{SHA256}(\text{canonical\_json}(\text{inputs}))[:12]\}$$
- **Timeline Hash**: SHA-256 digest over canonical JSON of `case_id`, `host`, ordered events, and metadata (excluding volatile generation timestamps).
- **Deterministic Range & Query Helpers**:
  - `get_events_by_type(timeline, event_type)`
  - `get_events_in_range(timeline, start_time, end_time)`
  - `get_events_for_evidence(timeline, evidence_id)`
  - `get_events_for_correlation(timeline, correlation_id)`
  - `get_timed_events(timeline)`, `get_untimed_events(timeline)`

### 3. Explainable Deterministic Risk Engine
- **Scoring Model**: Additive deterministic score accumulating rule weights up to a capped maximum of 100:
  $$\text{total\_score} = \min\left(100, \sum_{f \in \text{findings}} \text{score}(f)\right)$$
- **Deterministic Rules & Weights**:
  1. `RULE_ENDPOINT_NETWORK_ACTIVITY` (+15): Process initiating outbound connection.
  2. `RULE_SUSPICIOUS_EXTERNAL_NETWORK` (+10): Connection to external/public non-RFC1918 destination.
  3. `RULE_NETWORK_BLOCKCHAIN_CORRELATION` (+20): Network connection correlated with on-chain wallet.
  4. `RULE_TRANSACTION_CHAIN_LENGTH` (+15): High-confidence multi-hop transaction chain.
  5. `RULE_SUSPICIOUS_VASP_ATTRIBUTION` (+15): High-confidence attribution to suspicious/sanctioned VASP.
  6. `RULE_FULL_CROSS_DOMAIN_KILL_CHAIN` (+20): Full end-to-end cross-domain path (Process $\to$ VASP).
- **Finding Deduplication**: Findings are keyed deterministically by `(rule_id, sorted(evidence_ids), sorted(correlation_ids))` to prevent duplicate double-counting of identical observations.
- **Weakest-Link Confidence**: Finding confidence preserves the weakest underlying evidence or correlation confidence.
- **Severity Classification**:
  - `0 - 24`: **LOW**
  - `25 - 49`: **MEDIUM**
  - `50 - 74`: **HIGH**
  - `75 - 100`: **CRITICAL**
- **Deterministic Risk Hash**:
  $$\text{risk\_hash} = \text{SHA256}(\text{canonical\_json}(\{\text{case\_id}, \text{host}, \text{score}, \text{severity}, \text{findings}\}))$$

---

## Quickstart Guide

### 1. Environment Setup

```bash
# Activate virtual environment
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run full test suite (345 tests across all 10 phases)
PYTHONPATH=. pytest -q
```

### 2. CLI Execution & Inspection

#### Execute Full Pipeline (Evidence + Correlation + Graph + Timeline + Risk):
```bash
python -m jocky.cli examples/timeline_risk_demo.jky --execute --fixture
```

#### Execute Full Investigation Graph Pipeline:
```bash
python -m jocky.cli examples/graph_demo.jky --execute --fixture
```

#### Execute with Full JSON Output:
```bash
python -m jocky.cli examples/timeline_risk_demo.jky --execute --fixture --json
```

---

## Security Boundaries & Safety Guarantees

JOCKY is strictly defensive and read-only:
- **NO OFFENSIVE NETWORKING**: Does NOT implement packet injection, credential sniffing, MITM, ARP spoofing, DNS poisoning, port scanning, covert C2 channels, or domain fronting.
- **READ-ONLY SOCKET & PROCESS ENUMERATION**: Inspections read existing system state without modifying host sockets, killing processes, or modifying file permissions.
- **SYNTHETIC FIXTURES ONLY**: All test blockchain addresses and identities are synthetic (e.g. "Synthetic Suspicious EOA", "Example Exchange").
- **GROUNDED GRAPH & TIMELINE TOPOLOGY**: Graph edges and timeline events require verified evidence or correlation provenance. No fabricated shortcuts or timestamps.
- **SEPARATED DERIVED VIEWS**: `InvestigationGraph`, `InvestigationTimeline`, and `RiskAssessment` are derived views; building them never alters the underlying `EvidencePackage.package_hash`.
- **EXPLAINABLE RISK SCORING**: Zero black-box ML. Every risk finding is linked to explicit rules, evidence IDs, and bounded weights.

---

## Known Limitations (Phase 10 Scope)

- **Visual Dashboard UI**: Graph traversal, timelines, and risk assessments operate in-memory with text and JSON outputs; visual interactive canvas rendering is reserved for Phase 14.
- **On-Chain Evidence Anchoring**: `package_hash`, `graph_hash`, `timeline_hash`, and `risk_hash` provide cryptographic digests ready for IPFS/EVM smart contract anchoring in subsequent phases.
- **Live RPC Integrations**: Blockchain tracing and network analysis run deterministically on offline fixtures; live Web3 JSON-RPC providers remain optional.




---

## Phase 13: Central Investigation Management

Phase 13 introduces a lightweight, in-memory central investigation management layer on top of JOCKY's forensic and correlation engine. It allows investigators to manage multi-host cases, register target hosts into a centralized topology inventory, and attach immutable forensic evidence packages to the investigation case.

### Architecture
```
Multiple Hosts (Inventory)
      ↓
Central Investigation Case
      ↓
Host Evidence Packages (Attached)
      ↓
Existing Correlations / Graph / Timeline / Risk
      ↓
Unified Case Summary & Case Hash
```

### Key Capabilities
- **Language Extensions**:
  - `REGISTER HOST "hostname"`: Registers an endpoint into the case's host registry.
  - `ATTACH EVIDENCE`: Attaches the current host's `EvidencePackage` to the central case.
- **Host Registry**: In-memory registry with deterministic host IDs (`HOST-<sha256[:12]>`), host status tracking (`ONLINE`, `OFFLINE`, `UNKNOWN`), and optional platform metadata.
- **Package Hash Invariance**: Attaching an `EvidencePackage` to a case is strictly by immutable reference (`package_hash`). The package's integrity hash is verified before and after attachment and is never mutated.
- **Deterministic Case Hash**: Cases are hashed using `forensic.evidence.canonical.canonical_hash` over a canonical dict `{case_id, title, sorted(hosts), sorted(evidence_packages)}`. This digest is completely independent and separate from individual `package_hash`es and excludes mutable timestamps.
- **Aggregated Case Summary**: Gathers actual computed evidence items, relationships, cross-domain correlations, and the maximum risk assessment score across attached packages without inventing new scoring or correlation algorithms.

### Demo Execution
```bash
# Terminal output
python -m jocky.cli examples/central_management_demo.jky --execute --fixture

# Structured JSON output
python -m jocky.cli examples/central_management_demo.jky --execute --fixture --json
```

### Limitations & Scope (Phase 13)
- **In-Memory Only**: Central investigation state is in-memory per execution session; no distributed DB, cloud control plane, or external persistence is used.
- **No Remote Host Control**: Does NOT perform remote execution, agent orchestration, or C2 communications.
- **Multi-Host Collection Scope**: In the `central_management_demo.jky` script, multiple hosts (`LAB-PC-01`, `LAB-PC-02`, `LAB-PC-03`) are registered in the case inventory, but only `LAB-PC-01` executes forensic collection and attaches an evidence package in this local execution run.

---

## Phase 14: Investigation Dashboard

Phase 14 delivers a professional, unified web-based Investigation Dashboard built with React, TypeScript, Vite, and Tailwind CSS. The dashboard acts as the visualization layer for JOCKY's forensic, multi-host, blockchain, timeline, and cryptographic anchoring pipeline.

### Architecture
```
FastAPI Backend (/api/cases/...)
       ↓ (Typed JSON Contracts)
Vite + React 19 Frontend Dashboard
       ↓
┌─────────────────────────────────────────────────────────────┐
│ Case Overview (Central Investigation, Status & Metrics)     │
├─────────────────────────────────────────────────────────────┤
│ Hosts (Topology Inventory, Online/Unknown Posture)          │
├─────────────────────────────────────────────────────────────┤
│ Universal Evidence Explorer (Grounded Items & Provenance)   │
├─────────────────────────────────────────────────────────────┤
│ Investigation Attack Graph (Interactive Canvas & Inspector) │
├─────────────────────────────────────────────────────────────┤
│ Chronological Timeline (Unified Cross-Domain Events)        │
├─────────────────────────────────────────────────────────────┤
│ Risk Assessment (Explainable Rules & Weight Breakdown)      │
├─────────────────────────────────────────────────────────────┤
│ Blockchain Flow & Analytical VASP Attribution (Multi-Hop)   │
├─────────────────────────────────────────────────────────────┤
│ Evidence Anchoring & Dual-Verification (IPFS & On-Chain EVM)│
└─────────────────────────────────────────────────────────────┘
```

### Key Capabilities
- **Case Overview**: Displays actual case summary metrics (host count, evidence packages, evidence items, cross-domain correlations, grounded relationships, and overall risk score).
- **Host View**: Explores registered hosts, distinguishing `ONLINE`, `OFFLINE`, and `UNKNOWN` registration states without assuming absent telemetry means offline.
- **Universal Evidence Explorer**: Categorized and searchable table of evidence items (Files, Processes, Sockets, DNS records, Wallets, Transactions) with cryptographic SHA-256 integrity inspection.
- **Interactive Attack Graph**: Canvas with pan, zoom, node/edge selection, and forensic explainability panels detailing correlation provenance.
- **Chronological Timeline**: Multi-source timeline view showing exact event order or explicit `UNTIMED` badges (never fabricated).
- **Explainable Risk Assessment**: Visualizes deterministic rule weights, findings, confidence metrics, and linked evidence items.
- **Blockchain Trace & VASP**: Traces multi-hop transaction paths and presents analytical exchange attribution with explicit transparency disclaimers.
- **Dual-Verification Anchoring**: Real-time validation badges for IPFS CID and EVM smart contract block proofs.

### Running the Dashboard
```bash
# 1. Start the FastAPI backend
uvicorn api.main:app --host 127.0.0.1 --port 8000

# 2. In a separate terminal, run the Vite frontend
npm --prefix dashboard run dev
# Dashboard accessible at http://localhost:5173
```

### Building the Dashboard
```bash
npm --prefix dashboard run build
```

### Security & Integrity Guarantees
- **Read-Only Visualization**: The dashboard strictly visualizes existing forensic telemetry and cannot initiate remote commands, modify packages, or alter hash digests.
- **No Fabricated Data**: If data is missing or unavailable, the UI clearly displays `UNKNOWN`, `NOT AVAILABLE`, or `UNTIMED`.

---

## Phase 15: Security Research Lab

Phase 15 introduces a safe, controlled Security Research and Benchmarking Lab to JOCKY. The research lab allows security researchers and defensive detection engineers to study, benchmark, and evaluate detection rules against synthetic behavioral models without executing real malware, exploiting drivers, or deploying offensive payloads.

### Architecture
```
Controlled Research Scenario (ScenarioRegistry)
        ↓
Synthetic Observables (simulated = True)
        ↓
Defensive Detection Engine (Deterministic Rules)
        ↓
Benchmark Engine (Coverage, Timing, Metrics)
        ↓
Deterministic Result Hash (Isolated from Forensic Hashes)
        ↓
Reproducible CLI & Dashboard Reporting
```

### Safety & Ethical Boundaries
The Security Research Lab is strictly **defensive, deterministic, and non-destructive**:
- **NO OFFENSIVE PAYLOADS**: Does NOT generate shellcode, process injection vectors, reflective loaders, or malware.
- **NO DRIVER LOADING OR EXPLOITATION**: BYOVD research uses catalog records and static rule matching. No kernel drivers are downloaded, loaded, or interacted with.
- **NO SECURITY TAMPERING**: Security control assessment inspects posture without modifying or attempting to disable HVCI, VBS, or Secure Boot.
- **NO LIVE MALICIOUS TRAFFIC**: Network behavior simulation evaluates egress rules against RFC 5737 documentation IP ranges (`198.51.100.0/24`). No external attack infrastructure is contacted.
- **HASH ISOLATION**: `result_hash` is completely distinct from `EvidencePackage.package_hash`, `case_hash`, `graph_hash`, `timeline_hash`, and `risk_hash`. Production evidence packages are never contaminated.

### Registered Scenarios
1. `synthetic_polymorphism`: Evaluates detection consistency across benign representation transformations without executing payloads.
2. `synthetic_memory_execution`: Simulates RWX allocation telemetry without allocating executable physical pages or injecting code.
3. `synthetic_driver_risk`: Classifies driver vulnerability risk from synthetic catalog metadata.
4. `synthetic_security_controls`: Assesses hardware-enforced security posture (ENABLED, DISABLED, UNKNOWN, NOT APPLICABLE).
5. `synthetic_network_behavior`: Evaluates perimeter egress detection rules against documentation IP space.

### DSL Syntax
```jky
CASE "SEC-LAB-2026"
HOST "LAB-PC-01"

RESEARCH "synthetic_polymorphism"
RESEARCH "synthetic_memory_execution"
RESEARCH "synthetic_driver_risk"
RESEARCH "synthetic_security_controls"
RESEARCH "synthetic_network_behavior"
```

### Running Research Demos
```bash
# Terminal Execution
python -m jocky.cli examples/research_demo.jky --execute --fixture

# JSON Output
python -m jocky.cli examples/research_demo.jky --execute --fixture --json
```

---

## Deployment & Hosting

### Repository
- **GitHub Repository**: [https://github.com/jineshkumar134/jocky.git](https://github.com/jineshkumar134/jocky.git)

### Vercel Serverless Deployment

JOCKY is configured for full-stack deployment on [Vercel](https://vercel.com) via `vercel.json`:
- **Frontend**: Vite + React 19 single-page application built to static assets (`/dashboard/dist`).
- **Backend**: FastAPI serverless function powered by Python runtime (`/api/index.py`).
- **Swagger / OpenAPI Documentation**: Available at `/docs` and `/openapi.json`.

#### Deploying with Vercel CLI
```bash
# Install Vercel CLI
npm install -g vercel

# Deploy to Preview
vercel

# Deploy to Production
vercel --prod
```

#### Deploying via GitHub Integration
1. Push your changes to the GitHub repository: `https://github.com/jineshkumar134/jocky.git`.
2. Import the repository in your [Vercel Dashboard](https://vercel.com/new).
3. Vercel automatically detects `vercel.json` and provisions both the Python FastAPI serverless functions and the React frontend.


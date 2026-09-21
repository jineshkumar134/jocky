# JOCKY Architecture & Technical Specification

## Overview

**JOCKY** is a specialized cybersecurity and blockchain forensic domain-specific language (DSL) and investigation framework designed for automated cyber incident analysis, multi-hop cryptocurrency flow tracing, and cryptographically verifiable evidence anchoring.

---

## High-Level Pipeline

```
JOCKY Source (.jky)
       │
       ▼
   Lexer & Parser
       │
       ▼
  Abstract Syntax Tree (AST)
       │
       ▼
    JOCKY Intermediate Representation (IR)
       │
       ▼
    LLVM IR / Execution Engine
       │
       ├──► Endpoint Forensics Module (Files, Processes, Memory Artifacts)
       ├──► Network Forensics Module (Connections, Traffic Flows)
       └──► Blockchain Intelligence (EVM Tracing, VASP Entity Attribution)
       │
       ▼
  Evidence Correlation & Synthesis Engine
       │
       ├──► Unified Attack Graph
       ├──► Chronological Incident Timeline
       └──► Threat & Attribution Risk Analysis
       │
       ▼
  Decentralized Integrity Anchoring
       ├──► SHA-256 Content Addressing
       ├──► IPFS Storage Anchoring
       └──► EVM Smart Contract Proof Anchoring
       │
       ▼
  Forensic Report & Interactive Command Center Dashboard
```

---

## Directory Structure

```
jocky/
├── compiler/              # JOCKY DSL compilation pipeline
│   ├── lexer/            # Tokenizer
│   ├── parser/           # Recursive descent grammar parser
│   ├── ast/              # Abstract Syntax Tree nodes & visitors
│   ├── ir/               # JOCKY intermediate representation
│   └── llvm/             # LLVM IR generation adapters
├── runtime/               # Execution environment & orchestration
│   ├── executor/         # Script runner & execution context
│   └── modules/          # Core runtime modules
├── forensic/              # Digital forensics engines
│   ├── endpoint/         # File, process, and memory analysis
│   ├── network/          # Traffic and connection correlation
│   └── evidence/         # Artifact packaging & SHA-256 hashing
├── blockchain/            # On-chain intelligence
│   ├── evm/              # EVM RPC client & decoding
│   ├── tracer/           # Multi-hop transaction flow tracing
│   └── vasp/             # Exchange & entity attribution
├── correlation/           # Cross-domain evidence correlation engine
├── graph/                 # Attack graph & entity relation builder
├── anchoring/             # Proof-of-integrity subsystem
│   ├── ipfs/             # InterPlanetary File System storage adapter
│   └── evm/              # EVM smart contract anchor adapter
├── security_lab/          # Safe benchmark & synthetic simulation environment
├── api/                   # FastAPI backend services
│   ├── routes/           # API endpoints (health, compiler, forensics, graph)
│   ├── config.py         # App configuration & settings
│   └── main.py           # FastAPI entrypoint
├── dashboard/             # React + TypeScript + Vite + Tailwind UI
├── examples/              # Sample .jky scripts
├── tests/                 # Backend unit & integration test suite
└── docs/                  # Architecture & developer documentation
```

---

## Phased Implementation Roadmap

- **Phase 0 (Current)**: Project structure, Python API setup with health endpoints, React + Vite dashboard shell, pytest suite, and configuration baseline.
- **Phase 1**: JOCKY DSL Lexer, Parser, AST, and IR execution engine.
- **Phase 2**: Endpoint and network forensic modules with safe simulation feeds.
- **Phase 3**: Blockchain transaction tracer and VASP attribution engine.
- **Phase 4**: Correlation engine and attack graph generator.
- **Phase 5**: IPFS & EVM cryptographic evidence anchoring.
- **Phase 6**: Command Center UI integration, interactive graph visualization, and report export.

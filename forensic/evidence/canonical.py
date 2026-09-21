"""
JOCKY Forensic — Evidence Canonicalization and Deterministic Hashing
===================================================================
Implements deterministic canonical JSON serialization, stable evidence ID
generation, and cryptographic integrity hashing.

Key Principles:
- Deterministic canonical JSON serialization (sorted keys, compact separators,
  consistent float formatting, consistent ISO 8601 timestamps).
- Stable evidence IDs derived from:
    seed = f"{type}|{canonical_entity}|{provenance_seed}"
  where provenance_seed = f"{host}:{collector}"
- Cryptographic integrity hashing: SHA-256 of canonical JSON excluding
  the mutable integrity field.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from decimal import Decimal
from enum import Enum
from typing import Any, Dict, Optional


def _canonical_default(obj: Any) -> Any:
    """Type serializer for deterministic canonical JSON representation."""
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, (datetime,)):
        if obj.tzinfo is None:
            obj = obj.replace(tzinfo=timezone.utc)
        return obj.astimezone(timezone.utc).isoformat()
    if isinstance(obj, Decimal):
        return str(obj)
    if hasattr(obj, "model_dump"):
        return obj.model_dump()
    if hasattr(obj, "__dict__"):
        return obj.__dict__
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


def canonical_json(data: Any) -> str:
    """
    Produce a deterministic canonical JSON string.
    - Keys are recursively sorted in lexicographical ASCII order.
    - Separators are compact: (',', ':') with no extraneous whitespace.
    - UTF-8 characters are preserved without unnecessary escaping (ensure_ascii=False).
    - Floats are formatted consistently.
    """
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=_canonical_default,
    )


def canonical_hash(data: Any) -> str:
    """Compute the SHA-256 hexadecimal digest of canonical JSON data."""
    canon_str = canonical_json(data)
    return hashlib.sha256(canon_str.encode("utf-8")).hexdigest()


def generate_evidence_id(
    evidence_type: str,
    entity_data: Dict[str, Any],
    host: str,
    collector: str,
) -> str:
    """
    Generate a deterministic, stable evidence ID.

    Formula:
      type_prefix = evidence_type.upper()[:4]
      provenance_seed = f"{host}:{collector}"
      entity_seed = canonical_json(entity_data)
      combined_seed = f"{evidence_type.upper()}|{entity_seed}|{provenance_seed}"
      digest = sha256(combined_seed)[:12]
      return f"EVID-{type_prefix}-{digest}"

    Example outputs:
      EVID-FILE-7a2c1f904b3e
      EVID-PROC-5e8d2b10ca4f
      EVID-NETC-3b91fa0284e6
    """
    type_upper = evidence_type.upper()
    prefix_map = {
        "FILE": "FILE",
        "PROCESS": "PROC",
        "SYSTEM": "SYST",
        "NETWORK_CONNECTION": "NETC",
        "NETWORK_LISTENER": "NETL",
        "DNS_RECORD": "DNSR",
        "WALLET": "WLLT",
        "TRANSACTION": "TXID",
        "VASP": "VASP",
        "BLOCKCHAIN_EVENT": "BCEV",
    }
    type_prefix = prefix_map.get(type_upper, type_upper[:4])

    provenance_seed = f"{host}:{collector}"
    entity_seed = canonical_json(entity_data)
    combined_seed = f"{type_upper}|{entity_seed}|{provenance_seed}"
    digest = hashlib.sha256(combined_seed.encode("utf-8")).hexdigest()[:12]
    return f"EVID-{type_prefix}-{digest}"


def generate_relationship_id(
    rel_type: str,
    source_id: str,
    target_id: str,
) -> str:
    """
    Generate a deterministic, stable relationship ID.
    Formula:
      rel_prefix = rel_type.upper()[:4]
      seed = f"{rel_type.upper()}|{source_id}|{target_id}"
      digest = sha256(seed)[:10]
      return f"REL-{rel_prefix}-{digest}"
    """
    rel_upper = rel_type.upper()
    seed = f"{rel_upper}|{source_id}|{target_id}"
    digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:10]
    return f"REL-{rel_upper[:4]}-{digest}"

"""Decision Ledger hashing and projection invariants."""

from __future__ import annotations

import hashlib
import json
from typing import Any

FINDING_CURRENT_PROJECTION_SCHEMA_VERSION = "finding-current-projection.v1"


class DecisionLedgerInvariantError(RuntimeError):
    """Raised when immutable history or its current projection diverges."""


def canonical_payload_sha256(payload: dict[str, Any]) -> str:
    """Return a deterministic SHA-256 for a JSON-compatible decision payload."""
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()

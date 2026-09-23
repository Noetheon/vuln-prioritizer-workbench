"""
Versioned, lossless storage encoding; the public evidence contract stays v2.

Only fixed paths are shared. References live outside user/provider data, and
sections never contain references to other sections. This keeps hydration and
integrity checks bounded and avoids a recursive object-store protocol.
"""

from __future__ import annotations

import hashlib
import json
import zlib
from copy import deepcopy
from typing import Any

from app.decision_core.ledger import DecisionLedgerInvariantError, canonical_payload_sha256

STORAGE_KEY = "_vpw_evidence_storage"
STORAGE_VERSION = "finding-evidence-sections.v1"
# Provider facts occur in the replay input and two presentation contracts. Share
# those before sharing the remaining decision/input sections across imports.
FACT_PATHS = (
    ("evaluation_input", "provider_evidence"),
    ("provider", "provider_evidence"),
    ("priority_evidence", "raw", "provider_evidence"),
)
SECTION_PATHS = tuple(
    (name,)
    for name in ("priority_evidence", "provider", "evaluation_input", "remediation", "attack")
)
MIN_SECTION_BYTES = 512


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def split_payload(payload: dict[str, Any]) -> tuple[dict[str, Any], dict[str, bytes]]:
    """Return a compact document and immutable, content-addressed JSON sections."""
    if STORAGE_KEY in payload:
        raise DecisionLedgerInvariantError("Cannot encode an already encoded evidence payload.")
    document = deepcopy(payload)
    sections: dict[str, bytes] = {}
    refs: list[dict[str, Any]] = []
    for path in (*FACT_PATHS, *SECTION_PATHS):
        parent: Any = document
        for name in path[:-1]:
            parent = parent.get(name) if isinstance(parent, dict) else None
        if not isinstance(parent, dict) or path[-1] not in parent:
            continue
        encoded = _canonical_bytes(parent[path[-1]])
        if len(encoded) < MIN_SECTION_BYTES:
            continue
        digest = hashlib.sha256(encoded).hexdigest()
        sections[digest] = encoded
        refs.append({"path": list(path), "sha256": digest})
        del parent[path[-1]]
    document[STORAGE_KEY] = {
        "version": STORAGE_VERSION,
        "sha256": canonical_payload_sha256(payload),
        "refs": refs,
    }
    return document, sections


def section_references(document: dict[str, Any]) -> list[dict[str, Any]]:
    """Validate storage metadata, allowing unencoded historical/legacy contracts."""
    if STORAGE_KEY not in document:
        return []
    metadata = document[STORAGE_KEY]
    if not isinstance(metadata, dict) or metadata.get("version") != STORAGE_VERSION:
        raise DecisionLedgerInvariantError("Unsupported evidence storage version.")
    refs = metadata.get("refs")
    if not isinstance(refs, list) or len(refs) > len(FACT_PATHS) + len(SECTION_PATHS):
        raise DecisionLedgerInvariantError("Invalid evidence section references.")
    paths: set[tuple[str, ...]] = set()
    for ref in refs:
        if not isinstance(ref, dict) or not isinstance(ref.get("path"), list):
            raise DecisionLedgerInvariantError("Invalid evidence section reference.")
        if not all(isinstance(name, str) for name in ref["path"]):
            raise DecisionLedgerInvariantError("Invalid evidence section path.")
        path = tuple(ref["path"])
        digest = ref.get("sha256")
        if (
            path not in (*FACT_PATHS, *SECTION_PATHS)
            or path in paths
            or not isinstance(digest, str)
            or len(digest) != 64
            or any(char not in "0123456789abcdef" for char in digest)
        ):
            raise DecisionLedgerInvariantError("Invalid evidence section identity.")
        paths.add(path)
    return refs


def decode_section(compressed: bytes, size: int, digest: str) -> Any:
    """Verify compressed content before it can contribute to a decision payload."""
    try:
        if size < 0:
            raise ValueError("negative section length")
        decompressor = zlib.decompressobj()
        encoded = decompressor.decompress(compressed, size + 1)
        if (
            len(encoded) != size
            or not decompressor.eof
            or decompressor.unused_data
            or hashlib.sha256(encoded).hexdigest() != digest
        ):
            raise ValueError("section length or digest mismatch")
        return json.loads(encoded)
    except (ValueError, zlib.error, UnicodeError) as exc:
        raise DecisionLedgerInvariantError(f"Corrupt immutable evidence section {digest}.") from exc


def join_payload(document: dict[str, Any], sections: dict[str, Any]) -> dict[str, Any]:
    """Hydrate an isolated, exact public contract and verify its historical hash."""
    refs = section_references(document)
    payload = deepcopy(document)
    metadata = payload.pop(STORAGE_KEY, None)
    for ref in sorted(refs, key=lambda item: len(item["path"])):
        digest = ref["sha256"]
        if digest not in sections:
            raise DecisionLedgerInvariantError(f"Missing immutable evidence section {digest}.")
        parent: Any = payload
        for name in ref["path"][:-1]:
            parent = parent.get(name) if isinstance(parent, dict) else None
        name = ref["path"][-1]
        if not isinstance(parent, dict) or name in parent:
            raise DecisionLedgerInvariantError("Evidence section path conflicts with its document.")
        parent[name] = deepcopy(sections[digest])
    if metadata is not None and canonical_payload_sha256(payload) != metadata.get("sha256"):
        raise DecisionLedgerInvariantError(
            "Reconstructed evidence does not match its immutable hash."
        )
    return payload

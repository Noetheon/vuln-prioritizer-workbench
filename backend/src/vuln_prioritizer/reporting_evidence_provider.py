"""Provider snapshot helpers for CLI evidence bundle manifests."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from vuln_prioritizer.reporting_evidence_inputs import safe_source_path_label

PROVIDER_SNAPSHOT_MAX_BYTES = 25 * 1024 * 1024


def provider_snapshot_manifest_entry(
    metadata: object,
    *,
    analysis_path: Path,
    bundle_path: str | None = None,
    bundle_sha256: str | None = None,
) -> dict[str, Any]:
    if not isinstance(metadata, dict):
        return {}
    snapshot_path = metadata.get("provider_snapshot_file")
    snapshot_hash = metadata.get("provider_snapshot_hash")
    if snapshot_hash is None:
        resolved_snapshot = resolve_provider_snapshot_path(snapshot_path, analysis_path)
        if resolved_snapshot is not None:
            snapshot_hash = _sha256_file(resolved_snapshot, max_bytes=PROVIDER_SNAPSHOT_MAX_BYTES)
    entry = {
        "id": metadata.get("provider_snapshot_id"),
        "sha256": bundle_sha256 or snapshot_hash,
        "path": safe_source_path_label(snapshot_path) if snapshot_path else None,
        "bundle_path": bundle_path,
        "sources": metadata.get("provider_snapshot_sources", []),
    }
    return {key: value for key, value in entry.items() if value not in (None, "", [])}


def resolve_provider_snapshot_path(reported_path: object, analysis_path: Path) -> Path | None:
    """Resolve a provider snapshot only when it is a sidecar beside the analysis file."""
    if not isinstance(reported_path, str) or not reported_path.strip():
        return None
    candidate = Path(reported_path)
    if candidate.is_absolute() or ".." in candidate.parts:
        return None
    analysis_root = analysis_path.parent.resolve()
    resolved = (analysis_root / candidate).resolve()
    if not resolved.is_relative_to(analysis_root) or not resolved.is_file():
        return None
    if resolved.stat().st_size > PROVIDER_SNAPSHOT_MAX_BYTES:
        return None
    return resolved


def _sha256_file(path: Path, *, max_bytes: int) -> str | None:
    digest = hashlib.sha256()
    consumed = 0
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            consumed += len(chunk)
            if consumed > max_bytes:
                return None
            digest.update(chunk)
    return digest.hexdigest()


__all__ = [
    "provider_snapshot_manifest_entry",
    "resolve_provider_snapshot_path",
]

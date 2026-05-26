"""Provider snapshot metadata helpers for analysis contexts."""

from __future__ import annotations

import hashlib
from pathlib import Path


def _provider_snapshot_hash(path: Path | None) -> str | None:
    """Return the SHA-256 hash for a provider snapshot file when readable."""
    if path is None:
        return None
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def _provider_snapshot_metadata_path(path: Path | None, output_path: Path | None) -> str | None:
    """Return the provider snapshot path label stored in analysis metadata."""
    if path is None:
        return None
    if output_path is not None:
        try:
            return path.resolve().relative_to(output_path.parent.resolve()).as_posix()
        except ValueError:
            pass
    return str(path)

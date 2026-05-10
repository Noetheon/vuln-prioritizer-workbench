"""Input path helpers for CLI evidence bundle manifests."""

from __future__ import annotations

import hashlib
import ntpath
from pathlib import Path

from vuln_prioritizer.models import EvidenceBundleInputHash


def analysis_input_paths(metadata: object) -> list[str]:
    if not isinstance(metadata, dict):
        return []

    input_paths = metadata.get("input_paths")
    if isinstance(input_paths, list):
        normalized = [
            item.strip() for item in input_paths if isinstance(item, str) and item.strip()
        ]
        if normalized:
            return normalized

    input_path = metadata.get("input_path")
    if isinstance(input_path, str) and input_path.strip():
        return [input_path.strip()]
    return []


def source_input_bundle_path(resolved_input: Path, *, index: int, multiple: bool) -> str:
    if multiple:
        return f"input/{index:03d}-{resolved_input.name}"
    return f"input/{resolved_input.name}"


def input_hash_entry(
    path: Path,
    *,
    manifest_path: str | None = None,
) -> EvidenceBundleInputHash:
    content = path.read_bytes()
    return EvidenceBundleInputHash(
        path=manifest_path or safe_source_path_label(path),
        size_bytes=len(content),
        sha256=hashlib.sha256(content).hexdigest(),
    )


def safe_source_path_label(value: object) -> str:
    """Return a manifest-safe source label without local directory disclosure."""
    if isinstance(value, Path):
        text = str(value)
    elif isinstance(value, str):
        text = value
    else:
        text = ""
    name = ntpath.basename(text.strip().rstrip("/\\"))
    return name or "[REDACTED-PATH]"


def resolve_analysis_input_path(reported_path: object, analysis_path: Path) -> Path | None:
    if not isinstance(reported_path, str) or not reported_path.strip():
        return None
    candidate = Path(reported_path).expanduser()
    paths = (
        [candidate]
        if candidate.is_absolute()
        else [Path.cwd() / candidate, analysis_path.parent / candidate]
    )
    for path in paths:
        resolved = path.resolve()
        if resolved.is_file():
            return resolved
    return None


__all__ = [
    "analysis_input_paths",
    "input_hash_entry",
    "resolve_analysis_input_path",
    "safe_source_path_label",
    "source_input_bundle_path",
]

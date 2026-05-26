"""Managed artifact resolution for Workbench imports."""

from __future__ import annotations

import re
from pathlib import Path

from app.core.config import Settings
from app.services.import_errors import ImportServiceError
from vuln_prioritizer.options import AttackSource

SAFE_ATTACK_FILENAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")
SAFE_SNAPSHOT_FILENAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*[.]json$")


def resolve_workbench_provider_snapshot_path(
    provider_snapshot_file: str | None,
    *,
    settings: Settings,
) -> Path | None:
    """Resolve workbench provider snapshot path function."""
    value = provider_snapshot_file.strip() if provider_snapshot_file else ""
    if not value:
        return None
    if (
        not SAFE_SNAPSHOT_FILENAME_RE.fullmatch(value)
        or "/" in value
        or "\\" in value
        or Path(value).name != value
    ):
        raise ImportServiceError(status_code=422, detail="Provider snapshot path is not allowed.")
    snapshot_root = settings.provider_snapshot_dir_path.resolve(strict=False)
    candidate = (snapshot_root / value).resolve(strict=False)
    if not candidate.is_relative_to(snapshot_root):
        raise ImportServiceError(status_code=422, detail="Provider snapshot path is not allowed.")
    if not candidate.exists() or not candidate.is_file():
        raise ImportServiceError(status_code=422, detail="Provider snapshot file does not exist.")
    return candidate


def resolve_workbench_attack_artifact_path(
    value: str | None,
    *,
    settings: Settings,
) -> Path | None:
    """Resolve workbench attack artifact path function."""
    filename = value.strip() if value else ""
    if not filename:
        return None
    if (
        not SAFE_ATTACK_FILENAME_RE.fullmatch(filename)
        or "/" in filename
        or "\\" in filename
        or Path(filename).name != filename
    ):
        raise ImportServiceError(status_code=422, detail="ATT&CK artifact path is not allowed.")
    artifact_root = settings.attack_artifact_dir_path.resolve(strict=False)
    candidate = (artifact_root / filename).resolve(strict=False)
    if not candidate.is_relative_to(artifact_root):
        raise ImportServiceError(status_code=422, detail="ATT&CK artifact path is not allowed.")
    if not candidate.exists() or not candidate.is_file():
        raise ImportServiceError(status_code=422, detail="ATT&CK artifact file does not exist.")
    return candidate


def validate_attack_import_options(
    *,
    attack_source: str,
    attack_mapping_path: Path | None,
    attack_metadata_path: Path | None,
) -> AttackSource:
    """Validate attack import options function."""
    raw_source = attack_source.strip() if attack_source else "none"
    try:
        normalized_source = AttackSource(raw_source)
    except ValueError as exc:
        raise ImportServiceError(
            status_code=422,
            detail=f"Unsupported ATT&CK source: {raw_source}.",
        ) from exc
    if normalized_source == AttackSource.none:
        if attack_mapping_path is not None or attack_metadata_path is not None:
            raise ImportServiceError(
                status_code=422,
                detail="ATT&CK mapping files require attack_source=ctid-json or local-curated.",
            )
        return normalized_source
    if normalized_source not in {AttackSource.ctid_json, AttackSource.local_curated}:
        raise ImportServiceError(
            status_code=422,
            detail="Workbench ATT&CK imports only support ctid-json or local-curated.",
        )
    if attack_mapping_path is None:
        raise ImportServiceError(
            status_code=422,
            detail="ATT&CK imports require a mapping file.",
        )
    return normalized_source

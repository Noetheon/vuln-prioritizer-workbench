"""Provider snapshot export and replay helpers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

from pydantic import ValidationError

from app.domain.engine.models import ProviderSnapshotReport
from app.domain.engine.security_redaction import redact_text, redact_value

if TYPE_CHECKING:
    from pydantic import BaseModel

    from app.domain.engine.models import ProviderSnapshotItem


_REQUIRED_PROVIDER_SNAPSHOT_KEYS = {"metadata", "items", "warnings"}
_REQUIRED_PROVIDER_SNAPSHOT_METADATA_KEYS = {
    "schema_version",
    "artifact_kind",
    "snapshot_format",
    "generated_at",
    "input_path",
    "input_paths",
    "input_format",
    "selected_sources",
    "requested_cves",
    "output_path",
    "cache_enabled",
    "cache_dir",
    "source_hashes",
    "source_metadata",
    "offline_kev_file",
    "nvd_api_key_env",
}
_PROVIDER_SNAPSHOT_FORMAT = "provider-snapshot.v1.json"


def generate_provider_snapshot_json(report: ProviderSnapshotReport) -> str:
    """Serialize a provider snapshot report as stable JSON."""
    payload = report.model_dump()
    payload["warnings"] = [redact_text(str(warning)) for warning in payload.get("warnings", [])]
    metadata = payload.get("metadata")
    if isinstance(metadata, dict) and isinstance(metadata.get("source_metadata"), dict):
        metadata["source_metadata"] = redact_value(
            metadata["source_metadata"],
            redact_paths=False,
        )[0]
    return json.dumps(payload, indent=2, sort_keys=True)


def load_provider_snapshot(path: Path) -> ProviderSnapshotReport:
    """Load and validate a provider snapshot artifact."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"{path} could not be read: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path} is not valid JSON: {exc.msg}.") from exc

    _validate_explicit_provider_snapshot_v1(payload, path=path)

    try:
        return ProviderSnapshotReport.model_validate(payload)
    except ValidationError as exc:
        raise ValueError(f"{path} is not a valid provider snapshot: {exc}") from exc


def _validate_explicit_provider_snapshot_v1(payload: object, *, path: Path) -> None:
    if not isinstance(payload, dict):
        raise ValueError(f"{path} is not a valid provider snapshot: expected a JSON object.")

    missing_top_level = sorted(_REQUIRED_PROVIDER_SNAPSHOT_KEYS - set(payload))
    if missing_top_level:
        raise ValueError(
            f"{path} is not a valid provider snapshot: missing required top-level "
            f"field(s): {', '.join(missing_top_level)}."
        )

    metadata = payload.get("metadata")
    if not isinstance(metadata, dict):
        raise ValueError(
            f"{path} is not a valid provider snapshot: metadata must be a JSON object."
        )

    missing_metadata = sorted(_REQUIRED_PROVIDER_SNAPSHOT_METADATA_KEYS - set(metadata))
    if missing_metadata:
        raise ValueError(
            f"{path} is not a valid provider snapshot: missing required metadata "
            f"field(s): {', '.join(missing_metadata)}."
        )

    snapshot_format = metadata.get("snapshot_format")
    if snapshot_format != _PROVIDER_SNAPSHOT_FORMAT:
        raise ValueError(
            f"{path} is not a valid provider snapshot: metadata.snapshot_format must be "
            f"{_PROVIDER_SNAPSHOT_FORMAT}."
        )


def snapshot_items_by_cve(report: ProviderSnapshotReport) -> dict[str, ProviderSnapshotItem]:
    """Index a provider snapshot by CVE identifier."""
    return {item.cve_id: item for item in report.items}


def resolve_snapshot_provider_data(
    report: ProviderSnapshotReport,
    *,
    source_name: str,
    cve_ids: list[str],
) -> tuple[dict[str, BaseModel], list[str]]:
    """Resolve per-provider snapshot coverage for the requested CVEs."""
    items_by_cve = snapshot_items_by_cve(report)
    selected_sources = set(report.metadata.selected_sources)
    resolved: dict[str, BaseModel] = {}
    missing: list[str] = []

    for cve_id in cve_ids:
        if source_name not in selected_sources:
            continue
        item = items_by_cve.get(cve_id)
        provider_value = None if item is None else getattr(item, source_name, None)
        if provider_value is None:
            missing.append(cve_id)
            continue
        resolved[cve_id] = provider_value

    return resolved, missing

"""Provider status DTO projection helpers."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from app.core.config import Settings
from app.models import (
    AnalysisRun,
    AnalysisRunStatus,
    ProviderSnapshot,
    ProviderSnapshotStatusPublic,
    ProviderSourceStatusPublic,
    ProviderStatusPublic,
    ProviderUpdateJobPublic,
)
from app.models.base import get_datetime_utc
from app.services.run_workflow_metadata import (
    workflow_error_payload_or_empty,
    workflow_summary_payload_or_empty,
)
from vuln_prioritizer.security_redaction import redact_value

PROVIDER_SOURCES = ("nvd", "epss", "kev")
ATTACK_STIX_SOURCE = "attack_stix"
NO_PROVIDER_SNAPSHOT_WARNING = "No provider snapshot has been recorded yet."


def provider_update_job_public(
    run: AnalysisRun | None,
    *,
    active_settings: Settings,
) -> ProviderUpdateJobPublic | None:
    """Return public provider update job metadata for the current environment."""
    return _provider_update_job(run, production_safe=_production_safe(active_settings))


def provider_status_payload(
    snapshot: ProviderSnapshot | None,
    *,
    latest_update_run: AnalysisRun | None,
    active_settings: Settings,
) -> ProviderStatusPublic:
    """Build the provider status response from persisted snapshot and job state."""
    metadata = _snapshot_metadata(snapshot)
    production_safe = _production_safe(active_settings)
    public_metadata = _provider_public_metadata(metadata, production_safe=production_safe)
    warnings = [_public_text(item) for item in _string_list(metadata.get("warnings"))]
    failed_update_error = _failed_update_error(latest_update_run)
    raw_last_error = failed_update_error or _last_error(metadata)
    last_error = _public_text(raw_last_error) if raw_last_error is not None else None
    snapshot_status = _snapshot_status(snapshot, metadata)
    if snapshot is None:
        warnings.append(NO_PROVIDER_SNAPSHOT_WARNING)
    if failed_update_error is not None:
        warnings.append(f"Latest provider update failed: {_public_text(failed_update_error)}")

    degraded = snapshot_status.missing or raw_last_error is not None
    return ProviderStatusPublic(
        status="degraded" if degraded else "ok",
        snapshot=_snapshot_status(
            snapshot,
            metadata,
            public_metadata=public_metadata,
            production_safe=production_safe,
        ),
        sources=_source_statuses(snapshot, snapshot_status.selected_sources, last_error=last_error),
        latest_update_job=_provider_update_job(
            latest_update_run,
            production_safe=production_safe,
        ),
        cache_dir=(
            None
            if production_safe
            else _public_path(
                _string_or_none(public_metadata.get("cache_dir"))
                or _settings_path(active_settings, "provider_cache_dir", "PROVIDER_CACHE_DIR")
            )
        ),
        snapshot_dir=(
            None
            if production_safe
            else _public_path(
                _string_or_none(public_metadata.get("snapshot_dir"))
                or _settings_path(
                    active_settings,
                    "provider_snapshot_dir",
                    "PROVIDER_SNAPSHOT_DIR",
                )
            )
        ),
        warnings=warnings,
        last_sync=_last_sync(snapshot, metadata),
        last_error=last_error,
        cache_age_seconds=_cache_age_seconds(snapshot.created_at if snapshot is not None else None),
        snapshot_mode=_snapshot_mode(snapshot, metadata),
    )


def _provider_update_job(
    run: AnalysisRun | None,
    *,
    production_safe: bool = False,
) -> ProviderUpdateJobPublic | None:
    if run is None:
        return None
    metadata = workflow_summary_payload_or_empty(run) or workflow_error_payload_or_empty(run)
    public_metadata = _provider_public_metadata(metadata, production_safe=production_safe)
    return ProviderUpdateJobPublic(
        id=str(run.id),
        status=str(run.status),
        execution_mode=_string_or_none(metadata.get("execution_mode")) or "request",
        requested_sources=_string_list(
            metadata.get("requested_sources") or metadata.get("sources")
        ),
        started_at=_iso_datetime(run.started_at),
        finished_at=_iso_datetime(run.finished_at),
        error_message=_public_text(_failed_update_error(run)),
        metadata_=public_metadata,
    )


def _snapshot_status(
    snapshot: ProviderSnapshot | None,
    metadata: dict[str, Any],
    *,
    public_metadata: dict[str, Any] | None = None,
    production_safe: bool = False,
) -> ProviderSnapshotStatusPublic:
    if snapshot is None:
        return ProviderSnapshotStatusPublic()

    source_hashes = _dict_value(snapshot.source_hashes_json)
    selected_sources = _selected_sources(snapshot, metadata, source_hashes)
    snapshot_mode = _snapshot_mode(snapshot, metadata)
    safe_metadata = public_metadata or _provider_public_metadata(
        metadata,
        production_safe=production_safe,
    )
    return ProviderSnapshotStatusPublic(
        id=str(snapshot.id),
        created_at=_iso_datetime(snapshot.created_at),
        content_hash=snapshot.content_hash,
        nvd_last_sync=snapshot.nvd_last_sync,
        epss_date=snapshot.epss_date,
        kev_catalog_version=snapshot.kev_catalog_version,
        generated_at=_string_or_none(metadata.get("generated_at")),
        selected_sources=selected_sources,
        requested_cves=_int_value(metadata.get("requested_cves")),
        source_hashes={} if production_safe else _dict_value(_public_payload(source_hashes)),
        source_metadata=safe_metadata,
        source_path=None if production_safe else _source_path(safe_metadata),
        locked_provider_data=_bool_value(metadata.get("locked_provider_data")),
        missing=_bool_value(metadata.get("missing"), default=False),
        mode=snapshot_mode,
    )


def _source_statuses(
    snapshot: ProviderSnapshot | None,
    selected_sources: list[str],
    *,
    last_error: str | None,
) -> list[ProviderSourceStatusPublic]:
    values = {
        "nvd": snapshot.nvd_last_sync if snapshot is not None else None,
        "epss": snapshot.epss_date if snapshot is not None else None,
        "kev": snapshot.kev_catalog_version if snapshot is not None else None,
    }
    metadata = _snapshot_metadata(snapshot)
    source_hashes = _dict_value(snapshot.source_hashes_json) if snapshot is not None else {}
    source_names = _source_names(selected_sources, source_hashes)
    values[ATTACK_STIX_SOURCE] = _string_or_none(metadata.get("attack_version"))
    stale_sources = set(_string_list(metadata.get("stale_sources")))
    cache_age = _cache_age_seconds(snapshot.created_at if snapshot is not None else None)
    details = {
        "nvd": "NVD last modified timestamp from the latest stored snapshot.",
        "epss": "EPSS date from the latest stored snapshot.",
        "kev": "Latest KEV date_added value from the latest stored snapshot.",
        ATTACK_STIX_SOURCE: "ATT&CK STIX attack_version from the latest stored snapshot.",
    }
    selected = set(selected_sources)
    return [
        ProviderSourceStatusPublic(
            name=name,
            selected=name in selected,
            available=_source_available(name, values=values, source_hashes=source_hashes),
            stale=name in stale_sources,
            value=values.get(name),
            last_sync=(
                _string_or_none(metadata.get("generated_at"))
                if name == ATTACK_STIX_SOURCE
                else values.get(name)
            ),
            last_error=last_error,
            cache_age_seconds=cache_age,
            detail=details.get(name, f"{name} status from the latest stored snapshot."),
        )
        for name in source_names
    ]


def _selected_sources(
    snapshot: ProviderSnapshot,
    metadata: dict[str, Any],
    source_hashes: dict[str, Any],
) -> list[str]:
    explicit_sources = _string_list(metadata.get("selected_sources"))
    if explicit_sources:
        return explicit_sources

    hash_sources = _ordered_sources(source_hashes)
    if hash_sources:
        return hash_sources

    available_sources = {
        "nvd": snapshot.nvd_last_sync,
        "epss": snapshot.epss_date,
        "kev": snapshot.kev_catalog_version,
    }
    return [source for source in PROVIDER_SOURCES if available_sources[source] is not None]


def _ordered_sources(values: dict[str, Any]) -> list[str]:
    known_sources = [source for source in PROVIDER_SOURCES if source in values]
    extra_sources = sorted(source for source in values if source not in PROVIDER_SOURCES)
    return [*known_sources, *extra_sources]


def _source_names(selected_sources: list[str], source_hashes: dict[str, Any]) -> list[str]:
    source_names = list(PROVIDER_SOURCES)
    for source in [*_ordered_sources(source_hashes), *selected_sources]:
        if source not in source_names:
            source_names.append(source)
    return source_names


def _source_available(
    name: str,
    *,
    values: dict[str, str | None],
    source_hashes: dict[str, Any],
) -> bool:
    return values.get(name) is not None or _string_or_none(source_hashes.get(name)) is not None


def _snapshot_metadata(snapshot: ProviderSnapshot | None) -> dict[str, Any]:
    if snapshot is None:
        return {}
    return _dict_value(snapshot.source_metadata_json)


def _snapshot_mode(snapshot: ProviderSnapshot | None, metadata: dict[str, Any]) -> str:
    if snapshot is None or _bool_value(metadata.get("missing"), default=False):
        return "missing"

    explicit_mode = _string_or_none(metadata.get("snapshot_mode"))
    if explicit_mode is not None:
        return explicit_mode
    if _bool_value(metadata.get("locked_provider_data")):
        return "locked"
    if _bool_value(metadata.get("cache_only")):
        return "cache-only"
    return "snapshot"


def _last_sync(snapshot: ProviderSnapshot | None, metadata: dict[str, Any]) -> str | None:
    if snapshot is None:
        return None
    return _string_or_none(metadata.get("generated_at")) or _iso_datetime(snapshot.created_at)


def _cache_age_seconds(created_at: datetime | None) -> int | None:
    if created_at is None:
        return None
    normalized_created_at = _aware_datetime(created_at)
    age = get_datetime_utc() - normalized_created_at
    return max(int(age.total_seconds()), 0)


def _last_error(metadata: dict[str, Any]) -> str | None:
    for key in ("last_error", "error_message", "error"):
        value = _string_or_none(metadata.get(key))
        if value is not None:
            return value
    return None


def _failed_update_error(run: AnalysisRun | None) -> str | None:
    if run is None:
        return None
    if run.status != AnalysisRunStatus.FAILED:
        return None
    if run.error_message:
        return run.error_message
    error_json = workflow_error_payload_or_empty(run)
    for key in ("detail", "message", "error", "last_error"):
        value = _string_or_none(error_json.get(key))
        if value is not None:
            return value
    for value in error_json.values():
        text = _string_or_none(value)
        if text is not None:
            return text
    return None


def _source_path(metadata: dict[str, Any]) -> str | None:
    for key in ("source_path", "snapshot_path", "output_path"):
        value = _string_or_none(metadata.get(key))
        if value is not None:
            return value
    return None


def _settings_path(active_settings: object, *names: str) -> str | None:
    for name in names:
        value = getattr(active_settings, name, None)
        if value is not None:
            return str(value)
    return None


def _dict_value(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def _string_or_none(value: Any) -> str | None:
    if isinstance(value, str) and value.strip():
        return value
    return None


def _int_value(value: Any) -> int:
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str) and value.isdecimal():
        return int(value)
    return 0


def _bool_value(value: Any, *, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes"}
    return default


def _iso_datetime(value: datetime | None) -> str | None:
    if value is None:
        return None
    return _aware_datetime(value).isoformat()


def _aware_datetime(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value


def _provider_public_metadata(
    metadata: dict[str, Any],
    *,
    production_safe: bool,
) -> dict[str, Any]:
    public = _dict_value(_public_payload(metadata))
    if not production_safe:
        return public

    for key in (
        "cache_dir",
        "input_path",
        "input_paths",
        "output_path",
        "provider_cache_dir",
        "snapshot_dir",
        "snapshot_file",
        "snapshot_path",
        "source_path",
    ):
        public.pop(key, None)
    source_metadata = public.get("source_metadata")
    if isinstance(source_metadata, dict):
        public["source_metadata"] = _production_source_metadata(source_metadata)
    return public


def _production_source_metadata(value: dict[str, Any]) -> dict[str, Any]:
    allowed_keys = {
        "cache_only",
        "fallback_from_previous_snapshot",
        "fetched_count",
        "missing_count",
        "record_count",
        "source",
    }
    public: dict[str, Any] = {}
    for source, metadata in value.items():
        if isinstance(metadata, dict):
            public[source] = {key: item for key, item in metadata.items() if key in allowed_keys}
    return public


def _public_text(value: str | None) -> str | None:
    if value is None:
        return None
    redacted = _public_payload(value)
    return redacted if isinstance(redacted, str) else None


def _public_path(value: str | None) -> str | None:
    if value is None:
        return None
    redacted = _public_payload(value)
    return redacted if isinstance(redacted, str) else None


def _public_payload(value: Any) -> Any:
    redacted, _paths = redact_value(value)
    return redacted


def _production_safe(active_settings: Settings) -> bool:
    return active_settings.ENVIRONMENT != "local"

"""Provider status routes for the template Workbench API."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Request

from app.api.deps import CurrentUser, SessionDep
from app.core.config import settings
from app.models import (
    AnalysisRun,
    ProviderSnapshot,
    ProviderSnapshotStatusPublic,
    ProviderSourceStatusPublic,
    ProviderStatusPublic,
    ProviderUpdateJobPublic,
)
from app.models.base import get_datetime_utc
from app.repositories import RunRepository

router = APIRouter(prefix="/providers", tags=["providers"])

PROVIDER_SOURCES = ("nvd", "epss", "kev")
NO_PROVIDER_SNAPSHOT_WARNING = "No provider snapshot has been recorded yet."


@router.get("/status", response_model=ProviderStatusPublic)
def read_provider_status(
    request: Request,
    session: SessionDep,
    _current_user: CurrentUser,
) -> ProviderStatusPublic:
    """Return provider status from the latest stored SQLModel provider snapshot."""
    repository = RunRepository(session)
    snapshot = repository.get_latest_provider_snapshot()
    failed_update_run = repository.get_latest_failed_provider_update_run()
    return _provider_status_payload(
        snapshot,
        failed_update_run=failed_update_run,
        active_settings=_request_settings(request),
    )


def _provider_status_payload(
    snapshot: ProviderSnapshot | None,
    *,
    failed_update_run: AnalysisRun | None,
    active_settings: object,
) -> ProviderStatusPublic:
    metadata = _snapshot_metadata(snapshot)
    warnings = _string_list(metadata.get("warnings"))
    failed_update_error = _failed_update_error(failed_update_run)
    last_error = failed_update_error or _last_error(metadata)
    snapshot_status = _snapshot_status(snapshot, metadata)
    if snapshot is None:
        warnings.append(NO_PROVIDER_SNAPSHOT_WARNING)
    if failed_update_error is not None:
        warnings.append(f"Latest provider update failed: {failed_update_error}")

    degraded = snapshot_status.missing or last_error is not None
    return ProviderStatusPublic(
        status="degraded" if degraded else "ok",
        snapshot=snapshot_status,
        sources=_source_statuses(snapshot, snapshot_status.selected_sources, last_error=last_error),
        latest_update_job=_provider_update_job(failed_update_run),
        cache_dir=(
            _string_or_none(metadata.get("cache_dir"))
            or _settings_path(active_settings, "provider_cache_dir", "PROVIDER_CACHE_DIR")
        ),
        snapshot_dir=_string_or_none(metadata.get("snapshot_dir"))
        or _settings_path(
            active_settings,
            "provider_snapshot_dir",
            "PROVIDER_SNAPSHOT_DIR",
        ),
        warnings=warnings,
        last_sync=_last_sync(snapshot, metadata),
        last_error=last_error,
        cache_age_seconds=_cache_age_seconds(snapshot.created_at if snapshot is not None else None),
        snapshot_mode=_snapshot_mode(snapshot, metadata),
    )


def _snapshot_status(
    snapshot: ProviderSnapshot | None,
    metadata: dict[str, Any],
) -> ProviderSnapshotStatusPublic:
    if snapshot is None:
        return ProviderSnapshotStatusPublic()

    source_hashes = _dict_value(snapshot.source_hashes_json)
    selected_sources = _selected_sources(snapshot, metadata, source_hashes)
    snapshot_mode = _snapshot_mode(snapshot, metadata)
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
        source_hashes=source_hashes,
        source_metadata=metadata,
        source_path=_source_path(metadata),
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
    details = {
        "nvd": "NVD last modified timestamp from the latest stored snapshot.",
        "epss": "EPSS date from the latest stored snapshot.",
        "kev": "Latest KEV date_added value from the latest stored snapshot.",
    }
    selected = set(selected_sources)
    return [
        ProviderSourceStatusPublic(
            name=name,
            selected=name in selected,
            available=values[name] is not None,
            value=values[name],
            last_sync=values[name],
            last_error=last_error,
            detail=details[name],
        )
        for name in PROVIDER_SOURCES
    ]


def _provider_update_job(run: AnalysisRun | None) -> ProviderUpdateJobPublic | None:
    if run is None:
        return None
    metadata = _dict_value(run.summary_json) or _dict_value(run.error_json)
    return ProviderUpdateJobPublic(
        id=str(run.id),
        status=str(run.status),
        requested_sources=_string_list(
            metadata.get("requested_sources") or metadata.get("sources")
        ),
        started_at=_iso_datetime(run.started_at),
        finished_at=_iso_datetime(run.finished_at),
        error_message=_failed_update_error(run),
        metadata_=metadata,
    )


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
    if run.error_message:
        return run.error_message
    error_json = _dict_value(run.error_json)
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


def _request_settings(request: Request) -> object:
    return getattr(request.app.state, "template_settings", settings)


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

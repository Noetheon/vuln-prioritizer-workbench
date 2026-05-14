"""Provider update-job orchestration."""

from __future__ import annotations

import hashlib
import json
import os
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import timedelta
from pathlib import Path
from typing import Any

from pydantic import ValidationError
from sqlalchemy.engine import Engine
from sqlmodel import Session, col, select

from app.core.config import Settings
from app.models import (
    AnalysisRun,
    AnalysisRunStatus,
    Finding,
    Project,
    ProviderUpdateJobCreate,
)
from app.models.base import get_datetime_utc
from app.repositories import RunRepository
from vuln_prioritizer.cache import FileCache
from vuln_prioritizer.config import DEFAULT_CACHE_TTL_HOURS, DEFAULT_NVD_API_KEY_ENV
from vuln_prioritizer.models import (
    EpssData,
    KevData,
    NvdData,
    ProviderSnapshotItem,
    ProviderSnapshotMetadata,
    ProviderSnapshotReport,
)
from vuln_prioritizer.provider_snapshot import (
    generate_provider_snapshot_json,
    load_provider_snapshot,
    snapshot_items_by_cve,
)
from vuln_prioritizer.providers.epss import EpssProvider
from vuln_prioritizer.providers.kev import KevProvider
from vuln_prioritizer.providers.nvd import NvdProvider
from vuln_prioritizer.security_redaction import redact_value
from vuln_prioritizer.utils import iso_utc_now, normalize_cve_id

PROVIDER_UPDATE_INPUT_TYPE = "provider_update"
PROVIDER_UPDATE_PROJECT_NAME = "Provider Updates"
PROVIDER_UPDATE_LOCK_FILE = ".workbench-provider-update.lock"
PROVIDER_UPDATE_LOCK_STALE_SECONDS = 6 * 60 * 60
VALID_PROVIDER_SOURCES = ("nvd", "epss", "kev")


class ProviderUpdateConflict(RuntimeError):
    """Raised when a provider update is already active."""


class ProviderUpdateValidationError(ValueError):
    """Raised when a provider update request is invalid."""


class ProviderUpdateRefreshError(RuntimeError):
    """Raised when a live provider refresh degrades instead of producing a clean snapshot."""


def create_provider_update_job(
    session: Session,
    *,
    settings: Settings,
    payload: ProviderUpdateJobCreate,
) -> AnalysisRun:
    """Create and synchronously execute a deterministic cache-friendly update job."""
    repository = RunRepository(session)
    if repository.get_running_provider_update_run() is not None:
        raise ProviderUpdateConflict(
            "Provider update already running; retry after the active job finishes."
        )

    selected_sources, cve_ids = _provider_update_request_inputs(session, payload=payload)
    run = _create_provider_update_run(
        repository,
        session=session,
        selected_sources=selected_sources,
        cve_ids=cve_ids,
        cache_only=payload.cache_only,
        status=AnalysisRunStatus.RUNNING,
        execution_mode="request",
    )
    return _execute_provider_update_run(
        session=session,
        repository=repository,
        run=run,
        settings=settings,
        selected_sources=selected_sources,
        cve_ids=cve_ids,
        cache_only=payload.cache_only,
        execution_mode="request",
        fail_conflicts=False,
    )


def enqueue_provider_update_job(
    session: Session,
    *,
    settings: Settings,
    payload: ProviderUpdateJobCreate,
) -> AnalysisRun:
    """Create a provider update job that can be resumed outside the request path."""
    repository = RunRepository(session)
    if repository.get_running_provider_update_run() is not None:
        raise ProviderUpdateConflict(
            "Provider update already running; retry after the active job finishes."
        )
    _reject_active_provider_update_lock(settings.provider_snapshot_dir_path)
    selected_sources, cve_ids = _provider_update_request_inputs(session, payload=payload)
    return _create_provider_update_run(
        repository,
        session=session,
        selected_sources=selected_sources,
        cve_ids=cve_ids,
        cache_only=payload.cache_only,
        status=AnalysisRunStatus.PENDING,
        execution_mode="background",
    )


def execute_provider_update_job_background(
    engine: Engine,
    settings: Settings,
    payload: ProviderUpdateJobCreate,
    run_id: uuid.UUID,
) -> None:
    """Resume a queued provider update job outside the request/response path."""
    with Session(engine) as session:
        try:
            resume_provider_update_job(
                session,
                settings=settings,
                payload=payload,
                run_id=run_id,
            )
            session.commit()
        except Exception:
            session.rollback()
            mark_provider_update_job_background_failed(session=session, run_id=run_id)


def resume_provider_update_job(
    session: Session,
    *,
    settings: Settings,
    payload: ProviderUpdateJobCreate,
    run_id: uuid.UUID,
) -> AnalysisRun | None:
    """Execute a pending provider update job in the current session."""
    repository = RunRepository(session)
    run = repository.get_analysis_run(run_id)
    if run is None or run.input_type != PROVIDER_UPDATE_INPUT_TYPE:
        return None
    if run.status not in {AnalysisRunStatus.PENDING, AnalysisRunStatus.RUNNING}:
        return run

    selected_sources, cve_ids = _provider_update_request_inputs(session, payload=payload)
    run.status = AnalysisRunStatus.RUNNING
    run.summary_json = {
        **_dict_payload(run.summary_json),
        "requested_sources": selected_sources,
        "requested_cves": len(cve_ids),
        "cache_only": payload.cache_only,
        "execution_mode": "background",
        "mode": "workbench-provider-update",
    }
    session.add(run)
    session.flush()
    return _execute_provider_update_run(
        session=session,
        repository=repository,
        run=run,
        settings=settings,
        selected_sources=selected_sources,
        cve_ids=cve_ids,
        cache_only=payload.cache_only,
        execution_mode="background",
        fail_conflicts=True,
    )


def reconcile_stale_provider_update_runs(
    *,
    engine: Engine,
    settings: Settings,
) -> int:
    """Fail stale provider update rows that could otherwise block future updates."""
    stale_before = get_datetime_utc() - timedelta(minutes=settings.PROVIDER_UPDATE_STALE_MINUTES)
    reconciled = 0
    with Session(engine) as session:
        repository = RunRepository(session)
        for run in repository.list_active_analysis_runs_started_before(stale_before):
            if run.input_type != PROVIDER_UPDATE_INPUT_TYPE:
                continue
            failed = mark_provider_update_job_background_failed(
                session=session,
                run_id=run.id,
                error_message=(
                    "Provider update did not finish before the Workbench process restarted."
                ),
            )
            if failed is not None and failed.status == AnalysisRunStatus.FAILED:
                reconciled += 1
    return reconciled


def mark_provider_update_job_background_failed(
    *,
    session: Session,
    run_id: uuid.UUID,
    error_message: str = "Provider update execution failed.",
) -> AnalysisRun | None:
    """Mark an unfinished provider update failed when background execution exits."""
    repository = RunRepository(session)
    run = repository.get_analysis_run(run_id)
    if run is None or run.status not in {AnalysisRunStatus.PENDING, AnalysisRunStatus.RUNNING}:
        return run
    metadata = _dict_payload(run.summary_json)
    failed = _mark_provider_update_run_failed(
        session=session,
        run=run,
        selected_sources=_string_list(metadata.get("requested_sources")),
        requested_cves=_int_value(metadata.get("requested_cves")),
        cache_only=bool(metadata.get("cache_only", True)),
        execution_mode=str(metadata.get("execution_mode") or "background"),
        error_message=error_message,
        detail="Provider refresh failed before replacing or mutating existing snapshots.",
    )
    session.commit()
    return failed


def _execute_provider_update_run(
    *,
    session: Session,
    repository: RunRepository,
    run: AnalysisRun,
    settings: Settings,
    selected_sources: list[str],
    cve_ids: list[str],
    cache_only: bool,
    execution_mode: str,
    fail_conflicts: bool,
) -> AnalysisRun:
    try:
        with _provider_update_lock(settings.provider_snapshot_dir_path):
            if _other_running_update(repository, run.id) is not None:
                raise ProviderUpdateConflict(
                    "Provider update already running; retry after the active job finishes."
                )
            snapshot, metadata = _write_provider_snapshot(
                repository,
                settings=settings,
                selected_sources=selected_sources,
                cve_ids=cve_ids,
                cache_only=cache_only,
            )
    except ProviderUpdateConflict as exc:
        if fail_conflicts:
            return _mark_provider_update_run_failed(
                session=session,
                run=run,
                selected_sources=selected_sources,
                requested_cves=len(cve_ids),
                cache_only=cache_only,
                execution_mode=execution_mode,
                error_message=str(exc),
                detail="Provider refresh did not start because another job was active.",
            )
        raise
    except Exception as exc:
        return _mark_provider_update_run_failed(
            session=session,
            run=run,
            selected_sources=selected_sources,
            requested_cves=len(cve_ids),
            cache_only=cache_only,
            execution_mode=execution_mode,
            error_message=str(exc),
            detail="Provider refresh failed before replacing or mutating existing snapshots.",
        )

    metadata = {
        **metadata,
        "requested_sources": selected_sources,
        "requested_cves": len(cve_ids),
        "cache_only": cache_only,
        "execution_mode": execution_mode,
        "provider_snapshot_id": str(snapshot.id),
    }
    run.provider_snapshot_id = snapshot.id
    run.status = AnalysisRunStatus.COMPLETED
    run.finished_at = get_datetime_utc()
    run.summary_json = _redacted_payload(metadata)
    session.add(run)
    session.flush()
    return run


def _provider_update_request_inputs(
    session: Session,
    *,
    payload: ProviderUpdateJobCreate,
) -> tuple[list[str], list[str]]:
    return _normalize_sources(payload.sources), _provider_update_cve_ids(session, payload=payload)


def _create_provider_update_run(
    repository: RunRepository,
    *,
    session: Session,
    selected_sources: list[str],
    cve_ids: list[str],
    cache_only: bool,
    status: AnalysisRunStatus,
    execution_mode: str,
) -> AnalysisRun:
    project = _provider_update_project(session)
    return repository.create_analysis_run(
        project_id=project.id,
        input_type=PROVIDER_UPDATE_INPUT_TYPE,
        status=status,
        summary_json={
            "requested_sources": selected_sources,
            "requested_cves": len(cve_ids),
            "cache_only": cache_only,
            "execution_mode": execution_mode,
            "mode": "workbench-provider-update",
        },
    )


def _mark_provider_update_run_failed(
    *,
    session: Session,
    run: AnalysisRun,
    selected_sources: list[str],
    requested_cves: int,
    cache_only: bool,
    execution_mode: str,
    error_message: str,
    detail: str,
) -> AnalysisRun:
    failed_metadata = {
        "requested_sources": selected_sources,
        "requested_cves": requested_cves,
        "cache_only": cache_only,
        "execution_mode": execution_mode,
        "snapshot_created": False,
        "detail": detail,
    }
    run.status = AnalysisRunStatus.FAILED
    run.finished_at = get_datetime_utc()
    run.error_message = error_message
    run.error_json = _redacted_payload({"detail": error_message})
    run.summary_json = _redacted_payload(failed_metadata)
    session.add(run)
    session.flush()
    return run


def _normalize_sources(raw_sources: list[str]) -> list[str]:
    selected_sources: list[str] = []
    invalid_sources: list[str] = []
    for value in raw_sources:
        source = value.strip().lower()
        if source not in VALID_PROVIDER_SOURCES:
            invalid_sources.append(value)
            continue
        if source not in selected_sources:
            selected_sources.append(source)
    if invalid_sources:
        raise ProviderUpdateValidationError(
            "Invalid provider source(s): " + ", ".join(invalid_sources)
        )
    if not selected_sources:
        raise ProviderUpdateValidationError("At least one provider source is required.")
    return selected_sources


def _provider_update_cve_ids(
    session: Session,
    *,
    payload: ProviderUpdateJobCreate,
) -> list[str]:
    explicit_cves: list[str] = []
    invalid_cves: list[str] = []
    for value in payload.cve_ids:
        normalized = normalize_cve_id(value)
        if normalized is None:
            invalid_cves.append(value)
        elif normalized not in explicit_cves:
            explicit_cves.append(normalized)
    if invalid_cves:
        raise ProviderUpdateValidationError("Invalid CVE id(s): " + ", ".join(invalid_cves))

    if explicit_cves:
        cve_ids = explicit_cves
    else:
        statement = select(Finding.cve_id).order_by(col(Finding.cve_id))
        cve_ids = list(dict.fromkeys(session.exec(statement).all()))
    if payload.max_cves is not None:
        return cve_ids[: payload.max_cves]
    return cve_ids


def _provider_update_project(session: Session) -> Project:
    statement = select(Project).where(Project.name == PROVIDER_UPDATE_PROJECT_NAME)
    project = session.exec(statement).first()
    if project is not None:
        return project
    project = Project(
        name=PROVIDER_UPDATE_PROJECT_NAME,
        description="System project for global provider update jobs.",
    )
    session.add(project)
    session.flush()
    return project


def _other_running_update(repository: RunRepository, run_id: uuid.UUID) -> AnalysisRun | None:
    active_run = repository.get_running_provider_update_run()
    if active_run is None or active_run.id == run_id:
        return None
    return active_run


def _write_provider_snapshot(
    repository: RunRepository,
    *,
    settings: Settings,
    selected_sources: list[str],
    cve_ids: list[str],
    cache_only: bool,
) -> tuple[Any, dict[str, Any]]:
    snapshot_id = uuid.uuid4().hex
    snapshot_root = settings.provider_snapshot_dir_path
    snapshot_root.mkdir(parents=True, exist_ok=True)
    output_path = snapshot_root / f"provider-snapshot-{snapshot_id}.json"
    output_label = output_path.name
    generated_at = iso_utc_now()
    cache = FileCache(settings.provider_cache_dir_path, DEFAULT_CACHE_TTL_HOURS)
    baseline_items, baseline_warnings = _load_latest_snapshot_items(
        repository.get_latest_provider_snapshot(),
        settings=settings,
    )
    warnings = list(baseline_warnings)
    refresh_warnings: list[str] = []
    source_counts: dict[str, dict[str, int]] = {}
    nvd_results: dict[str, NvdData] = {}
    epss_results: dict[str, EpssData] = {}
    kev_results: dict[str, KevData] = {}
    if "nvd" in selected_sources:
        nvd_results, source_warnings, source_counts["nvd"] = _provider_records_for_snapshot(
            source="nvd",
            cve_ids=cve_ids,
            cache=cache,
            cache_only=cache_only,
            baseline_items=baseline_items,
            nvd_api_key_env=settings.NVD_API_KEY_ENV,
        )
        warnings.extend(source_warnings)
        refresh_warnings.extend(source_warnings if not cache_only else [])
    if "epss" in selected_sources:
        epss_results, source_warnings, source_counts["epss"] = _provider_records_for_snapshot(
            source="epss",
            cve_ids=cve_ids,
            cache=cache,
            cache_only=cache_only,
            baseline_items=baseline_items,
        )
        warnings.extend(source_warnings)
        refresh_warnings.extend(source_warnings if not cache_only else [])
    if "kev" in selected_sources:
        kev_results, source_warnings, source_counts["kev"] = _provider_records_for_snapshot(
            source="kev",
            cve_ids=cve_ids,
            cache=cache,
            cache_only=cache_only,
            baseline_items=baseline_items,
        )
        warnings.extend(source_warnings)
        refresh_warnings.extend(source_warnings if not cache_only else [])

    source_hashes = _provider_cache_source_hashes(cache, selected_sources)
    report = ProviderSnapshotReport(
        metadata=ProviderSnapshotMetadata(
            snapshot_id=snapshot_id,
            generated_at=generated_at,
            input_paths=[],
            input_format="workbench-current-findings",
            selected_sources=selected_sources,
            requested_cves=len(cve_ids),
            output_path=output_label,
            cache_enabled=True,
            cache_only=cache_only,
            cache_dir=None,
            source_hashes=source_hashes,
            source_metadata=_provider_source_metadata(
                selected_sources=selected_sources,
                source_hashes=source_hashes,
                source_counts=source_counts,
                cache_only=cache_only,
            ),
            nvd_api_key_env=settings.NVD_API_KEY_ENV,
        ),
        items=[
            ProviderSnapshotItem(
                cve_id=cve_id,
                nvd=nvd_results.get(cve_id) if "nvd" in selected_sources else None,
                epss=epss_results.get(cve_id) if "epss" in selected_sources else None,
                kev=kev_results.get(cve_id) if "kev" in selected_sources else None,
            )
            for cve_id in cve_ids
        ],
        warnings=[
            *warnings,
            *(["No CVEs were available for provider snapshot refresh."] if not cve_ids else []),
        ],
    )
    refresh_failure = _provider_refresh_failure(
        selected_sources=selected_sources,
        cache_only=cache_only,
        refresh_warnings=refresh_warnings,
    )
    if refresh_failure is not None:
        raise ProviderUpdateRefreshError(refresh_failure)
    document = generate_provider_snapshot_json(report)
    output_path.write_text(document, encoding="utf-8")
    content_hash = hashlib.sha256(document.encode("utf-8")).hexdigest()
    metadata_json = report.metadata.model_dump()
    metadata_json.update(
        {
            "source_path": output_label,
            "snapshot_file": output_label,
            "item_count": len(report.items),
            "warnings": report.warnings,
            "missing": False,
            "generated_by": "workbench-provider-update-job",
            "snapshot_mode": "cache-only" if cache_only else "snapshot",
        }
    )
    try:
        snapshot = repository.get_or_create_provider_snapshot(
            content_hash=content_hash,
            nvd_last_sync=_latest_nvd_sync(nvd_results.values()),
            epss_date=_latest_epss_date(epss_results.values()),
            kev_catalog_version=_latest_kev_date(kev_results.values()),
            source_hashes_json={"provider_snapshot": content_hash},
            source_metadata_json=metadata_json,
        )
    except Exception:
        output_path.unlink(missing_ok=True)
        raise
    return snapshot, {
        "mode": "workbench-provider-update",
        "snapshot_created": True,
        "snapshot_file": output_label,
        "snapshot_sha256": content_hash,
        "selected_sources": selected_sources,
        "requested_cves": len(cve_ids),
        "source_counts": source_counts,
        "warnings": report.warnings,
    }


def _provider_refresh_failure(
    *,
    selected_sources: list[str],
    cache_only: bool,
    refresh_warnings: list[str],
) -> str | None:
    if cache_only or not refresh_warnings:
        return None
    warning_text = "; ".join(refresh_warnings[:3])
    suffix = " ..." if len(refresh_warnings) > 3 else ""
    return (
        "Provider refresh returned degraded live data for source(s) "
        + ", ".join(selected_sources)
        + f": {warning_text}{suffix}"
    )


def _load_latest_snapshot_items(
    latest_snapshot: Any | None,
    *,
    settings: Settings,
) -> tuple[dict[str, ProviderSnapshotItem], list[str]]:
    if latest_snapshot is None:
        return {}, []
    metadata = (
        latest_snapshot.source_metadata_json
        if isinstance(latest_snapshot.source_metadata_json, dict)
        else {}
    )
    path_value = (
        metadata.get("snapshot_file") or metadata.get("source_path") or metadata.get("output_path")
    )
    if not isinstance(path_value, str) or not path_value or path_value == "[REDACTED]":
        return {}, ["Latest provider snapshot has no reusable source artifact path."]
    path = Path(path_value)
    snapshot_root = settings.provider_snapshot_dir_path.resolve(strict=False)
    if not path.is_absolute():
        path = snapshot_root / path
    candidate = path.resolve(strict=False)
    if not candidate.is_relative_to(snapshot_root):
        return {}, ["Latest provider snapshot artifact path is outside the snapshot directory."]
    if not candidate.is_file():
        return {}, ["Latest provider snapshot artifact is no longer available on disk."]
    try:
        return snapshot_items_by_cve(load_provider_snapshot(candidate)), []
    except ValueError as exc:
        return {}, [f"Latest provider snapshot artifact could not be reused: {exc}"]


def _provider_records_for_snapshot(
    *,
    source: str,
    cve_ids: list[str],
    cache: FileCache,
    cache_only: bool,
    baseline_items: dict[str, ProviderSnapshotItem],
    nvd_api_key_env: str = DEFAULT_NVD_API_KEY_ENV,
) -> tuple[dict[str, Any], list[str], dict[str, int]]:
    warnings: list[str] = []
    if cache_only:
        fetched, warnings = _cached_provider_records(source=source, cache=cache, cve_ids=cve_ids)
    elif source == "nvd":
        fetched, warnings = NvdProvider.from_env(
            api_key_env=nvd_api_key_env,
            cache=cache,
        ).fetch_many(cve_ids, refresh=True)
    elif source == "epss":
        fetched, warnings = EpssProvider(cache=cache).fetch_many(cve_ids, refresh=True)
    else:
        fetched, warnings = KevProvider(cache=cache).fetch_many(cve_ids, refresh=True)

    merged: dict[str, Any] = {}
    fallback_count = 0
    missing_count = 0
    for cve_id in cve_ids:
        if cve_id in fetched:
            merged[cve_id] = fetched[cve_id]
            continue
        baseline_item = baseline_items.get(cve_id)
        baseline_value = getattr(baseline_item, source, None) if baseline_item is not None else None
        if baseline_value is not None:
            merged[cve_id] = baseline_value
            fallback_count += 1
            continue
        missing_count += 1
    if missing_count:
        warnings.append(f"{source.upper()} data missing for {missing_count} CVE(s).")
    return (
        merged,
        warnings,
        {
            "records": len(merged),
            "fetched": len(fetched),
            "fallback_from_previous_snapshot": fallback_count,
            "missing": missing_count,
        },
    )


def _cached_provider_records(
    *,
    source: str,
    cache: FileCache,
    cve_ids: list[str],
) -> tuple[dict[str, Any], list[str]]:
    if source == "kev":
        cached_catalog = cache.get_json("kev", "catalog")
        if not isinstance(cached_catalog, dict):
            return {}, ["Cache-only KEV catalog is missing from the local cache."]
        return _cached_kev_records(cached_catalog, cve_ids)

    model = NvdData if source == "nvd" else EpssData
    records: dict[str, Any] = {}
    invalid: list[str] = []
    for cve_id in cve_ids:
        cached_payload = cache.get_json(source, cve_id)
        if cached_payload is None:
            continue
        try:
            records[cve_id] = model.model_validate(cached_payload)
        except ValidationError:
            invalid.append(cve_id)
    warnings = (
        [f"Cache-only {source.upper()} data invalid for CVE(s): " + ", ".join(invalid) + "."]
        if invalid
        else []
    )
    return records, warnings


def _cached_kev_records(
    cached_catalog: dict[str, Any],
    cve_ids: list[str],
) -> tuple[dict[str, KevData], list[str]]:
    records: dict[str, KevData] = {}
    invalid: list[str] = []
    for cve_id in cve_ids:
        item = cached_catalog.get(cve_id)
        if item is None:
            continue
        try:
            records[cve_id] = KevData.model_validate(item)
        except ValidationError:
            invalid.append(cve_id)
    warnings = (
        ["Cache-only KEV data invalid for CVE(s): " + ", ".join(invalid) + "."] if invalid else []
    )
    return records, warnings


def _provider_cache_source_hashes(
    cache: FileCache,
    selected_sources: list[str],
) -> dict[str, str | None]:
    return {
        source: cache.inspect_namespace(source)["namespace_checksum"]
        for source in selected_sources
        if source in VALID_PROVIDER_SOURCES
    }


def _provider_source_metadata(
    *,
    selected_sources: list[str],
    source_hashes: dict[str, str | None],
    source_counts: dict[str, dict[str, int]],
    cache_only: bool,
) -> dict[str, dict[str, str | int | bool | None]]:
    source_labels = {
        "nvd": "NVD CVE API 2.0",
        "epss": "FIRST EPSS API",
        "kev": "CISA KEV catalog",
    }
    return {
        source: {
            "source": source_labels[source],
            "record_count": source_counts.get(source, {}).get("records", 0),
            "fetched_count": source_counts.get(source, {}).get("fetched", 0),
            "fallback_from_previous_snapshot": source_counts.get(source, {}).get(
                "fallback_from_previous_snapshot",
                0,
            ),
            "missing_count": source_counts.get(source, {}).get("missing", 0),
            "cache_only": cache_only,
            "cache_namespace_hash": source_hashes.get(source),
        }
        for source in selected_sources
        if source in source_labels
    }


def _latest_nvd_sync(records: Any) -> str | None:
    values = [
        value for record in records for value in (record.last_modified, record.published) if value
    ]
    return sorted(values)[-1] if values else None


def _latest_epss_date(records: Any) -> str | None:
    values = [record.date for record in records if record.date]
    return sorted(values)[-1] if values else None


def _latest_kev_date(records: Any) -> str | None:
    values = [record.date_added for record in records if record.date_added]
    return sorted(values)[-1] if values else None


@contextmanager
def _provider_update_lock(snapshot_root: Path) -> Iterator[Path]:
    """Acquire a local lock around snapshot writes."""
    snapshot_root.mkdir(parents=True, exist_ok=True)
    lock_path = snapshot_root / PROVIDER_UPDATE_LOCK_FILE
    descriptor: int | None = None
    try:
        descriptor = _open_provider_update_lock(lock_path)
        os.write(
            descriptor,
            json.dumps(
                {
                    "pid": os.getpid(),
                    "created_at": iso_utc_now(),
                    "stale_after_seconds": PROVIDER_UPDATE_LOCK_STALE_SECONDS,
                },
                sort_keys=True,
            ).encode("utf-8"),
        )
        yield lock_path
    finally:
        if descriptor is not None:
            os.close(descriptor)
            lock_path.unlink(missing_ok=True)


def _reject_active_provider_update_lock(snapshot_root: Path) -> None:
    snapshot_root.mkdir(parents=True, exist_ok=True)
    lock_path = snapshot_root / PROVIDER_UPDATE_LOCK_FILE
    if not lock_path.exists():
        return
    if _provider_update_lock_is_stale(lock_path):
        lock_path.unlink(missing_ok=True)
        return
    raise ProviderUpdateConflict(
        "Provider update already running; retry after the active job finishes."
    )


def _open_provider_update_lock(lock_path: Path) -> int:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    try:
        return os.open(lock_path, flags, 0o600)
    except FileExistsError as exc:
        if _provider_update_lock_is_stale(lock_path):
            lock_path.unlink(missing_ok=True)
            try:
                return os.open(lock_path, flags, 0o600)
            except FileExistsError:
                pass
        raise ProviderUpdateConflict(
            "Provider update already running; retry after the active job finishes."
        ) from exc


def _provider_update_lock_is_stale(lock_path: Path) -> bool:
    try:
        return time.time() - lock_path.stat().st_mtime > PROVIDER_UPDATE_LOCK_STALE_SECONDS
    except OSError:
        return False


def _dict_payload(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def _int_value(value: Any) -> int:
    if isinstance(value, int):
        return value
    return 0


def _redacted_payload(payload: dict[str, Any]) -> dict[str, Any]:
    redacted, _paths = redact_value(payload)
    return redacted if isinstance(redacted, dict) else {}

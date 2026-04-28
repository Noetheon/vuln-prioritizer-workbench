"""Provider snapshot status and refresh-job helpers for Workbench routes."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any
from uuid import uuid4

from fastapi import HTTPException
from pydantic import ValidationError

from vuln_prioritizer.api.schemas import (
    ProviderSnapshotStatus,
    ProviderSourceStatus,
    ProviderStatusResponse,
    ProviderUpdateJobRequest,
)
from vuln_prioritizer.cache import FileCache
from vuln_prioritizer.config import DEFAULT_CACHE_TTL_HOURS
from vuln_prioritizer.db.repositories import WorkbenchRepository
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
from vuln_prioritizer.utils import iso_utc_now, normalize_cve_id
from vuln_prioritizer.workbench_config import WorkbenchSettings


def _create_provider_update_job_record(
    *,
    repo: WorkbenchRepository,
    settings: WorkbenchSettings,
    payload: ProviderUpdateJobRequest,
) -> Any:
    latest_snapshot = repo.get_latest_provider_snapshot()
    previous_metadata = {
        "snapshot_preserved": latest_snapshot is not None,
        "previous_snapshot_id": latest_snapshot.id if latest_snapshot is not None else None,
        "previous_snapshot_hash": latest_snapshot.content_hash
        if latest_snapshot is not None
        else None,
    }
    try:
        snapshot, refresh_metadata = _run_provider_snapshot_refresh(
            repo=repo,
            settings=settings,
            payload=payload,
            latest_snapshot=latest_snapshot,
        )
        metadata = {
            "mode": "synchronous-local-snapshot-refresh",
            **previous_metadata,
            **refresh_metadata,
            "new_snapshot_id": snapshot.id if snapshot is not None else None,
            "new_snapshot_hash": snapshot.content_hash if snapshot is not None else None,
        }
        status = "completed"
        error_message = None
    except HTTPException:
        raise
    except Exception as exc:
        metadata = {
            "mode": "synchronous-local-snapshot-refresh",
            **previous_metadata,
            "snapshot_created": False,
            "detail": "Provider refresh failed before replacing or mutating existing snapshots.",
        }
        status = "failed"
        error_message = str(exc)
    job = repo.create_provider_update_job(
        status=status,
        requested_sources_json=list(payload.sources),
        metadata_json=metadata,
        error_message=error_message,
    )
    return job


def _run_provider_snapshot_refresh(
    *,
    repo: WorkbenchRepository,
    settings: WorkbenchSettings,
    payload: ProviderUpdateJobRequest,
    latest_snapshot: Any | None,
) -> tuple[Any | None, dict[str, Any]]:
    selected_sources: list[str] = list(dict.fromkeys(payload.sources))
    cve_ids = _provider_update_cve_ids(repo, payload=payload)
    if not cve_ids:
        return None, {
            "snapshot_created": False,
            "selected_sources": selected_sources,
            "requested_cves": 0,
            "cache_only": payload.cache_only,
            "warnings": ["No CVEs were available for provider snapshot refresh."],
        }

    baseline_items, baseline_warnings = _load_latest_snapshot_items(latest_snapshot)
    cache = FileCache(settings.provider_cache_dir, DEFAULT_CACHE_TTL_HOURS)
    warnings = list(baseline_warnings)
    source_counts: dict[str, dict[str, int]] = {}

    nvd_results: dict[str, NvdData] = {}
    epss_results: dict[str, EpssData] = {}
    kev_results: dict[str, KevData] = {}
    if "nvd" in selected_sources:
        nvd_results, source_warnings, source_counts["nvd"] = _provider_records_for_snapshot(
            source="nvd",
            cve_ids=cve_ids,
            cache=cache,
            cache_only=payload.cache_only,
            baseline_items=baseline_items,
            settings=settings,
        )
        warnings.extend(source_warnings)
    if "epss" in selected_sources:
        epss_results, source_warnings, source_counts["epss"] = _provider_records_for_snapshot(
            source="epss",
            cve_ids=cve_ids,
            cache=cache,
            cache_only=payload.cache_only,
            baseline_items=baseline_items,
            settings=settings,
        )
        warnings.extend(source_warnings)
    if "kev" in selected_sources:
        kev_results, source_warnings, source_counts["kev"] = _provider_records_for_snapshot(
            source="kev",
            cve_ids=cve_ids,
            cache=cache,
            cache_only=payload.cache_only,
            baseline_items=baseline_items,
            settings=settings,
        )
        warnings.extend(source_warnings)

    output_path = settings.provider_snapshot_dir / f"workbench-provider-snapshot-{uuid4().hex}.json"
    report = ProviderSnapshotReport(
        metadata=ProviderSnapshotMetadata(
            generated_at=iso_utc_now(),
            input_paths=[],
            input_format="workbench-current-findings",
            selected_sources=selected_sources,
            requested_cves=len(cve_ids),
            output_path=str(output_path),
            cache_enabled=True,
            cache_only=payload.cache_only,
            cache_dir=str(settings.provider_cache_dir),
            nvd_api_key_env=settings.nvd_api_key_env,
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
        warnings=warnings,
    )
    document = generate_provider_snapshot_json(report)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(document, encoding="utf-8")
    content_hash = hashlib.sha256(document.encode("utf-8")).hexdigest()
    existing_snapshot = repo.get_provider_snapshot_by_hash(content_hash)
    if existing_snapshot is not None:
        snapshot = existing_snapshot
    else:
        metadata_json = report.metadata.model_dump()
        metadata_json.update(
            {
                "source_path": str(output_path),
                "item_count": len(report.items),
                "warnings": warnings,
                "missing": False,
                "generated_by": "provider-update-job",
                "source_counts": source_counts,
            }
        )
        snapshot = repo.create_provider_snapshot(
            content_hash=content_hash,
            nvd_last_sync=_latest_nvd_sync(nvd_results.values()),
            epss_date=_latest_epss_date(epss_results.values()),
            kev_catalog_version=_latest_kev_date(kev_results.values()),
            metadata_json=metadata_json,
        )
    return snapshot, {
        "snapshot_created": True,
        "snapshot_path": str(output_path),
        "snapshot_sha256": content_hash,
        "selected_sources": selected_sources,
        "requested_cves": len(cve_ids),
        "cache_only": payload.cache_only,
        "source_counts": source_counts,
        "warnings": warnings,
    }


def _provider_update_cve_ids(
    repo: WorkbenchRepository,
    *,
    payload: ProviderUpdateJobRequest,
) -> list[str]:
    explicit_cves: list[str] = []
    invalid_cves: list[str] = []
    for value in payload.cve_ids:
        normalized = normalize_cve_id(value)
        if normalized is None:
            invalid_cves.append(value)
        else:
            explicit_cves.append(normalized)
    if invalid_cves:
        raise HTTPException(
            status_code=422,
            detail="Invalid CVE id(s): " + ", ".join(invalid_cves),
        )
    cve_ids = explicit_cves
    if not cve_ids:
        cve_ids = [
            finding.cve_id
            for project in repo.list_projects()
            for finding in repo.list_project_findings(project.id)
        ]
    unique_cves = sorted(dict.fromkeys(cve_ids))
    if payload.max_cves is not None:
        return unique_cves[: payload.max_cves]
    return unique_cves


def _load_latest_snapshot_items(
    latest_snapshot: Any | None,
) -> tuple[dict[str, ProviderSnapshotItem], list[str]]:
    if latest_snapshot is None:
        return {}, []
    metadata = (
        latest_snapshot.metadata_json if isinstance(latest_snapshot.metadata_json, dict) else {}
    )
    path_value = (
        metadata.get("source_path") or metadata.get("snapshot_path") or metadata.get("output_path")
    )
    if not isinstance(path_value, str) or not path_value:
        return {}, ["Latest provider snapshot has no readable source artifact path."]
    path = Path(path_value)
    if not path.is_file():
        return {}, ["Latest provider snapshot artifact is no longer available on disk."]
    try:
        return snapshot_items_by_cve(load_provider_snapshot(path)), []
    except ValueError as exc:
        return {}, [f"Latest provider snapshot artifact could not be reused: {exc}"]


def _provider_records_for_snapshot(
    *,
    source: str,
    cve_ids: list[str],
    cache: FileCache,
    cache_only: bool,
    baseline_items: dict[str, ProviderSnapshotItem],
    settings: WorkbenchSettings,
) -> tuple[dict[str, Any], list[str], dict[str, int]]:
    warnings: list[str] = []
    fetched: dict[str, Any]
    if cache_only:
        fetched, warnings = _cached_provider_records(source=source, cache=cache, cve_ids=cve_ids)
    elif source == "nvd":
        fetched, warnings = NvdProvider.from_env(
            api_key_env=settings.nvd_api_key_env,
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


def _provider_status_payload(snapshot: Any, *, settings: WorkbenchSettings) -> dict[str, Any]:
    metadata = snapshot.metadata_json if snapshot is not None else {}
    selected_sources = metadata.get("selected_sources", []) if isinstance(metadata, dict) else []
    locked_provider_data = (
        bool(metadata.get("locked_provider_data")) if isinstance(metadata, dict) else False
    )
    warnings = list(metadata.get("warnings", [])) if isinstance(metadata, dict) else []
    snapshot_status = ProviderSnapshotStatus(
        id=snapshot.id if snapshot is not None else None,
        content_hash=snapshot.content_hash if snapshot is not None else None,
        generated_at=metadata.get("generated_at") if isinstance(metadata, dict) else None,
        selected_sources=list(selected_sources),
        requested_cves=int(metadata.get("requested_cves", 0)) if isinstance(metadata, dict) else 0,
        source_path=metadata.get("source_path") if isinstance(metadata, dict) else None,
        locked_provider_data=locked_provider_data,
        missing=snapshot is None or bool(metadata.get("missing", False)),
    )
    sources = [
        ProviderSourceStatus(
            name="nvd",
            selected="nvd" in selected_sources,
            available=snapshot is not None and snapshot.nvd_last_sync is not None,
            value=snapshot.nvd_last_sync if snapshot is not None else None,
            detail="NVD last modified timestamp from the latest stored snapshot.",
        ),
        ProviderSourceStatus(
            name="epss",
            selected="epss" in selected_sources,
            available=snapshot is not None and snapshot.epss_date is not None,
            value=snapshot.epss_date if snapshot is not None else None,
            detail="EPSS date from the latest stored snapshot.",
        ),
        ProviderSourceStatus(
            name="kev",
            selected="kev" in selected_sources,
            available=snapshot is not None and snapshot.kev_catalog_version is not None,
            value=snapshot.kev_catalog_version if snapshot is not None else None,
            detail="Latest KEV date_added value from the latest stored snapshot.",
        ),
    ]
    if snapshot is None:
        warnings.append("No provider snapshot has been recorded by a Workbench import yet.")
    return ProviderStatusResponse(
        status="degraded" if snapshot is None or snapshot_status.missing else "ok",
        snapshot=snapshot_status,
        sources=sources,
        cache_dir=str(settings.provider_cache_dir),
        snapshot_dir=str(settings.provider_snapshot_dir),
        warnings=warnings,
    ).model_dump()


def _provider_update_job_payload(job: Any) -> dict[str, Any]:
    return {
        "id": job.id,
        "status": job.status,
        "requested_sources": list(job.requested_sources_json or []),
        "started_at": job.started_at.isoformat(),
        "finished_at": job.finished_at.isoformat() if job.finished_at else None,
        "error_message": job.error_message,
        "metadata": job.metadata_json or {},
    }

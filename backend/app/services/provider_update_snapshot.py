"""Provider update snapshot construction and cache projection helpers."""

from __future__ import annotations

import hashlib
import uuid
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from app.core.config import Settings
from app.repositories import RunRepository
from app.services.provider_update_constants import VALID_PROVIDER_SOURCES
from app.services.provider_update_errors import ProviderUpdateRefreshError
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
from vuln_prioritizer.utils import iso_utc_now


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


__all__ = [
    "_write_provider_snapshot",
    "_provider_refresh_failure",
    "_load_latest_snapshot_items",
    "_provider_records_for_snapshot",
    "_cached_provider_records",
    "_cached_kev_records",
    "_provider_cache_source_hashes",
    "_provider_source_metadata",
    "_latest_nvd_sync",
    "_latest_epss_date",
    "_latest_kev_date",
]

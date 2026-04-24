"""Shared output helpers for data subcommands."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import typer
from pydantic import ValidationError

from vuln_prioritizer.cache import FileCache
from vuln_prioritizer.cli_support.common import (
    TABLE_AND_JSON_OUTPUT_FORMATS,
    TableJsonOutputFormat,
    exit_input_validation,
    validate_command_formats,
    validate_output_mode,
)
from vuln_prioritizer.models import EpssData, KevData, NvdData
from vuln_prioritizer.providers.nvd import has_nvd_content
from vuln_prioritizer.reporter import write_output
from vuln_prioritizer.utils import iso_utc_now

DATA_COMMAND_SCHEMA_VERSION = "1.2.0"


def validate_data_output_options(
    *,
    command_name: str,
    format: TableJsonOutputFormat,
    output: Path | None,
    quiet: bool,
) -> None:
    """Validate shared table/json output rules for data subcommands."""
    validate_output_mode(format, output)
    validate_command_formats(
        command_name=command_name,
        format=format,
        allowed_formats=set(TABLE_AND_JSON_OUTPUT_FORMATS),
    )
    if quiet and format != TableJsonOutputFormat.json:
        exit_input_validation("--quiet can only be used together with --format json.")


def emit_data_json_payload(
    *,
    payload: dict[str, object],
    output: Path | None,
    quiet: bool,
) -> None:
    """Write and optionally print a normalized JSON payload."""
    document = json.dumps(payload, indent=2, sort_keys=True)
    if output is not None:
        write_output(output, document)
    if output is None and not quiet:
        typer.echo(document)


def build_data_status_payload(
    *,
    cache_dir: Path,
    cache_ttl_hours: int,
    output: Path | None,
    offline_kev_file: Path | None,
    statuses: list[dict[str, object]],
    attack_validation: dict[str, Any] | None,
    attack_mapping_sha256: str | None,
    attack_metadata_sha256: str | None,
    warnings: list[str],
) -> dict[str, object]:
    """Build the machine-readable `data status` payload."""
    namespace_items = [normalize_namespace_status(status) for status in statuses]
    return {
        "metadata": {
            "schema_version": DATA_COMMAND_SCHEMA_VERSION,
            "command": "data status",
            "generated_at": iso_utc_now(),
            "output_format": "json",
            "output_path": str(output) if output is not None else None,
            "cache_dir": str(cache_dir),
            "cache_ttl_hours": cache_ttl_hours,
            "kev_mode": "offline file" if offline_kev_file is not None else "live/cache",
            "offline_kev_file": str(offline_kev_file) if offline_kev_file is not None else None,
        },
        "summary": {
            "namespace_count": len(namespace_items),
            "namespace_file_count": sum(
                _coerce_int(item["file_count"]) for item in namespace_items
            ),
            "attack_enabled": attack_validation is not None,
        },
        "namespaces": namespace_items,
        "attack": (
            build_attack_validation_payload(
                validation=attack_validation,
                mapping_file_sha256=attack_mapping_sha256,
                technique_metadata_file_sha256=attack_metadata_sha256,
            )
            if attack_validation is not None
            else None
        ),
        "warnings": list(warnings),
    }


def build_data_update_payload(
    *,
    cache_dir: Path,
    cache_ttl_hours: int,
    output: Path | None,
    input_paths: list[Path],
    input_format: str,
    max_cves: int | None,
    offline_kev_file: Path | None,
    nvd_api_key_env: str,
    selected_sources: list[str],
    cve_ids: list[str],
    rows: list[dict[str, str | int | None]],
    warnings: list[str],
) -> dict[str, object]:
    """Build the machine-readable `data update` payload."""
    source_items = [normalize_update_row(row) for row in rows]
    return {
        "metadata": {
            "schema_version": DATA_COMMAND_SCHEMA_VERSION,
            "command": "data update",
            "generated_at": iso_utc_now(),
            "output_format": "json",
            "output_path": str(output) if output is not None else None,
            "cache_dir": str(cache_dir),
            "cache_ttl_hours": cache_ttl_hours,
            "input_path": str(input_paths[0]) if input_paths else None,
            "input_paths": [str(path) for path in input_paths],
            "merged_input_count": len(input_paths) if input_paths else 0,
            "input_format": input_format,
            "max_cves": max_cves,
            "offline_kev_file": str(offline_kev_file) if offline_kev_file is not None else None,
            "nvd_api_key_env": nvd_api_key_env,
        },
        "summary": {
            "selected_sources": list(selected_sources),
            "requested_cves": len(cve_ids),
            "updated_sources": len(source_items),
        },
        "requested_cve_ids": list(cve_ids),
        "sources": source_items,
        "warnings": list(warnings),
    }


def build_data_verify_payload(
    *,
    cache: FileCache,
    cache_dir: Path,
    cache_ttl_hours: int,
    output: Path | None,
    input_paths: list[Path],
    input_format: str,
    max_cves: int | None,
    offline_kev_file: Path | None,
    cve_ids: list[str],
    statuses: list[dict[str, object]],
    local_file_rows: list[dict[str, str | int]],
    attack_validation: dict[str, Any] | None,
    attack_mapping_sha256: str | None,
    attack_metadata_sha256: str | None,
    warnings: list[str],
) -> dict[str, object]:
    """Build the machine-readable `data verify` payload."""
    namespace_items = [normalize_namespace_status(status) for status in statuses]
    coverage_items = build_cache_coverage_items(cache=cache, cve_ids=cve_ids)
    local_files = [normalize_local_file_row(row) for row in local_file_rows]
    return {
        "metadata": {
            "schema_version": DATA_COMMAND_SCHEMA_VERSION,
            "command": "data verify",
            "generated_at": iso_utc_now(),
            "output_format": "json",
            "output_path": str(output) if output is not None else None,
            "cache_dir": str(cache_dir),
            "cache_ttl_hours": cache_ttl_hours,
            "input_path": str(input_paths[0]) if input_paths else None,
            "input_paths": [str(path) for path in input_paths],
            "merged_input_count": len(input_paths) if input_paths else 0,
            "input_format": input_format,
            "max_cves": max_cves,
            "kev_mode": "offline file" if offline_kev_file is not None else "live/cache",
            "offline_kev_file": str(offline_kev_file) if offline_kev_file is not None else None,
        },
        "summary": {
            "namespace_count": len(namespace_items),
            "requested_cves": len(cve_ids),
            "coverage_entries": len(coverage_items),
            "local_file_count": len(local_files),
            "attack_enabled": attack_validation is not None,
        },
        "requested_cve_ids": list(cve_ids),
        "namespaces": namespace_items,
        "coverage": coverage_items,
        "local_files": local_files,
        "attack": (
            build_attack_validation_payload(
                validation=attack_validation,
                mapping_file_sha256=attack_mapping_sha256,
                technique_metadata_file_sha256=attack_metadata_sha256,
            )
            if attack_validation is not None
            else None
        ),
        "warnings": list(warnings),
    }


def build_cache_coverage_items(
    *,
    cache: FileCache,
    cve_ids: list[str],
) -> list[dict[str, object]]:
    """Build per-source cache coverage rows for `data verify`."""
    if not cve_ids:
        return []

    requested = len(cve_ids)
    nvd_hits, nvd_empty, nvd_invalid = _validated_per_cve_cache_hits(
        cache=cache,
        namespace="nvd",
        cve_ids=cve_ids,
        model=NvdData,
    )
    epss_hits, epss_empty, epss_invalid = _validated_per_cve_cache_hits(
        cache=cache,
        namespace="epss",
        cve_ids=cve_ids,
        model=EpssData,
    )
    kev_payload = cache.get_json("kev", "catalog")
    kev_catalog = kev_payload if isinstance(kev_payload, dict) else {}
    kev_hits = 0
    kev_invalid = 0
    for cve_id in cve_ids:
        item = kev_catalog.get(cve_id)
        if item is None:
            continue
        try:
            parsed = KevData.model_validate(item)
        except ValidationError:
            kev_invalid += 1
            continue
        if parsed.in_kev:
            kev_hits += 1

    return [
        build_coverage_item(
            source="nvd",
            cached_hits=nvd_hits,
            requested=requested,
            empty_records=nvd_empty,
            invalid_records=nvd_invalid,
            details="Fresh per-CVE cache entries validated with NVD schema and content checks.",
        ),
        build_coverage_item(
            source="epss",
            cached_hits=epss_hits,
            requested=requested,
            empty_records=epss_empty,
            invalid_records=epss_invalid,
            details="Fresh per-CVE cache entries validated with EPSS schema and content checks.",
        ),
        build_coverage_item(
            source="kev",
            cached_hits=kev_hits,
            requested=requested,
            empty_records=0,
            invalid_records=kev_invalid,
            details="Coverage derived from the cached KEV catalog index.",
        ),
    ]


def build_coverage_item(
    *,
    source: str,
    cached_hits: int,
    requested: int,
    empty_records: int = 0,
    invalid_records: int = 0,
    details: str,
) -> dict[str, object]:
    """Return one normalized cache coverage row."""
    return {
        "source": source,
        "cached_hits": cached_hits,
        "requested_cves": requested,
        "coverage": f"{cached_hits}/{requested}",
        "empty_records": empty_records,
        "invalid_records": invalid_records,
        "details": details,
    }


def _validated_per_cve_cache_hits(
    *,
    cache: FileCache,
    namespace: str,
    cve_ids: list[str],
    model: type[NvdData] | type[EpssData],
) -> tuple[int, int, int]:
    hits = 0
    empty = 0
    invalid = 0
    for cve_id in cve_ids:
        cached_payload = cache.get_json(namespace, cve_id)
        if cached_payload is None:
            continue
        try:
            parsed = model.model_validate(cached_payload)
        except ValidationError:
            invalid += 1
            continue
        if isinstance(parsed, NvdData):
            if has_nvd_content(parsed):
                hits += 1
            else:
                empty += 1
        elif parsed.epss is not None or parsed.percentile is not None or parsed.date is not None:
            hits += 1
        else:
            empty += 1
    return hits, empty, invalid


def build_attack_validation_payload(
    *,
    validation: dict[str, Any],
    mapping_file_sha256: str | None,
    technique_metadata_file_sha256: str | None,
) -> dict[str, object]:
    """Normalize ATT&CK validation details for JSON output."""
    return {
        "source": str(validation["source"]),
        "mapping_file": nullable_string(validation.get("mapping_file")),
        "mapping_file_sha256": mapping_file_sha256,
        "technique_metadata_file": nullable_string(validation.get("technique_metadata_file")),
        "technique_metadata_file_sha256": technique_metadata_file_sha256,
        "source_version": nullable_string(validation.get("source_version")),
        "attack_version": nullable_string(validation.get("attack_version")),
        "domain": nullable_string(validation.get("domain")),
        "mapping_framework": nullable_string(validation.get("mapping_framework")),
        "mapping_framework_version": nullable_string(validation.get("mapping_framework_version")),
        "mapping_count": int(validation["mapping_count"]),
        "unique_cves": int(validation["unique_cves"]),
        "technique_count": int(validation["technique_count"]),
        "missing_metadata_ids": list(validation["missing_metadata_ids"]),
        "domain_mismatch": bool(validation["domain_mismatch"]),
        "attack_version_mismatch": bool(validation["attack_version_mismatch"]),
        "revoked_or_deprecated_count": int(validation["revoked_or_deprecated_count"]),
    }


def normalize_namespace_status(status: dict[str, object]) -> dict[str, object]:
    """Return a stable machine-readable cache namespace summary."""
    return {
        "namespace": str(status["namespace"]),
        "file_count": _coerce_int(status["file_count"]),
        "valid_count": _coerce_int(status["valid_count"]),
        "expired_count": _coerce_int(status["expired_count"]),
        "invalid_count": _coerce_int(status["invalid_count"]),
        "latest_cached_at": nullable_string(status.get("latest_cached_at")),
        "namespace_checksum": nullable_string(status.get("namespace_checksum")),
    }


def normalize_update_row(row: dict[str, str | int | None]) -> dict[str, object]:
    """Return a stable machine-readable data update row."""
    source = str(row["source"]).lower()
    return {
        "source": source,
        "mode": str(row["mode"]),
        "requested_cves": _coerce_int(row["requested"]),
        "cached_records": _coerce_int(row["records"]),
        "latest_cached_at": nullable_string(row.get("latest_cached_at")),
        "details": str(row["details"]),
    }


def normalize_local_file_row(row: dict[str, str | int]) -> dict[str, object]:
    """Return a stable machine-readable local file verification row."""
    return {
        "label": str(row["label"]),
        "path": str(row["path"]),
        "size_bytes": int(row["size_bytes"]),
        "sha256": str(row["sha256"]),
    }


def nullable_string(value: object) -> str | None:
    """Convert a possibly-null value into an explicit nullable string."""
    if value is None:
        return None
    return str(value)


def _coerce_int(value: object) -> int:
    """Convert validated status/update values into ints for JSON payloads."""
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value)
    raise TypeError(f"Expected an integer-like value, got {type(value).__name__}.")

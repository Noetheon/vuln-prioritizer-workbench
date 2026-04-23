"""Data command registrations."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Any, TypeVar, cast

import typer
from dotenv import load_dotenv
from pydantic import ValidationError
from rich.panel import Panel

from vuln_prioritizer.cache import FileCache
from vuln_prioritizer.cli_support.attack_support import validate_attack_inputs_or_exit
from vuln_prioritizer.cli_support.common import (
    TABLE_AND_JSON_OUTPUT_FORMATS,
    AttackSource,
    DataSourceName,
    InputFormat,
    TableJsonOutputFormat,
    build_input_specs_or_exit,
    console,
    output_format_option,
    print_warnings,
)
from vuln_prioritizer.cli_support.data_support import (
    build_data_status_payload,
    build_data_update_payload,
    build_data_verify_payload,
    emit_data_json_payload,
    validate_data_output_options,
)
from vuln_prioritizer.cli_support.extras import (
    data_sources_require_cves,
    load_data_command_cves_or_exit,
    render_cache_coverage_table,
    render_cache_namespace_table,
    render_data_update_table,
    render_local_file_table,
    resolve_data_sources,
    sha256_file,
)
from vuln_prioritizer.config import (
    DEFAULT_CACHE_DIR,
    DEFAULT_CACHE_TTL_HOURS,
    DEFAULT_NVD_API_KEY_ENV,
)
from vuln_prioritizer.inputs import InputSpec
from vuln_prioritizer.models import (
    EpssData,
    KevData,
    NvdData,
    ProviderSnapshotItem,
    ProviderSnapshotMetadata,
    ProviderSnapshotReport,
)
from vuln_prioritizer.provider_snapshot import generate_provider_snapshot_json
from vuln_prioritizer.providers.epss import EpssProvider
from vuln_prioritizer.providers.kev import KevProvider
from vuln_prioritizer.providers.nvd import NvdProvider, has_nvd_content
from vuln_prioritizer.reporter import write_output
from vuln_prioritizer.utils import iso_utc_now

ProviderCacheRecord = TypeVar("ProviderCacheRecord", NvdData, EpssData)


def data_status(
    cache_dir: Path = typer.Option(
        DEFAULT_CACHE_DIR, "--cache-dir", file_okay=False, dir_okay=True
    ),
    cache_ttl_hours: int = typer.Option(DEFAULT_CACHE_TTL_HOURS, "--cache-ttl-hours", min=1),
    offline_kev_file: Path | None = typer.Option(None, "--offline-kev-file", dir_okay=False),
    attack_mapping_file: Path | None = typer.Option(None, "--attack-mapping-file", dir_okay=False),
    attack_technique_metadata_file: Path | None = typer.Option(
        None, "--attack-technique-metadata-file", dir_okay=False
    ),
    output: Path | None = typer.Option(None, "--output", dir_okay=False),
    format: TableJsonOutputFormat = output_format_option(
        TableJsonOutputFormat.table, TABLE_AND_JSON_OUTPUT_FORMATS
    ),
    quiet: bool = typer.Option(
        False,
        "--quiet",
        help="Suppress JSON stdout; valid only with --format json.",
    ),
) -> None:
    """Show cache status and local metadata versions."""
    validate_data_output_options(
        command_name="data status",
        format=format,
        output=output,
        quiet=quiet,
    )

    cache = FileCache(cache_dir, cache_ttl_hours)
    statuses = [
        cache.inspect_namespace("nvd"),
        cache.inspect_namespace("epss"),
        cache.inspect_namespace("kev"),
    ]
    warnings: list[str] = []
    attack_validation: dict[str, Any] | None = None
    attack_mapping_sha256: str | None = None
    attack_metadata_sha256: str | None = None
    if attack_mapping_file is not None:
        attack_validation = validate_attack_inputs_or_exit(
            attack_source=AttackSource.ctid_json.value,
            attack_mapping_file=attack_mapping_file,
            attack_technique_metadata_file=attack_technique_metadata_file,
        )
        attack_mapping_sha256 = sha256_file(attack_mapping_file)
        if attack_technique_metadata_file is not None:
            attack_metadata_sha256 = sha256_file(attack_technique_metadata_file)
        warnings.extend(cast(list[str], attack_validation["warnings"]))

    if format == TableJsonOutputFormat.json:
        emit_data_json_payload(
            payload=build_data_status_payload(
                cache_dir=cache_dir,
                cache_ttl_hours=cache_ttl_hours,
                output=output,
                offline_kev_file=offline_kev_file,
                statuses=statuses,
                attack_validation=attack_validation,
                attack_mapping_sha256=attack_mapping_sha256,
                attack_metadata_sha256=attack_metadata_sha256,
                warnings=warnings,
            ),
            output=output,
            quiet=quiet,
        )
        return

    console.print(
        Panel(
            "\n".join(
                [
                    f"Cache directory: {cache_dir}",
                    f"Cache TTL (hours): {cache_ttl_hours}",
                    f"KEV mode: {'offline file' if offline_kev_file else 'live/cache'}",
                ]
            ),
            title="Data Status",
        )
    )
    console.print(render_cache_namespace_table(statuses))
    if attack_validation is not None:
        console.print(
            Panel(
                "\n".join(
                    [
                        f"ATT&CK source: {attack_validation['source']}",
                        f"ATT&CK mapping file: {attack_validation['mapping_file']}",
                        "ATT&CK mapping SHA256: " + (attack_mapping_sha256 or "N.A."),
                        f"ATT&CK source version: {attack_validation['source_version'] or 'N.A.'}",
                        f"ATT&CK version: {attack_validation['attack_version'] or 'N.A.'}",
                        f"ATT&CK domain: {attack_validation['domain'] or 'N.A.'}",
                    ]
                ),
                title="ATT&CK Metadata",
            )
        )
    print_warnings(warnings)


def data_update(
    source: list[DataSourceName] | None = typer.Option(None, "--source"),
    input: list[Path] | None = typer.Option(
        None, "--input", exists=True, dir_okay=False, readable=True
    ),
    input_format: list[InputFormat] | None = typer.Option(None, "--input-format"),
    cve: list[str] | None = typer.Option(None, "--cve"),
    max_cves: int | None = typer.Option(None, "--max-cves", min=1),
    cache_dir: Path = typer.Option(
        DEFAULT_CACHE_DIR, "--cache-dir", file_okay=False, dir_okay=True
    ),
    cache_ttl_hours: int = typer.Option(DEFAULT_CACHE_TTL_HOURS, "--cache-ttl-hours", min=1),
    offline_kev_file: Path | None = typer.Option(None, "--offline-kev-file", dir_okay=False),
    nvd_api_key_env: str = typer.Option(DEFAULT_NVD_API_KEY_ENV, "--nvd-api-key-env"),
    output: Path | None = typer.Option(None, "--output", dir_okay=False),
    format: TableJsonOutputFormat = output_format_option(
        TableJsonOutputFormat.table, TABLE_AND_JSON_OUTPUT_FORMATS
    ),
    quiet: bool = typer.Option(
        False,
        "--quiet",
        help="Suppress JSON stdout; valid only with --format json.",
    ),
) -> None:
    """Refresh cached live-source data for requested CVEs or the KEV catalog."""
    validate_data_output_options(
        command_name="data update",
        format=format,
        output=output,
        quiet=quiet,
    )

    load_dotenv()
    selected_sources = resolve_data_sources(source)
    requires_cves = data_sources_require_cves(selected_sources)
    input_specs = build_input_specs_or_exit(
        input_paths=input,
        input_formats=input_format,
        command_name="data update",
        require_inputs=False,
    )
    cve_ids, input_warnings = load_data_command_cves_or_exit(
        input_specs=input_specs,
        inline_cves=cve or [],
        max_cves=max_cves,
        required=requires_cves,
    )
    cache = FileCache(cache_dir, cache_ttl_hours)

    rows: list[dict[str, str | int | None]] = []
    warnings = list(input_warnings)
    if "nvd" in selected_sources:
        nvd_results, provider_warnings = NvdProvider.from_env(
            api_key_env=nvd_api_key_env,
            cache=cache,
        ).fetch_many(cve_ids, refresh=True)
        warnings.extend(provider_warnings)
        rows.append(
            {
                "source": "NVD",
                "mode": "live/api",
                "requested": len(cve_ids),
                "records": sum(1 for item in nvd_results.values() if has_nvd_content(item)),
                "latest_cached_at": cache.latest_cached_at("nvd") or "N.A.",
                "details": "Per-CVE records refreshed from the NVD CVE API cache namespace.",
            }
        )
    if "epss" in selected_sources:
        epss_results, provider_warnings = EpssProvider(cache=cache).fetch_many(
            cve_ids, refresh=True
        )
        warnings.extend(provider_warnings)
        rows.append(
            {
                "source": "EPSS",
                "mode": "live/api",
                "requested": len(cve_ids),
                "records": sum(
                    1
                    for item in epss_results.values()
                    if item.epss is not None or item.percentile is not None or item.date is not None
                ),
                "latest_cached_at": cache.latest_cached_at("epss") or "N.A.",
                "details": (
                    "Per-CVE EPSS records refreshed from the FIRST EPSS API cache namespace."
                ),
            }
        )
    if "kev" in selected_sources:
        _, provider_warnings = KevProvider(cache=cache).fetch_many(
            cve_ids,
            offline_file=offline_kev_file,
            refresh=True,
        )
        warnings.extend(provider_warnings)
        cached_catalog = cache.get_json("kev", "catalog") or {}
        rows.append(
            {
                "source": "KEV",
                "mode": "offline file" if offline_kev_file else "live/catalog",
                "requested": len(cve_ids),
                "records": len(cached_catalog) if isinstance(cached_catalog, dict) else 0,
                "latest_cached_at": cache.latest_cached_at("kev") or "N.A.",
                "details": "Catalog namespace refreshed and indexed for cached KEV lookups.",
            }
        )

    if format == TableJsonOutputFormat.json:
        emit_data_json_payload(
            payload=build_data_update_payload(
                cache_dir=cache_dir,
                cache_ttl_hours=cache_ttl_hours,
                output=output,
                input_paths=input or [],
                input_format=_effective_input_format(input_specs),
                max_cves=max_cves,
                offline_kev_file=offline_kev_file,
                nvd_api_key_env=nvd_api_key_env,
                selected_sources=selected_sources,
                cve_ids=cve_ids,
                rows=rows,
                warnings=warnings,
            ),
            output=output,
            quiet=quiet,
        )
        return

    console.print(
        Panel(
            "\n".join(
                [
                    "Selected sources: " + ", ".join(selected_sources),
                    f"Cache directory: {cache_dir}",
                    f"Cache TTL (hours): {cache_ttl_hours}",
                    f"Requested CVEs: {len(cve_ids)}",
                ]
            ),
            title="Data Update",
        )
    )
    console.print(render_data_update_table(rows))
    print_warnings(warnings)


def data_verify(
    input: list[Path] | None = typer.Option(
        None, "--input", exists=True, dir_okay=False, readable=True
    ),
    input_format: list[InputFormat] | None = typer.Option(None, "--input-format"),
    cve: list[str] | None = typer.Option(None, "--cve"),
    max_cves: int | None = typer.Option(None, "--max-cves", min=1),
    cache_dir: Path = typer.Option(
        DEFAULT_CACHE_DIR, "--cache-dir", file_okay=False, dir_okay=True
    ),
    cache_ttl_hours: int = typer.Option(DEFAULT_CACHE_TTL_HOURS, "--cache-ttl-hours", min=1),
    offline_kev_file: Path | None = typer.Option(None, "--offline-kev-file", dir_okay=False),
    attack_mapping_file: Path | None = typer.Option(None, "--attack-mapping-file", dir_okay=False),
    attack_technique_metadata_file: Path | None = typer.Option(
        None, "--attack-technique-metadata-file", dir_okay=False
    ),
    output: Path | None = typer.Option(None, "--output", dir_okay=False),
    format: TableJsonOutputFormat = output_format_option(
        TableJsonOutputFormat.table, TABLE_AND_JSON_OUTPUT_FORMATS
    ),
    quiet: bool = typer.Option(
        False,
        "--quiet",
        help="Suppress JSON stdout; valid only with --format json.",
    ),
) -> None:
    """Verify cache integrity, cache coverage, and local file checksums."""
    validate_data_output_options(
        command_name="data verify",
        format=format,
        output=output,
        quiet=quiet,
    )

    cache = FileCache(cache_dir, cache_ttl_hours)
    input_specs = build_input_specs_or_exit(
        input_paths=input,
        input_formats=input_format,
        command_name="data verify",
        require_inputs=False,
    )
    cve_ids, input_warnings = load_data_command_cves_or_exit(
        input_specs=input_specs,
        inline_cves=cve or [],
        max_cves=max_cves,
        required=False,
    )
    statuses = [
        cache.inspect_namespace("nvd"),
        cache.inspect_namespace("epss"),
        cache.inspect_namespace("kev"),
    ]
    warnings = list(input_warnings)
    local_file_rows: list[dict[str, str | int]] = []
    attack_validation: dict[str, Any] | None = None
    attack_mapping_sha256: str | None = None
    attack_metadata_sha256: str | None = None

    if offline_kev_file is not None:
        local_file_rows.append(
            {
                "label": "Offline KEV file",
                "path": str(offline_kev_file),
                "sha256": sha256_file(offline_kev_file),
                "size_bytes": offline_kev_file.stat().st_size,
            }
        )
    if attack_mapping_file is not None:
        attack_validation = validate_attack_inputs_or_exit(
            attack_source=AttackSource.ctid_json.value,
            attack_mapping_file=attack_mapping_file,
            attack_technique_metadata_file=attack_technique_metadata_file,
        )
        attack_mapping_sha256 = sha256_file(attack_mapping_file)
        local_file_rows.append(
            {
                "label": "ATT&CK mapping file",
                "path": str(attack_mapping_file),
                "sha256": attack_mapping_sha256,
                "size_bytes": attack_mapping_file.stat().st_size,
            }
        )
        if attack_technique_metadata_file is not None:
            attack_metadata_sha256 = sha256_file(attack_technique_metadata_file)
            local_file_rows.append(
                {
                    "label": "ATT&CK metadata file",
                    "path": str(attack_technique_metadata_file),
                    "sha256": attack_metadata_sha256,
                    "size_bytes": attack_technique_metadata_file.stat().st_size,
                }
            )
        warnings.extend(cast(list[str], attack_validation["warnings"]))

    if format == TableJsonOutputFormat.json:
        emit_data_json_payload(
            payload=build_data_verify_payload(
                cache=cache,
                cache_dir=cache_dir,
                cache_ttl_hours=cache_ttl_hours,
                output=output,
                input_paths=input or [],
                input_format=_effective_input_format(input_specs),
                max_cves=max_cves,
                offline_kev_file=offline_kev_file,
                cve_ids=cve_ids,
                statuses=statuses,
                local_file_rows=local_file_rows,
                attack_validation=attack_validation,
                attack_mapping_sha256=attack_mapping_sha256,
                attack_metadata_sha256=attack_metadata_sha256,
                warnings=warnings,
            ),
            output=output,
            quiet=quiet,
        )
        return

    console.print(
        Panel(
            "\n".join(
                [
                    f"Cache directory: {cache_dir}",
                    f"Cache TTL (hours): {cache_ttl_hours}",
                    f"Requested CVEs for coverage check: {len(cve_ids)}",
                    f"KEV mode: {'offline file' if offline_kev_file else 'live/cache'}",
                ]
            ),
            title="Data Verify",
        )
    )
    console.print(render_cache_namespace_table(statuses))
    if cve_ids:
        console.print(render_cache_coverage_table(cache, cve_ids))

    if offline_kev_file is not None:
        console.print(
            render_local_file_table(
                [local_file_rows[0]],
                title="Pinned Local Files",
            )
        )
    if attack_validation is not None:
        attack_file_rows = local_file_rows[1:] if offline_kev_file is not None else local_file_rows
        console.print(render_local_file_table(attack_file_rows, title="Pinned Local Files"))
        console.print(
            Panel(
                "\n".join(
                    [
                        f"ATT&CK source: {attack_validation['source']}",
                        f"Source version: {attack_validation['source_version'] or 'N.A.'}",
                        f"ATT&CK version: {attack_validation['attack_version'] or 'N.A.'}",
                        f"Domain: {attack_validation['domain'] or 'N.A.'}",
                        f"Unique CVEs in mapping: {attack_validation['unique_cves']}",
                        f"Total mapping objects: {attack_validation['mapping_count']}",
                        f"Technique metadata entries: {attack_validation['technique_count']}",
                    ]
                ),
                title="ATT&CK Verification",
            )
        )
    print_warnings(warnings)


def data_export_provider_snapshot(
    source: list[DataSourceName] | None = typer.Option(None, "--source"),
    input: list[Path] | None = typer.Option(
        None, "--input", exists=True, dir_okay=False, readable=True
    ),
    input_format: list[InputFormat] | None = typer.Option(None, "--input-format"),
    cve: list[str] | None = typer.Option(None, "--cve"),
    max_cves: int | None = typer.Option(None, "--max-cves", min=1),
    output: Path = typer.Option(..., "--output", dir_okay=False),
    cache_dir: Path = typer.Option(
        DEFAULT_CACHE_DIR, "--cache-dir", file_okay=False, dir_okay=True
    ),
    cache_ttl_hours: int = typer.Option(DEFAULT_CACHE_TTL_HOURS, "--cache-ttl-hours", min=1),
    offline_kev_file: Path | None = typer.Option(None, "--offline-kev-file", dir_okay=False),
    nvd_api_key_env: str = typer.Option(DEFAULT_NVD_API_KEY_ENV, "--nvd-api-key-env"),
    cache_only: bool = typer.Option(
        False,
        "--cache-only",
        help="Export only locally cached/offline provider data; never refresh live providers.",
    ),
) -> None:
    """Export pinned provider data for later replay."""
    load_dotenv()
    selected_sources = resolve_data_sources(source)
    input_specs = build_input_specs_or_exit(
        input_paths=input,
        input_formats=input_format,
        command_name="data export-provider-snapshot",
        require_inputs=False,
    )
    cve_ids, warnings = load_data_command_cves_or_exit(
        input_specs=input_specs,
        inline_cves=cve or [],
        max_cves=max_cves,
        required=True,
    )
    cache = FileCache(cache_dir, cache_ttl_hours)

    nvd_results: dict[str, NvdData] = {}
    epss_results: dict[str, EpssData] = {}
    kev_results: dict[str, KevData] = {}
    if "nvd" in selected_sources:
        if cache_only:
            nvd_results, provider_warnings = load_cached_provider_records(
                cache=cache,
                namespace="nvd",
                cve_ids=cve_ids,
                model=NvdData,
            )
        else:
            nvd_results, provider_warnings = NvdProvider.from_env(
                api_key_env=nvd_api_key_env,
                cache=cache,
            ).fetch_many(cve_ids, refresh=True)
        warnings.extend(provider_warnings)
    if "epss" in selected_sources:
        if cache_only:
            epss_results, provider_warnings = load_cached_provider_records(
                cache=cache,
                namespace="epss",
                cve_ids=cve_ids,
                model=EpssData,
            )
        else:
            epss_results, provider_warnings = EpssProvider(cache=cache).fetch_many(
                cve_ids,
                refresh=True,
            )
        warnings.extend(provider_warnings)
    if "kev" in selected_sources:
        if cache_only:
            kev_results, provider_warnings = load_cache_only_kev_records(
                cache=cache,
                cve_ids=cve_ids,
                offline_kev_file=offline_kev_file,
            )
        else:
            kev_results, provider_warnings = KevProvider(cache=cache).fetch_many(
                cve_ids,
                offline_file=offline_kev_file,
                refresh=True,
            )
        warnings.extend(provider_warnings)

    report = ProviderSnapshotReport(
        metadata=ProviderSnapshotMetadata(
            generated_at=iso_utc_now(),
            input_path=str(input[0]) if input else None,
            input_paths=[str(path) for path in (input or [])],
            input_format=_effective_input_format(input_specs),
            selected_sources=selected_sources,
            requested_cves=len(cve_ids),
            output_path=str(output),
            cache_enabled=True,
            cache_only=cache_only,
            cache_dir=str(cache_dir),
            offline_kev_file=str(offline_kev_file) if offline_kev_file else None,
            nvd_api_key_env=nvd_api_key_env,
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
    write_output(output, generate_provider_snapshot_json(report))
    console.print(f"[green]Wrote provider snapshot output to {output}[/green]")
    print_warnings(warnings)


def load_cached_provider_records(
    *,
    cache: FileCache,
    namespace: str,
    cve_ids: list[str],
    model: type[ProviderCacheRecord],
) -> tuple[dict[str, ProviderCacheRecord], list[str]]:
    results: dict[str, ProviderCacheRecord] = {}
    missing: list[str] = []
    invalid: list[str] = []
    for cve_id in cve_ids:
        cached_payload = cache.get_json(namespace, cve_id)
        if cached_payload is None:
            missing.append(cve_id)
            continue
        try:
            results[cve_id] = model.model_validate(cached_payload)
        except ValidationError:
            invalid.append(cve_id)

    warnings: list[str] = []
    if missing:
        warnings.append(
            f"cache-only {namespace.upper()} data missing for {len(missing)} CVE(s): "
            + ", ".join(missing)
            + "."
        )
    if invalid:
        warnings.append(
            f"cache-only {namespace.upper()} data invalid for {len(invalid)} CVE(s): "
            + ", ".join(invalid)
            + "."
        )
    return results, warnings


def load_cache_only_kev_records(
    *,
    cache: FileCache,
    cve_ids: list[str],
    offline_kev_file: Path | None,
) -> tuple[dict[str, KevData], list[str]]:
    if offline_kev_file is not None:
        return KevProvider(cache=cache).fetch_many(
            cve_ids,
            offline_file=offline_kev_file,
            refresh=False,
        )

    cached_catalog = cache.get_json("kev", "catalog")
    if not isinstance(cached_catalog, dict):
        return {}, ["cache-only KEV catalog is missing from the local cache."]

    index: dict[str, KevData] = {}
    invalid: list[str] = []
    for cve_id, item in cached_catalog.items():
        try:
            index[str(cve_id)] = KevData.model_validate(item)
        except ValidationError:
            invalid.append(str(cve_id))

    warnings = (
        ["cache-only KEV catalog contains invalid record(s): " + ", ".join(invalid) + "."]
        if invalid
        else []
    )
    return {
        cve_id: index.get(cve_id, KevData(cve_id=cve_id, in_kev=False)) for cve_id in cve_ids
    }, warnings


def register(data_app: typer.Typer) -> None:
    data_app.command("status")(data_status)
    data_app.command("update")(data_update)
    data_app.command("verify")(data_verify)
    data_app.command("export-provider-snapshot")(data_export_provider_snapshot)


def _effective_input_format(input_specs: Sequence[InputSpec]) -> str:
    formats = {str(getattr(spec, "input_format", "auto")) for spec in input_specs}
    if not formats:
        return InputFormat.auto.value
    if len(formats) == 1:
        return next(iter(formats))
    return "mixed"

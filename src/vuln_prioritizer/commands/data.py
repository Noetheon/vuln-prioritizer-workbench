"""Data command registrations."""

from __future__ import annotations

from pathlib import Path
from typing import cast

import typer
from dotenv import load_dotenv
from rich.panel import Panel

from vuln_prioritizer.cache import FileCache
from vuln_prioritizer.cli_support.analysis import has_nvd_content
from vuln_prioritizer.cli_support.attack_support import validate_attack_inputs_or_exit
from vuln_prioritizer.cli_support.common import (
    AttackSource,
    DataSourceName,
    InputFormat,
    console,
    print_warnings,
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
from vuln_prioritizer.providers.epss import EpssProvider
from vuln_prioritizer.providers.kev import KevProvider
from vuln_prioritizer.providers.nvd import NvdProvider


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
) -> None:
    """Show cache status and local metadata versions."""
    cache = FileCache(cache_dir, cache_ttl_hours)
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
    console.print(
        render_cache_namespace_table(
            [
                cache.inspect_namespace("nvd"),
                cache.inspect_namespace("epss"),
                cache.inspect_namespace("kev"),
            ]
        )
    )
    if attack_mapping_file is not None:
        validation = validate_attack_inputs_or_exit(
            attack_source=AttackSource.ctid_json.value,
            attack_mapping_file=attack_mapping_file,
            attack_technique_metadata_file=attack_technique_metadata_file,
        )
        console.print(
            Panel(
                "\n".join(
                    [
                        f"ATT&CK source: {validation['source']}",
                        f"ATT&CK mapping file: {validation['mapping_file']}",
                        "ATT&CK mapping SHA256: "
                        + (sha256_file(attack_mapping_file) if attack_mapping_file else "N.A."),
                        f"ATT&CK source version: {validation['source_version'] or 'N.A.'}",
                        f"ATT&CK version: {validation['attack_version'] or 'N.A.'}",
                        f"ATT&CK domain: {validation['domain'] or 'N.A.'}",
                    ]
                ),
                title="ATT&CK Metadata",
            )
        )
        print_warnings(cast(list[str], validation["warnings"]))


def data_update(
    source: list[DataSourceName] | None = typer.Option(None, "--source"),
    input: Path | None = typer.Option(None, "--input", exists=True, dir_okay=False, readable=True),
    input_format: InputFormat = typer.Option(InputFormat.auto, "--input-format"),
    cve: list[str] | None = typer.Option(None, "--cve"),
    max_cves: int | None = typer.Option(None, "--max-cves", min=1),
    cache_dir: Path = typer.Option(
        DEFAULT_CACHE_DIR, "--cache-dir", file_okay=False, dir_okay=True
    ),
    cache_ttl_hours: int = typer.Option(DEFAULT_CACHE_TTL_HOURS, "--cache-ttl-hours", min=1),
    offline_kev_file: Path | None = typer.Option(None, "--offline-kev-file", dir_okay=False),
    nvd_api_key_env: str = typer.Option(DEFAULT_NVD_API_KEY_ENV, "--nvd-api-key-env"),
) -> None:
    """Refresh cached live-source data for requested CVEs or the KEV catalog."""
    load_dotenv()
    selected_sources = resolve_data_sources(source)
    requires_cves = data_sources_require_cves(selected_sources)
    cve_ids, input_warnings = load_data_command_cves_or_exit(
        input_path=input,
        input_format=input_format.value,
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
    input: Path | None = typer.Option(None, "--input", exists=True, dir_okay=False, readable=True),
    input_format: InputFormat = typer.Option(InputFormat.auto, "--input-format"),
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
) -> None:
    """Verify cache integrity, cache coverage, and local file checksums."""
    cache = FileCache(cache_dir, cache_ttl_hours)
    cve_ids, input_warnings = load_data_command_cves_or_exit(
        input_path=input,
        input_format=input_format.value,
        inline_cves=cve or [],
        max_cves=max_cves,
        required=False,
    )
    statuses = [
        cache.inspect_namespace("nvd"),
        cache.inspect_namespace("epss"),
        cache.inspect_namespace("kev"),
    ]

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
                [
                    {
                        "label": "Offline KEV file",
                        "path": str(offline_kev_file),
                        "sha256": sha256_file(offline_kev_file),
                        "size_bytes": offline_kev_file.stat().st_size,
                    }
                ],
                title="Pinned Local Files",
            )
        )
    if attack_mapping_file is not None:
        validation = validate_attack_inputs_or_exit(
            attack_source=AttackSource.ctid_json.value,
            attack_mapping_file=attack_mapping_file,
            attack_technique_metadata_file=attack_technique_metadata_file,
        )
        file_rows: list[dict[str, str | int]] = [
            {
                "label": "ATT&CK mapping file",
                "path": str(attack_mapping_file),
                "sha256": sha256_file(attack_mapping_file),
                "size_bytes": attack_mapping_file.stat().st_size,
            }
        ]
        if attack_technique_metadata_file is not None:
            file_rows.append(
                {
                    "label": "ATT&CK metadata file",
                    "path": str(attack_technique_metadata_file),
                    "sha256": sha256_file(attack_technique_metadata_file),
                    "size_bytes": attack_technique_metadata_file.stat().st_size,
                }
            )
        console.print(render_local_file_table(file_rows, title="Pinned Local Files"))
        console.print(
            Panel(
                "\n".join(
                    [
                        f"ATT&CK source: {validation['source']}",
                        f"Source version: {validation['source_version'] or 'N.A.'}",
                        f"ATT&CK version: {validation['attack_version'] or 'N.A.'}",
                        f"Domain: {validation['domain'] or 'N.A.'}",
                        f"Unique CVEs in mapping: {validation['unique_cves']}",
                        f"Total mapping objects: {validation['mapping_count']}",
                        f"Technique metadata entries: {validation['technique_count']}",
                    ]
                ),
                title="ATT&CK Verification",
            )
        )
        input_warnings.extend(cast(list[str], validation["warnings"]))
    print_warnings(input_warnings)


def register(data_app: typer.Typer) -> None:
    data_app.command("status")(data_status)
    data_app.command("update")(data_update)
    data_app.command("verify")(data_verify)

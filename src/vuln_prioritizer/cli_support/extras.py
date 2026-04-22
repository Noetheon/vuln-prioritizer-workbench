"""Data and cache CLI helpers used by command modules."""

from __future__ import annotations

import hashlib
from pathlib import Path

from pydantic import ValidationError
from rich.table import Table

from vuln_prioritizer.cache import FileCache
from vuln_prioritizer.inputs import InputLoader
from vuln_prioritizer.utils import normalize_cve_id

from .common import DataSourceName, exit_input_validation


def resolve_data_sources(sources: list[DataSourceName] | None) -> list[str]:
    ordered: list[str] = []
    requested = sources or [DataSourceName.all]
    for source in requested:
        expanded = ["nvd", "epss", "kev"] if source == DataSourceName.all else [source.value]
        for item in expanded:
            if item not in ordered:
                ordered.append(item)
    return ordered


def data_sources_require_cves(sources: list[str]) -> bool:
    return any(item in {"nvd", "epss"} for item in sources)


def load_data_command_cves_or_exit(
    *,
    input_path: Path | None,
    input_format: str,
    inline_cves: list[str],
    max_cves: int | None,
    required: bool,
) -> tuple[list[str], list[str]]:
    cve_ids: list[str] = []
    warnings: list[str] = []

    if input_path is not None:
        try:
            parsed_input = InputLoader().load(
                input_path, input_format=input_format, max_cves=max_cves
            )
        except (ValidationError, ValueError) as exc:
            exit_input_validation(str(exc))
        cve_ids.extend(parsed_input.unique_cves)
        warnings.extend(parsed_input.warnings)

    for raw_cve in inline_cves:
        normalized = normalize_cve_id(raw_cve)
        if normalized is None:
            warnings.append(f"Ignored invalid CVE identifier: {raw_cve!r}")
            continue
        if normalized not in cve_ids:
            cve_ids.append(normalized)

    if max_cves is not None and len(cve_ids) > max_cves:
        warnings.append(f"Truncated data-source verification input to the first {max_cves} CVEs.")
        cve_ids = cve_ids[:max_cves]

    if required and not cve_ids:
        exit_input_validation("NVD and EPSS cache refresh requires --input or at least one --cve.")

    return cve_ids, warnings


def render_cache_namespace_table(statuses: list[dict[str, object]]) -> Table:
    table = Table(title="Cache Namespaces", show_lines=False)
    table.add_column("Source", style="bold")
    table.add_column("Files")
    table.add_column("Valid")
    table.add_column("Expired")
    table.add_column("Invalid")
    table.add_column("Latest Cached At")
    table.add_column("Namespace SHA256")

    labels = {"nvd": "NVD", "epss": "EPSS", "kev": "KEV"}
    for status in statuses:
        namespace = str(status["namespace"])
        table.add_row(
            labels.get(namespace, namespace.upper()),
            str(status["file_count"]),
            str(status["valid_count"]),
            str(status["expired_count"]),
            str(status["invalid_count"]),
            str(status["latest_cached_at"] or "N.A."),
            str(status["namespace_checksum"] or "N.A."),
        )
    return table


def render_data_update_table(rows: list[dict[str, str | int | None]]) -> Table:
    table = Table(title="Updated Sources", show_lines=False)
    table.add_column("Source", style="bold")
    table.add_column("Mode")
    table.add_column("Requested CVEs")
    table.add_column("Cached Records")
    table.add_column("Latest Cached At")
    table.add_column("Details")

    for row in rows:
        table.add_row(
            str(row["source"]),
            str(row["mode"]),
            str(row["requested"]),
            str(row["records"]),
            str(row["latest_cached_at"]),
            str(row["details"]),
        )
    return table


def render_cache_coverage_table(cache: FileCache, cve_ids: list[str]) -> Table:
    table = Table(title="Cache Coverage", show_lines=False)
    table.add_column("Source", style="bold")
    table.add_column("Cached Coverage")
    table.add_column("Details")

    nvd_hits = sum(1 for cve_id in cve_ids if cache.get_json("nvd", cve_id) is not None)
    epss_hits = sum(1 for cve_id in cve_ids if cache.get_json("epss", cve_id) is not None)
    kev_payload = cache.get_json("kev", "catalog")
    kev_catalog = kev_payload if isinstance(kev_payload, dict) else {}
    kev_hits = sum(1 for cve_id in cve_ids if cve_id in kev_catalog)

    table.add_row("NVD", f"{nvd_hits}/{len(cve_ids)}", "Fresh per-CVE cache entries available.")
    table.add_row("EPSS", f"{epss_hits}/{len(cve_ids)}", "Fresh per-CVE cache entries available.")
    table.add_row(
        "KEV",
        f"{kev_hits}/{len(cve_ids)}",
        "Coverage derived from the cached KEV catalog index.",
    )
    return table


def render_local_file_table(rows: list[dict[str, str | int]], *, title: str) -> Table:
    table = Table(title=title, show_lines=False)
    table.add_column("Label", style="bold")
    table.add_column("Path")
    table.add_column("Size (bytes)")
    table.add_column("SHA256")

    for row in rows:
        table.add_row(
            str(row["label"]),
            str(row["path"]),
            str(row["size_bytes"]),
            str(row["sha256"]),
        )
    return table


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    digest.update(path.read_bytes())
    return digest.hexdigest()

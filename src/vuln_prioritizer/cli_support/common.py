"""Shared CLI enums and helpers."""

from __future__ import annotations

from collections.abc import MutableMapping
from enum import StrEnum
from pathlib import Path
from typing import Any, NoReturn

import typer
from rich.console import Console
from rich.panel import Panel

from vuln_prioritizer import __version__
from vuln_prioritizer.runtime_config import (
    LoadedRuntimeConfig,
    discover_runtime_config,
    load_runtime_config,
)

console = Console()


class OutputFormat(StrEnum):
    markdown = "markdown"
    json = "json"
    sarif = "sarif"
    table = "table"


class ReportOutputFormat(StrEnum):
    markdown = "markdown"
    json = "json"
    table = "table"


class TableJsonOutputFormat(StrEnum):
    table = "table"
    json = "json"


class SnapshotCreateOutputFormat(StrEnum):
    json = "json"
    markdown = "markdown"


FULL_OUTPUT_FORMATS = (
    OutputFormat.markdown,
    OutputFormat.json,
    OutputFormat.sarif,
    OutputFormat.table,
)
REPORT_OUTPUT_FORMATS = (
    ReportOutputFormat.markdown,
    ReportOutputFormat.json,
    ReportOutputFormat.table,
)
TABLE_AND_JSON_OUTPUT_FORMATS = (
    TableJsonOutputFormat.table,
    TableJsonOutputFormat.json,
)
SNAPSHOT_CREATE_OUTPUT_FORMATS = (
    SnapshotCreateOutputFormat.json,
    SnapshotCreateOutputFormat.markdown,
)


class PriorityFilter(StrEnum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"


class SortBy(StrEnum):
    priority = "priority"
    epss = "epss"
    cvss = "cvss"
    cve = "cve"


class AttackSource(StrEnum):
    none = "none"
    local_csv = "local-csv"
    ctid_json = "ctid-json"


class InputFormat(StrEnum):
    auto = "auto"
    cve_list = "cve-list"
    trivy_json = "trivy-json"
    grype_json = "grype-json"
    cyclonedx_json = "cyclonedx-json"
    spdx_json = "spdx-json"
    dependency_check_json = "dependency-check-json"
    github_alerts_json = "github-alerts-json"
    nessus_xml = "nessus-xml"
    openvas_xml = "openvas-xml"


class PolicyProfile(StrEnum):
    default = "default"
    enterprise = "enterprise"
    conservative = "conservative"


class DataSourceName(StrEnum):
    all = "all"
    nvd = "nvd"
    epss = "epss"
    kev = "kev"


class TargetKind(StrEnum):
    generic = "generic"
    image = "image"
    repository = "repository"
    filesystem = "filesystem"
    host = "host"


class RollupBy(StrEnum):
    asset = "asset"
    service = "service"


class StateWaiverStatusFilter(StrEnum):
    all = "all"
    active = "active"
    review_due = "review_due"
    expired = "expired"


class StatePriorityScope(StrEnum):
    all = "all"
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"


PRIORITY_LABELS = {
    PriorityFilter.critical: "Critical",
    PriorityFilter.high: "High",
    PriorityFilter.medium: "Medium",
    PriorityFilter.low: "Low",
}


def format_metavar(allowed_formats: tuple[StrEnum, ...]) -> str:
    return "[" + "|".join(item.value for item in allowed_formats) + "]"


def output_format_option(default: StrEnum, allowed_formats: tuple[StrEnum, ...]) -> Any:
    return typer.Option(
        default,
        "--format",
        metavar=format_metavar(allowed_formats),
        show_choices=False,
    )


def version_callback(value: bool) -> None:
    if not value:
        return
    typer.echo(f"vuln-prioritizer {__version__}")
    raise typer.Exit()


def validate_output_mode(format: StrEnum, output: Path | None) -> None:
    if format == OutputFormat.table and output is not None:
        console.print(
            "[red]Input validation failed:[/red] "
            "--output cannot be used together with --format table."
        )
        raise typer.Exit(code=2)


def validate_unique_output_paths(paths: dict[str, Path | None]) -> None:
    resolved: dict[Path, str] = {}
    for label, path in paths.items():
        if path is None:
            continue
        resolved_path = path.resolve()
        if resolved_path in resolved:
            exit_input_validation(
                f"{resolved[resolved_path]} and {label} must point to different files."
            )
        resolved[resolved_path] = label


def load_runtime_config_for_session(
    *,
    config: Path | None,
    no_config: bool,
) -> LoadedRuntimeConfig | None:
    if no_config:
        return None

    config_path = config
    if config_path is None:
        config_path = discover_runtime_config(Path.cwd())
    if config_path is None:
        return None

    try:
        return load_runtime_config(config_path)
    except ValueError as exc:
        exit_input_validation(str(exc))
    raise AssertionError("unreachable")


def merge_default_maps(
    current: MutableMapping[str, object] | None,
    update: dict[str, object],
) -> dict[str, object]:
    if current is None:
        return update
    merged = dict(current)
    for key, value in update.items():
        existing = merged.get(key)
        if isinstance(existing, dict) and isinstance(value, dict):
            merged[key] = merge_default_maps(existing, value)
        else:
            merged[key] = value
    return merged


def runtime_config_path(ctx: typer.Context) -> Path | None:
    root = ctx.find_root()
    obj = root.obj if isinstance(root.obj, dict) else {}
    loaded = obj.get("runtime_config")
    if isinstance(loaded, LoadedRuntimeConfig):
        return loaded.path
    return None


def runtime_config(ctx: typer.Context) -> LoadedRuntimeConfig | None:
    root = ctx.find_root()
    obj = root.obj if isinstance(root.obj, dict) else {}
    loaded = obj.get("runtime_config")
    return loaded if isinstance(loaded, LoadedRuntimeConfig) else None


def validate_command_formats(
    *,
    command_name: str,
    format: StrEnum,
    allowed_formats: set[StrEnum],
) -> None:
    if format in allowed_formats:
        return

    supported = ", ".join(
        item.value for item in sorted(allowed_formats, key=lambda item: item.value)
    )
    console.print(
        f"[red]Input validation failed:[/red] {command_name} supports only --format {supported}."
    )
    raise typer.Exit(code=2)


def print_warnings(warnings: list[str]) -> None:
    if warnings:
        console.print(
            Panel(
                "\n".join(f"- {warning}" for warning in warnings),
                title="Warnings",
                border_style="yellow",
            )
        )


def exit_input_validation(message: str) -> NoReturn:
    console.print(f"[red]Input validation failed:[/red] {message}")
    raise typer.Exit(code=2)

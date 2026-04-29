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
from vuln_prioritizer.cli_options import (
    FULL_OUTPUT_FORMATS,
    PRIORITY_LABELS,
    REPORT_OUTPUT_FORMATS,
    SNAPSHOT_CREATE_OUTPUT_FORMATS,
    TABLE_AND_JSON_OUTPUT_FORMATS,
    AttackSource,
    DataSourceName,
    InputFormat,
    OutputFormat,
    PolicyProfile,
    PriorityFilter,
    ReportOutputFormat,
    RollupBy,
    SnapshotCreateOutputFormat,
    SortBy,
    StatePriorityScope,
    StateWaiverStatusFilter,
    SummaryTemplate,
    TableJsonOutputFormat,
    TargetKind,
)
from vuln_prioritizer.inputs.loader import InputSpec
from vuln_prioritizer.runtime_config import (
    LoadedRuntimeConfig,
    discover_runtime_config,
    load_runtime_config,
)

console = Console()

__all__ = [
    "FULL_OUTPUT_FORMATS",
    "PRIORITY_LABELS",
    "REPORT_OUTPUT_FORMATS",
    "SNAPSHOT_CREATE_OUTPUT_FORMATS",
    "TABLE_AND_JSON_OUTPUT_FORMATS",
    "AttackSource",
    "DataSourceName",
    "InputFormat",
    "OutputFormat",
    "PolicyProfile",
    "PriorityFilter",
    "ReportOutputFormat",
    "RollupBy",
    "SnapshotCreateOutputFormat",
    "SortBy",
    "StatePriorityScope",
    "StateWaiverStatusFilter",
    "SummaryTemplate",
    "TableJsonOutputFormat",
    "TargetKind",
    "build_input_specs_or_exit",
    "console",
    "emit_stdout",
    "exit_input_validation",
    "format_metavar",
    "load_runtime_config_for_session",
    "merge_default_maps",
    "output_format_option",
    "print_warnings",
    "runtime_config",
    "runtime_config_path",
    "should_emit_json_stdout",
    "validate_command_formats",
    "validate_output_mode",
    "validate_unique_output_paths",
    "version_callback",
]


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


def build_input_specs_or_exit(
    *,
    input_paths: list[Path] | None,
    input_formats: list[InputFormat] | None,
    command_name: str,
    require_inputs: bool,
) -> list[InputSpec]:
    paths = input_paths or []
    if require_inputs and not paths:
        exit_input_validation(f"{command_name} requires at least one --input.")
    if not paths:
        return []

    format_values = [item.value for item in (input_formats or [])]
    if not format_values:
        format_values = [InputFormat.auto.value] * len(paths)
    elif len(format_values) == 1:
        format_values = format_values * len(paths)
    elif len(format_values) != len(paths):
        exit_input_validation(
            f"{command_name} received {len(paths)} --input value(s) but "
            f"{len(format_values)} --input-format value(s). Use one shared --input-format "
            "or one --input-format per --input."
        )

    return [
        InputSpec(path=path, input_format=input_format)
        for path, input_format in zip(paths, format_values, strict=True)
    ]


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


def should_emit_json_stdout(format: StrEnum, output: Path | None) -> bool:
    return format.value == "json" and output is None


def emit_stdout(content: str) -> None:
    typer.echo(content)


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

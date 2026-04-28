"""Input validation command registrations."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

import typer
from pydantic import ValidationError
from rich.panel import Panel
from rich.table import Table

from vuln_prioritizer.cli_support.common import (
    TABLE_AND_JSON_OUTPUT_FORMATS,
    InputFormat,
    TableJsonOutputFormat,
    TargetKind,
    build_input_specs_or_exit,
    console,
    emit_stdout,
    exit_input_validation,
    output_format_option,
    print_warnings,
    should_emit_json_stdout,
    validate_command_formats,
    validate_output_mode,
)
from vuln_prioritizer.inputs import InputLoader, load_asset_context_file, load_vex_files
from vuln_prioritizer.inputs.loader import (
    AssetContextCatalog,
    AssetContextLoadDiagnostics,
    VexLoadDiagnostics,
)
from vuln_prioritizer.reporter import write_output
from vuln_prioritizer.utils import iso_utc_now


def input_validate(
    input: list[Path] | None = typer.Option(
        None, "--input", exists=True, dir_okay=False, readable=True
    ),
    input_format: list[InputFormat] | None = typer.Option(None, "--input-format"),
    asset_context: Path | None = typer.Option(None, "--asset-context", dir_okay=False),
    vex_file: list[Path] | None = typer.Option(None, "--vex-file", dir_okay=False),
    target_kind: TargetKind = typer.Option(TargetKind.generic, "--target-kind"),
    target_ref: str | None = typer.Option(None, "--target-ref"),
    max_cves: int | None = typer.Option(None, "--max-cves", min=1),
    output: Path | None = typer.Option(None, "--output", dir_okay=False),
    format: TableJsonOutputFormat = output_format_option(
        TableJsonOutputFormat.table, TABLE_AND_JSON_OUTPUT_FORMATS
    ),
    strict: bool = typer.Option(False, "--strict"),
) -> None:
    """Validate local input, asset context, and VEX files without provider lookups."""
    validate_output_mode(format, output)
    validate_command_formats(
        command_name="input validate",
        format=format,
        allowed_formats=set(TABLE_AND_JSON_OUTPUT_FORMATS),
    )
    if not input and asset_context is None and not vex_file:
        exit_input_validation("input validate requires --input, --asset-context, or --vex-file.")

    input_specs = build_input_specs_or_exit(
        input_paths=input,
        input_formats=input_format,
        command_name="input validate",
        require_inputs=False,
    )
    try:
        asset_records, asset_diagnostics = load_asset_context_file(
            asset_context,
            return_diagnostics=True,
        )
        vex_statements, vex_diagnostics = load_vex_files(
            vex_file or [],
            return_diagnostics=True,
        )
        parsed_input = (
            InputLoader().load_many(
                input_specs,
                max_cves=max_cves,
                target_kind=target_kind.value,
                target_ref=target_ref,
                asset_records=asset_records,
                vex_statements=vex_statements,
            )
            if input_specs
            else None
        )
    except (OSError, ValidationError, ValueError) as exc:
        exit_input_validation(str(exc))

    report = build_input_validation_report(
        input_paths=input or [],
        input_format=input_format,
        output=output,
        max_cves=max_cves,
        target_kind=target_kind.value,
        target_ref=target_ref,
        asset_context=asset_context,
        asset_records=asset_records,
        asset_diagnostics=asset_diagnostics,
        vex_files=vex_file or [],
        vex_statements=vex_statements,
        vex_diagnostics=vex_diagnostics,
        parsed_input=parsed_input,
    )
    json_payload = json.dumps(report, indent=2, sort_keys=True)

    if should_emit_json_stdout(format, output):
        emit_stdout(json_payload)
        if strict and not report["summary"]["ok"]:
            raise typer.Exit(code=1)
        return

    console.print(render_input_validation_panel(report))
    if report["sources"]:
        console.print(render_input_validation_sources_table(report))
    print_warnings(report["warnings"])

    if output is not None:
        write_output(output, json_payload)
        console.print(f"[green]Wrote json output to {output}[/green]")
    if strict and not report["summary"]["ok"]:
        raise typer.Exit(code=1)


def input_inspect(
    input: list[Path] = typer.Option(..., "--input", exists=True, dir_okay=False, readable=True),
    input_format: list[InputFormat] | None = typer.Option(None, "--input-format"),
    asset_context: Path | None = typer.Option(None, "--asset-context", dir_okay=False),
    vex_file: list[Path] | None = typer.Option(None, "--vex-file", dir_okay=False),
    target_kind: TargetKind = typer.Option(TargetKind.generic, "--target-kind"),
    target_ref: str | None = typer.Option(None, "--target-ref"),
    max_cves: int | None = typer.Option(None, "--max-cves", min=1),
    output: Path | None = typer.Option(None, "--output", dir_okay=False),
    format: TableJsonOutputFormat = output_format_option(
        TableJsonOutputFormat.json, TABLE_AND_JSON_OUTPUT_FORMATS
    ),
) -> None:
    """Emit normalized input occurrences without provider lookups."""
    _run_input_inspect(
        input=input,
        input_format=input_format,
        asset_context=asset_context,
        vex_file=vex_file,
        target_kind=target_kind,
        target_ref=target_ref,
        max_cves=max_cves,
        output=output,
        format=format,
        command_name="input inspect",
    )


def _run_input_inspect(
    *,
    input: list[Path],
    input_format: list[InputFormat] | None,
    asset_context: Path | None,
    vex_file: list[Path] | None,
    target_kind: TargetKind,
    target_ref: str | None,
    max_cves: int | None,
    output: Path | None,
    format: TableJsonOutputFormat,
    command_name: str,
) -> None:
    validate_output_mode(format, output)
    validate_command_formats(
        command_name=command_name,
        format=format,
        allowed_formats=set(TABLE_AND_JSON_OUTPUT_FORMATS),
    )
    input_specs = build_input_specs_or_exit(
        input_paths=input,
        input_formats=input_format,
        command_name=command_name,
        require_inputs=True,
    )
    try:
        asset_records = load_asset_context_file(asset_context)
        vex_statements = load_vex_files(vex_file or [])
        parsed_input = InputLoader().load_many(
            input_specs,
            max_cves=max_cves,
            target_kind=target_kind.value,
            target_ref=target_ref,
            asset_records=asset_records,
            vex_statements=vex_statements,
        )
    except (OSError, ValidationError, ValueError) as exc:
        exit_input_validation(str(exc))

    warnings = list(parsed_input.warnings)
    report = {
        "metadata": {
            "schema_version": "1.3.0",
            "command": command_name,
            "generated_at": iso_utc_now(),
            "input_paths": [str(path) for path in input],
            "input_format": parsed_input.input_format,
            "output_format": format.value,
            "output_path": str(output) if output else None,
            "asset_context": str(asset_context) if asset_context else None,
            "vex_files": [str(path) for path in vex_file or []],
            "target_kind": target_kind.value,
            "target_ref": target_ref,
            "max_cves": max_cves,
        },
        "summary": {
            "total_rows": parsed_input.total_rows,
            "occurrence_count": len(parsed_input.occurrences),
            "unique_cves": len(parsed_input.unique_cves),
            "included_occurrence_count": parsed_input.included_occurrence_count,
            "included_unique_cves": parsed_input.included_unique_cves,
            "warning_count": len(parsed_input.warnings),
        },
        "sources": [source.model_dump() for source in parsed_input.source_summaries],
        "unique_cves": parsed_input.unique_cves,
        "occurrences": [occurrence.model_dump() for occurrence in parsed_input.occurrences],
        "warnings": warnings,
    }
    json_payload = json.dumps(report, indent=2, sort_keys=True)

    if should_emit_json_stdout(format, output):
        emit_stdout(json_payload)
        return

    console.print(render_input_inspect_table(report))
    print_warnings(warnings)
    if output is not None:
        write_output(output, json_payload)
        console.print(f"[green]Wrote json output to {output}[/green]")


def input_normalize(
    input: list[Path] = typer.Option(..., "--input", exists=True, dir_okay=False, readable=True),
    input_format: list[InputFormat] | None = typer.Option(None, "--input-format"),
    asset_context: Path | None = typer.Option(None, "--asset-context", dir_okay=False),
    vex_file: list[Path] | None = typer.Option(None, "--vex-file", dir_okay=False),
    target_kind: TargetKind = typer.Option(TargetKind.generic, "--target-kind"),
    target_ref: str | None = typer.Option(None, "--target-ref"),
    max_cves: int | None = typer.Option(None, "--max-cves", min=1),
    output: Path | None = typer.Option(None, "--output", dir_okay=False),
    format: TableJsonOutputFormat = output_format_option(
        TableJsonOutputFormat.json, TABLE_AND_JSON_OUTPUT_FORMATS
    ),
) -> None:
    """Alias for input inspect."""
    _run_input_inspect(
        input=input,
        input_format=input_format,
        asset_context=asset_context,
        vex_file=vex_file,
        target_kind=target_kind,
        target_ref=target_ref,
        max_cves=max_cves,
        output=output,
        format=format,
        command_name="input normalize",
    )


def render_input_inspect_table(report: dict[str, Any]) -> Table:
    table = Table(title="Normalized Occurrences", show_lines=False)
    table.add_column("CVE")
    table.add_column("Format")
    table.add_column("Component")
    table.add_column("Version")
    table.add_column("Target")
    table.add_column("Asset")
    for occurrence in report["occurrences"][:50]:
        table.add_row(
            occurrence.get("cve_id") or "",
            occurrence.get("source_format") or "",
            occurrence.get("component_name") or "",
            occurrence.get("component_version") or "",
            occurrence.get("target_ref") or "",
            occurrence.get("asset_id") or "",
        )
    return table


def build_input_validation_report(
    *,
    input_paths: list[Path],
    input_format: list[InputFormat] | None,
    output: Path | None,
    max_cves: int | None,
    target_kind: str,
    target_ref: str | None,
    asset_context: Path | None,
    asset_records: AssetContextCatalog,
    asset_diagnostics: AssetContextLoadDiagnostics,
    vex_files: list[Path],
    vex_statements: list[Any],
    vex_diagnostics: VexLoadDiagnostics,
    parsed_input: Any,
) -> dict[str, Any]:
    warnings = merge_warning_messages(
        list(parsed_input.warnings) if parsed_input is not None else [],
        list(asset_diagnostics.warnings),
        list(vex_diagnostics.warnings),
    )
    status_counts = Counter(statement.status for statement in vex_statements)
    return {
        "metadata": {
            "schema_version": "1.2.0",
            "command": "input validate",
            "generated_at": iso_utc_now(),
            "input_path": str(input_paths[0]) if input_paths else None,
            "input_paths": [str(path) for path in input_paths],
            "input_format": _input_validation_format(input_format),
            "output_format": "json",
            "output_path": str(output) if output else None,
            "asset_context": str(asset_context) if asset_context else None,
            "vex_files": [str(path) for path in vex_files],
            "target_kind": target_kind,
            "target_ref": target_ref,
            "max_cves": max_cves,
        },
        "summary": {
            "ok": not warnings,
            "total_rows": int(getattr(parsed_input, "total_rows", 0)),
            "occurrence_count": len(getattr(parsed_input, "occurrences", [])),
            "unique_cves": len(getattr(parsed_input, "unique_cves", [])),
            "included_occurrence_count": int(getattr(parsed_input, "included_occurrence_count", 0)),
            "included_unique_cves": int(getattr(parsed_input, "included_unique_cves", 0)),
            "input_source_count": len(getattr(parsed_input, "source_summaries", [])),
            "warning_count": len(warnings),
            "asset_context_rows": asset_diagnostics.loaded_rows,
            "asset_context_skipped_rows": asset_diagnostics.skipped_rows,
            "asset_context_rules": len(asset_records.rules),
            "vex_statement_count": len(vex_statements),
            "vex_skipped_statements": vex_diagnostics.skipped_statements,
            "asset_match_conflict_count": int(
                getattr(parsed_input, "asset_match_conflict_count", 0)
            ),
            "vex_conflict_count": int(getattr(parsed_input, "vex_conflict_count", 0)),
        },
        "sources": [
            source.model_dump() for source in getattr(parsed_input, "source_summaries", [])
        ],
        "asset_context": {
            "total_rows": asset_diagnostics.total_rows,
            "loaded_rows": asset_diagnostics.loaded_rows,
            "skipped_rows": asset_diagnostics.skipped_rows,
            "exact_rules": asset_diagnostics.exact_rules,
            "glob_rules": asset_diagnostics.glob_rules,
            "legacy_schema": asset_diagnostics.legacy_schema,
            "warnings": list(asset_diagnostics.warnings),
        },
        "vex": {
            "file_count": len(vex_files),
            "statement_count": len(vex_statements),
            "skipped_statements": vex_diagnostics.skipped_statements,
            "statuses": dict(sorted(status_counts.items())),
            "warnings": list(vex_diagnostics.warnings),
        },
        "warnings": warnings,
    }


def render_input_validation_panel(report: dict[str, Any]) -> Panel:
    summary = report["summary"]
    metadata = report["metadata"]
    lines = [
        f"Input files: {len(metadata['input_paths'])}",
        f"Total rows: {summary['total_rows']}",
        f"Occurrences: {summary['occurrence_count']}",
        f"Unique CVEs: {summary['unique_cves']}",
        f"Asset context rules: {summary['asset_context_rules']}",
        f"Skipped asset rows: {summary['asset_context_skipped_rows']}",
        f"VEX statements: {summary['vex_statement_count']}",
        f"Skipped VEX statements: {summary['vex_skipped_statements']}",
        f"Warnings: {summary['warning_count']}",
    ]
    return Panel("\n".join(lines), title="Input Validation")


def render_input_validation_sources_table(report: dict[str, Any]) -> Table:
    table = Table(title="Input Sources", show_lines=False)
    table.add_column("Input")
    table.add_column("Format")
    table.add_column("Rows", justify="right")
    table.add_column("Occurrences", justify="right")
    table.add_column("Unique CVEs", justify="right")
    table.add_column("Warnings", justify="right")
    for source in report["sources"]:
        table.add_row(
            source["input_path"],
            source["input_format"],
            str(source["total_rows"]),
            str(source["occurrence_count"]),
            str(source["unique_cves"]),
            str(source["warning_count"]),
        )
    return table


def _input_validation_format(input_format: list[InputFormat] | None) -> str:
    values = [item.value for item in input_format or []]
    if not values:
        return InputFormat.auto.value
    if len(set(values)) == 1:
        return values[0]
    return "mixed"


def merge_warning_messages(*groups: list[str]) -> list[str]:
    merged: list[str] = []
    seen: set[str] = set()
    for group in groups:
        for warning in group:
            if warning in seen:
                continue
            seen.add(warning)
            merged.append(warning)
    return merged


def register(input_app: typer.Typer) -> None:
    input_app.command("validate")(input_validate)
    input_app.command("inspect")(input_inspect)
    input_app.command("normalize")(input_normalize)

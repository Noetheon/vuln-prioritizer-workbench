"""Report command registrations."""

from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.panel import Panel

from vuln_prioritizer.cli_support.common import (
    TABLE_AND_JSON_OUTPUT_FORMATS,
    TableJsonOutputFormat,
    console,
    emit_stdout,
    output_format_option,
    should_emit_json_stdout,
    validate_command_formats,
    validate_output_mode,
)
from vuln_prioritizer.cli_support.report_io import (
    load_analysis_report_payload,
    verify_evidence_bundle,
    write_evidence_bundle,
)
from vuln_prioritizer.reporter import (
    generate_evidence_bundle_verification_json,
    generate_html_report,
    render_evidence_bundle_verification_table,
    write_output,
)
from vuln_prioritizer.reporting_payloads import generate_summary_markdown
from vuln_prioritizer.sarif_validation import validate_sarif_file
from vuln_prioritizer.services.workbench_reports import (
    generate_findings_csv,
    generate_workbench_sarif,
)

WORKBENCH_REPORT_FORMATS = {"json", "markdown", "html", "csv", "sarif"}


def report_html(
    input: Path = typer.Option(..., "--input", exists=True, dir_okay=False, readable=True),
    output: Path = typer.Option(..., "--output", dir_okay=False),
) -> None:
    """Render a static HTML report from an analysis JSON export."""
    payload = load_analysis_report_payload(input)
    write_output(output, generate_html_report(payload))
    console.print(f"[green]Wrote html output to {output}[/green]")


def report_workbench(
    input: Path = typer.Option(..., "--input", exists=True, dir_okay=False, readable=True),
    output: Path = typer.Option(..., "--output", dir_okay=False),
    format: str = typer.Option("html", "--format"),
) -> None:
    """Render a Workbench-style report from an analysis JSON export."""
    if format not in WORKBENCH_REPORT_FORMATS:
        console.print(
            f"[red]Input validation failed:[/red] Unsupported Workbench report format: {format}."
        )
        raise typer.Exit(code=2)
    payload = load_analysis_report_payload(input)
    if format == "json":
        document = json.dumps(payload, indent=2, sort_keys=True)
    elif format == "markdown":
        document = generate_summary_markdown(payload)
    elif format == "html":
        document = generate_html_report(payload)
    elif format == "csv":
        document = generate_findings_csv(payload)
    else:
        document = generate_workbench_sarif(payload)
    write_output(output, document)
    console.print(f"[green]Wrote {format} Workbench report output to {output}[/green]")


def report_evidence_bundle(
    input: Path = typer.Option(..., "--input", exists=True, dir_okay=False, readable=True),
    output: Path = typer.Option(..., "--output", dir_okay=False),
    include_input_copy: bool = typer.Option(True, "--include-input-copy/--no-include-input-copy"),
) -> None:
    """Build a reproducible evidence bundle from an analysis JSON export."""
    payload = load_analysis_report_payload(input)
    manifest = write_evidence_bundle(
        analysis_path=input,
        output_path=output,
        payload=payload,
        include_input_copy=include_input_copy,
    )
    console.print(f"[green]Wrote evidence bundle to {output}[/green]")
    console.print(f"[green]Included {len(manifest.files)} artifact(s) plus manifest.[/green]")


def report_verify_evidence_bundle(
    input: Path = typer.Option(..., "--input", exists=True, dir_okay=False, readable=True),
    output: Path | None = typer.Option(None, "--output", dir_okay=False),
    format: TableJsonOutputFormat = output_format_option(
        TableJsonOutputFormat.table, TABLE_AND_JSON_OUTPUT_FORMATS
    ),
) -> None:
    """Verify evidence bundle manifest integrity against the ZIP members."""
    validate_output_mode(format, output)
    validate_command_formats(
        command_name="report verify-evidence-bundle",
        format=format,
        allowed_formats=set(TABLE_AND_JSON_OUTPUT_FORMATS),
    )

    metadata, summary, items = verify_evidence_bundle(input)
    json_payload = generate_evidence_bundle_verification_json(items, summary, metadata)
    if should_emit_json_stdout(format, output):
        emit_stdout(json_payload)
        if not summary.ok:
            raise typer.Exit(code=1)
        return

    console.print(
        Panel(
            "\n".join(
                [
                    f"Bundle: {metadata.bundle_path}",
                    f"Manifest schema: {metadata.manifest_schema_version or 'unavailable'}",
                    f"Verification result: {'passed' if summary.ok else 'failed'}",
                ]
            ),
            title="Evidence Bundle",
        )
    )
    console.print(render_evidence_bundle_verification_table(items, summary))

    if output is not None:
        write_output(output, json_payload)
        console.print(f"[green]Wrote json output to {output}[/green]")

    if not summary.ok:
        raise typer.Exit(code=1)


def report_validate_sarif(
    input: Path = typer.Option(..., "--input", exists=True, dir_okay=False, readable=True),
    output: Path | None = typer.Option(None, "--output", dir_okay=False),
    format: TableJsonOutputFormat = output_format_option(
        TableJsonOutputFormat.table, TABLE_AND_JSON_OUTPUT_FORMATS
    ),
) -> None:
    """Validate a SARIF 2.1.0 report before CI upload."""
    validate_output_mode(format, output)
    validate_command_formats(
        command_name="report validate-sarif",
        format=format,
        allowed_formats=set(TABLE_AND_JSON_OUTPUT_FORMATS),
    )
    try:
        payload, errors = validate_sarif_file(input)
    except ValueError as exc:
        console.print(f"[red]Input validation failed:[/red] {exc}")
        raise typer.Exit(code=2) from exc
    result = {
        "schema_version": "1.2.0",
        "artifact_kind": "sarif-validation-report",
        "input_path": str(input),
        "ok": not errors,
        "sarif_version": payload.get("version"),
        "run_count": len(payload.get("runs", [])) if isinstance(payload.get("runs"), list) else 0,
        "error_count": len(errors),
        "errors": errors,
    }
    if format == TableJsonOutputFormat.json:
        document = json.dumps(result, indent=2, sort_keys=True)
        if output is not None:
            write_output(output, document)
            console.print(f"[green]Wrote json output to {output}[/green]")
        else:
            emit_stdout(document)
        if errors:
            raise typer.Exit(code=1)
        return

    console.print(
        Panel(
            "\n".join(
                [
                    f"Input: {input}",
                    f"SARIF version: {payload.get('version') or 'unavailable'}",
                    f"Validation result: {'passed' if not errors else 'failed'}",
                    f"Errors: {len(errors)}",
                ]
            ),
            title="SARIF Validation",
        )
    )
    if errors:
        for error in errors:
            console.print(f"[red]- {error}[/red]")
        raise typer.Exit(code=1)


def register(report_app: typer.Typer) -> None:
    report_app.command("html")(report_html)
    report_app.command("workbench")(report_workbench)
    report_app.command("evidence-bundle")(report_evidence_bundle)
    report_app.command("verify-evidence-bundle")(report_verify_evidence_bundle)
    report_app.command("validate-sarif")(report_validate_sarif)

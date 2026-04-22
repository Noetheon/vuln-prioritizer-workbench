"""Report command registrations."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.panel import Panel

from vuln_prioritizer.cli_support.common import (
    TABLE_AND_JSON_OUTPUT_FORMATS,
    TableJsonOutputFormat,
    console,
    output_format_option,
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


def report_html(
    input: Path = typer.Option(..., "--input", exists=True, dir_okay=False, readable=True),
    output: Path = typer.Option(..., "--output", dir_okay=False),
) -> None:
    """Render a static HTML report from an analysis JSON export."""
    payload = load_analysis_report_payload(input)
    write_output(output, generate_html_report(payload))
    console.print(f"[green]Wrote html output to {output}[/green]")


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
        write_output(output, generate_evidence_bundle_verification_json(items, summary, metadata))
        console.print(f"[green]Wrote json output to {output}[/green]")

    if not summary.ok:
        raise typer.Exit(code=1)


def register(report_app: typer.Typer) -> None:
    report_app.command("html")(report_html)
    report_app.command("evidence-bundle")(report_evidence_bundle)
    report_app.command("verify-evidence-bundle")(report_verify_evidence_bundle)

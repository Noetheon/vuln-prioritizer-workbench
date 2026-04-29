"""ATT&CK command registrations."""

from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import typer
from rich.panel import Panel

from vuln_prioritizer.cli_support.attack_support import (
    format_distribution,
    generate_attack_coverage_markdown,
    generate_attack_validation_markdown,
    load_attack_only_or_exit,
    read_input_cves_from_specs,
    render_attack_coverage_table,
    render_attack_validation_panel,
    validate_attack_inputs_or_exit,
)
from vuln_prioritizer.cli_support.common import (
    REPORT_OUTPUT_FORMATS,
    AttackSource,
    InputFormat,
    OutputFormat,
    ReportOutputFormat,
    build_input_specs_or_exit,
    console,
    emit_stdout,
    output_format_option,
    print_warnings,
    should_emit_json_stdout,
    validate_command_formats,
    validate_output_mode,
)
from vuln_prioritizer.reporter import write_output
from vuln_prioritizer.services.attack_enrichment import AttackEnrichmentService


def attack_validate(
    attack_source: AttackSource = typer.Option(AttackSource.ctid_json, "--attack-source"),
    attack_mapping_file: Path = typer.Option(..., "--attack-mapping-file", dir_okay=False),
    attack_technique_metadata_file: Path | None = typer.Option(
        None, "--attack-technique-metadata-file", dir_okay=False
    ),
    output: Path | None = typer.Option(None, "--output", dir_okay=False),
    format: ReportOutputFormat = output_format_option(
        ReportOutputFormat.table, REPORT_OUTPUT_FORMATS
    ),
) -> None:
    """Validate local ATT&CK mapping and metadata files."""
    validate_output_mode(format, output)
    validate_command_formats(
        command_name="attack validate",
        format=format,
        allowed_formats=set(REPORT_OUTPUT_FORMATS),
    )

    result = validate_attack_inputs_or_exit(
        attack_source=attack_source.value,
        attack_mapping_file=attack_mapping_file,
        attack_technique_metadata_file=attack_technique_metadata_file,
    )

    json_payload = json.dumps(result, indent=2, sort_keys=True)
    if should_emit_json_stdout(format, output):
        emit_stdout(json_payload)
        return

    console.print(render_attack_validation_panel(result))
    print_warnings(cast(list[str], result["warnings"]))

    if output is not None:
        if format == OutputFormat.markdown:
            write_output(output, generate_attack_validation_markdown(result))
        elif format == OutputFormat.json:
            write_output(output, json_payload)
        console.print(f"[green]Wrote {format.value} output to {output}[/green]")


def attack_coverage(
    input: list[Path] = typer.Option(..., "--input", exists=True, dir_okay=False, readable=True),
    input_format: list[InputFormat] | None = typer.Option(None, "--input-format"),
    attack_source: AttackSource = typer.Option(AttackSource.ctid_json, "--attack-source"),
    attack_mapping_file: Path = typer.Option(..., "--attack-mapping-file", dir_okay=False),
    attack_technique_metadata_file: Path | None = typer.Option(
        None, "--attack-technique-metadata-file", dir_okay=False
    ),
    output: Path | None = typer.Option(None, "--output", dir_okay=False),
    format: ReportOutputFormat = output_format_option(
        ReportOutputFormat.table, REPORT_OUTPUT_FORMATS
    ),
    max_cves: int | None = typer.Option(None, "--max-cves", min=1),
) -> None:
    """Show ATT&CK coverage for a local CVE list."""
    validate_output_mode(format, output)
    validate_command_formats(
        command_name="attack coverage",
        format=format,
        allowed_formats=set(REPORT_OUTPUT_FORMATS),
    )

    input_specs = build_input_specs_or_exit(
        input_paths=input,
        input_formats=input_format,
        command_name="attack coverage",
        require_inputs=True,
    )
    (
        cve_ids,
        total_input_rows,
        parser_warnings,
        input_sources,
        effective_input_format,
        input_paths,
    ) = read_input_cves_from_specs(input_specs, max_cves=max_cves)
    attack_items, metadata, warnings = load_attack_only_or_exit(
        cve_ids,
        attack_source=attack_source.value,
        attack_mapping_file=attack_mapping_file,
        attack_technique_metadata_file=attack_technique_metadata_file,
    )
    summary = AttackEnrichmentService().summarize(attack_items)
    warnings = parser_warnings + warnings
    json_payload = json.dumps(
        {
            "metadata": {
                "schema_version": "1.2.0",
                "input_path": input_paths[0] if input_paths else str(input[0]),
                "input_paths": input_paths,
                "input_format": effective_input_format,
                "input_sources": input_sources,
                "max_cves": max_cves,
                **metadata,
            },
            "summary": summary.model_dump(),
            "items": [item.model_dump() for item in attack_items],
            "warnings": warnings,
        },
        indent=2,
        sort_keys=True,
    )

    if should_emit_json_stdout(format, output):
        emit_stdout(json_payload)
        return

    console.print(render_attack_coverage_table(attack_items))
    console.print(
        Panel(
            "\n".join(
                [
                    f"Total input rows: {total_input_rows}",
                    f"Valid unique CVEs: {len(cve_ids)}",
                    f"Mapped CVEs: {summary.mapped_cves}",
                    f"Unmapped CVEs: {summary.unmapped_cves}",
                    f"ATT&CK source: {metadata['source']}",
                    "Mapping type distribution: "
                    + format_distribution(summary.mapping_type_distribution),
                    "Technique distribution: "
                    + format_distribution(summary.technique_distribution),
                    "Tactic distribution: " + format_distribution(summary.tactic_distribution),
                ]
            ),
            title="ATT&CK Coverage",
        )
    )
    print_warnings(warnings)

    if output is not None:
        if format == OutputFormat.markdown:
            write_output(
                output,
                generate_attack_coverage_markdown(
                    input_path=", ".join(input_paths),
                    attack_items=attack_items,
                    summary=summary,
                    metadata=metadata,
                    warnings=warnings,
                ),
            )
        elif format == OutputFormat.json:
            write_output(output, json_payload)
        console.print(f"[green]Wrote {format.value} output to {output}[/green]")


def attack_navigator_layer(
    input: list[Path] = typer.Option(..., "--input", exists=True, dir_okay=False, readable=True),
    input_format: list[InputFormat] | None = typer.Option(None, "--input-format"),
    attack_source: AttackSource = typer.Option(AttackSource.ctid_json, "--attack-source"),
    attack_mapping_file: Path = typer.Option(..., "--attack-mapping-file", dir_okay=False),
    attack_technique_metadata_file: Path | None = typer.Option(
        None, "--attack-technique-metadata-file", dir_okay=False
    ),
    output: Path = typer.Option(..., "--output", dir_okay=False),
    max_cves: int | None = typer.Option(None, "--max-cves", min=1),
) -> None:
    """Export an ATT&CK Navigator layer from local mapping coverage."""
    input_specs = build_input_specs_or_exit(
        input_paths=input,
        input_formats=input_format,
        command_name="attack navigator-layer",
        require_inputs=True,
    )
    cve_ids, _, parser_warnings, _, _, input_paths = read_input_cves_from_specs(
        input_specs,
        max_cves=max_cves,
    )
    attack_items, metadata, warnings = load_attack_only_or_exit(
        cve_ids,
        attack_source=attack_source.value,
        attack_mapping_file=attack_mapping_file,
        attack_technique_metadata_file=attack_technique_metadata_file,
    )
    layer = AttackEnrichmentService().build_navigator_layer(attack_items)
    write_output(output, json.dumps(layer, indent=2, sort_keys=True))
    console.print(
        Panel(
            "\n".join(
                [
                    "Input file: " + (input_paths[0] if len(input_paths) == 1 else "mixed"),
                    f"Output file: {output}",
                    f"ATT&CK source: {metadata['source']}",
                    f"Mapped techniques: {len(layer['techniques'])}",
                ]
            ),
            title="Navigator Layer",
        )
    )
    print_warnings(parser_warnings + warnings)
    console.print(f"[green]Wrote navigator layer to {output}[/green]")


def register(attack_app: typer.Typer) -> None:
    attack_app.command("validate")(attack_validate)
    attack_app.command("coverage")(attack_coverage)
    attack_app.command("navigator-layer")(attack_navigator_layer)

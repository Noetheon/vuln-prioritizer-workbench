"""Snapshot and rollup command registrations."""

from __future__ import annotations

import json
from pathlib import Path

import typer
from dotenv import load_dotenv

from vuln_prioritizer.cli_support.analysis import (
    AnalysisRequest,
    build_priority_policy,
    prepare_analysis,
)
from vuln_prioritizer.cli_support.common import (
    REPORT_OUTPUT_FORMATS,
    SNAPSHOT_CREATE_OUTPUT_FORMATS,
    AttackSource,
    InputFormat,
    OutputFormat,
    PolicyProfile,
    PriorityFilter,
    ReportOutputFormat,
    RollupBy,
    SnapshotCreateOutputFormat,
    SortBy,
    TargetKind,
    build_input_specs_or_exit,
    console,
    output_format_option,
    print_warnings,
    runtime_config_path,
    validate_command_formats,
    validate_output_mode,
)
from vuln_prioritizer.cli_support.snapshot_rollup import (
    build_rollup_buckets,
    build_snapshot_diff,
    load_rollup_payload,
    load_snapshot_payload,
)
from vuln_prioritizer.config import (
    DEFAULT_CACHE_DIR,
    DEFAULT_CACHE_TTL_HOURS,
    DEFAULT_NVD_API_KEY_ENV,
)
from vuln_prioritizer.models import RollupMetadata, SnapshotDiffMetadata, SnapshotMetadata
from vuln_prioritizer.reporter import (
    build_snapshot_report_payload,
    generate_markdown_report,
    generate_rollup_json,
    generate_rollup_markdown,
    generate_snapshot_diff_json,
    generate_snapshot_diff_markdown,
    render_findings_table,
    render_rollup_table,
    render_snapshot_diff_table,
    render_summary_panel,
    write_output,
)
from vuln_prioritizer.utils import iso_utc_now


def snapshot_create(
    ctx: typer.Context,
    input: list[Path] = typer.Option(..., "--input", exists=True, dir_okay=False, readable=True),
    output: Path = typer.Option(..., "--output", dir_okay=False),
    format: SnapshotCreateOutputFormat = output_format_option(
        SnapshotCreateOutputFormat.json, SNAPSHOT_CREATE_OUTPUT_FORMATS
    ),
    input_format: list[InputFormat] | None = typer.Option(None, "--input-format"),
    no_attack: bool = typer.Option(False, "--no-attack"),
    attack_source: AttackSource = typer.Option(AttackSource.none, "--attack-source"),
    attack_mapping_file: Path | None = typer.Option(None, "--attack-mapping-file", dir_okay=False),
    attack_technique_metadata_file: Path | None = typer.Option(
        None, "--attack-technique-metadata-file", dir_okay=False
    ),
    priority: list[PriorityFilter] | None = typer.Option(None, "--priority"),
    kev_only: bool = typer.Option(False, "--kev-only"),
    min_cvss: float | None = typer.Option(None, "--min-cvss", min=0.0, max=10.0),
    min_epss: float | None = typer.Option(None, "--min-epss", min=0.0, max=1.0),
    sort_by: SortBy = typer.Option(SortBy.priority, "--sort-by"),
    critical_epss_threshold: float = typer.Option(0.70, "--critical-epss-threshold"),
    critical_cvss_threshold: float = typer.Option(7.0, "--critical-cvss-threshold"),
    high_epss_threshold: float = typer.Option(0.40, "--high-epss-threshold"),
    high_cvss_threshold: float = typer.Option(9.0, "--high-cvss-threshold"),
    medium_epss_threshold: float = typer.Option(0.10, "--medium-epss-threshold"),
    medium_cvss_threshold: float = typer.Option(7.0, "--medium-cvss-threshold"),
    policy_profile: str = typer.Option(PolicyProfile.default.value, "--policy-profile"),
    policy_file: Path | None = typer.Option(None, "--policy-file", dir_okay=False),
    waiver_file: Path | None = typer.Option(None, "--waiver-file", dir_okay=False),
    asset_context: Path | None = typer.Option(None, "--asset-context", dir_okay=False),
    target_kind: TargetKind = typer.Option(TargetKind.generic, "--target-kind"),
    target_ref: str | None = typer.Option(None, "--target-ref"),
    vex_file: list[Path] | None = typer.Option(None, "--vex-file", dir_okay=False),
    show_suppressed: bool = typer.Option(False, "--show-suppressed"),
    hide_waived: bool = typer.Option(False, "--hide-waived"),
    max_cves: int | None = typer.Option(None, "--max-cves", min=1),
    offline_kev_file: Path | None = typer.Option(None, "--offline-kev-file", dir_okay=False),
    offline_attack_file: Path | None = typer.Option(None, "--offline-attack-file", dir_okay=False),
    provider_snapshot_file: Path | None = typer.Option(
        None, "--provider-snapshot-file", dir_okay=False
    ),
    locked_provider_data: bool = typer.Option(False, "--locked-provider-data"),
    nvd_api_key_env: str = typer.Option(DEFAULT_NVD_API_KEY_ENV, "--nvd-api-key-env"),
    no_cache: bool = typer.Option(False, "--no-cache"),
    cache_dir: Path = typer.Option(
        DEFAULT_CACHE_DIR, "--cache-dir", file_okay=False, dir_okay=True
    ),
    cache_ttl_hours: int = typer.Option(DEFAULT_CACHE_TTL_HOURS, "--cache-ttl-hours", min=1),
) -> None:
    """Create a reusable prioritized snapshot artifact."""
    load_dotenv()
    validate_command_formats(
        command_name="snapshot create",
        format=format,
        allowed_formats=set(SNAPSHOT_CREATE_OUTPUT_FORMATS),
    )

    findings, context = prepare_analysis(
        AnalysisRequest(
            input_specs=build_input_specs_or_exit(
                input_paths=input,
                input_formats=input_format,
                command_name="snapshot create",
                require_inputs=True,
            ),
            output=output,
            format=format,
            provider_snapshot_file=provider_snapshot_file,
            locked_provider_data=locked_provider_data,
            no_attack=no_attack,
            attack_source=attack_source,
            attack_mapping_file=attack_mapping_file,
            attack_technique_metadata_file=attack_technique_metadata_file,
            offline_attack_file=offline_attack_file,
            priority_filters=priority,
            kev_only=kev_only,
            min_cvss=min_cvss,
            min_epss=min_epss,
            sort_by=sort_by,
            policy=build_priority_policy(
                critical_epss_threshold=critical_epss_threshold,
                critical_cvss_threshold=critical_cvss_threshold,
                high_epss_threshold=high_epss_threshold,
                high_cvss_threshold=high_cvss_threshold,
                medium_epss_threshold=medium_epss_threshold,
                medium_cvss_threshold=medium_cvss_threshold,
            ),
            policy_profile=policy_profile,
            policy_file=policy_file,
            waiver_file=waiver_file,
            asset_context=asset_context,
            target_kind=target_kind.value,
            target_ref=target_ref,
            vex_files=vex_file or [],
            show_suppressed=show_suppressed,
            hide_waived=hide_waived,
            max_cves=max_cves,
            offline_kev_file=offline_kev_file,
            nvd_api_key_env=nvd_api_key_env,
            no_cache=no_cache,
            cache_dir=cache_dir,
            cache_ttl_hours=cache_ttl_hours,
        )
    )
    config_path = runtime_config_path(ctx)
    snapshot_metadata = SnapshotMetadata.model_validate(
        {
            **context.model_dump(),
            "schema_version": SnapshotMetadata.model_fields["schema_version"].default,
            "snapshot_kind": SnapshotMetadata.model_fields["snapshot_kind"].default,
            "config_file": str(config_path) if config_path else None,
        }
    )

    console.print(render_findings_table(findings))
    console.print(render_summary_panel(snapshot_metadata))
    print_warnings(snapshot_metadata.warnings)

    if format == OutputFormat.json:
        write_output(
            output,
            json.dumps(
                build_snapshot_report_payload(findings, snapshot_metadata),
                indent=2,
                sort_keys=True,
            ),
        )
    else:
        write_output(output, generate_markdown_report(findings, snapshot_metadata))
    console.print(f"[green]Wrote snapshot {format.value} output to {output}[/green]")


def snapshot_diff(
    before: Path = typer.Option(..., "--before", exists=True, dir_okay=False, readable=True),
    after: Path = typer.Option(..., "--after", exists=True, dir_okay=False, readable=True),
    output: Path | None = typer.Option(None, "--output", dir_okay=False),
    format: ReportOutputFormat = output_format_option(
        ReportOutputFormat.table, REPORT_OUTPUT_FORMATS
    ),
    include_unchanged: bool = typer.Option(False, "--include-unchanged"),
) -> None:
    """Compare two snapshot artifacts by CVE."""
    validate_output_mode(format, output)
    validate_command_formats(
        command_name="snapshot diff",
        format=format,
        allowed_formats=set(REPORT_OUTPUT_FORMATS),
    )

    before_payload = load_snapshot_payload(before)
    after_payload = load_snapshot_payload(after)
    items, summary = build_snapshot_diff(
        before_payload,
        after_payload,
        include_unchanged=include_unchanged,
    )
    metadata = SnapshotDiffMetadata(
        generated_at=iso_utc_now(),
        before_path=str(before),
        after_path=str(after),
        include_unchanged=include_unchanged,
    )

    console.print(render_snapshot_diff_table(items, summary, metadata))
    if output is not None:
        if format == OutputFormat.markdown:
            write_output(output, generate_snapshot_diff_markdown(items, summary, metadata))
        elif format == OutputFormat.json:
            write_output(output, generate_snapshot_diff_json(items, summary, metadata))
        console.print(f"[green]Wrote {format.value} output to {output}[/green]")


def rollup(
    input: Path = typer.Option(..., "--input", exists=True, dir_okay=False, readable=True),
    by: RollupBy = typer.Option(RollupBy.asset, "--by"),
    output: Path | None = typer.Option(None, "--output", dir_okay=False),
    format: ReportOutputFormat = output_format_option(
        ReportOutputFormat.table, REPORT_OUTPUT_FORMATS
    ),
    top: int = typer.Option(5, "--top", min=1),
) -> None:
    """Aggregate analysis or snapshot findings by asset or business service."""
    validate_output_mode(format, output)
    validate_command_formats(
        command_name="rollup",
        format=format,
        allowed_formats=set(REPORT_OUTPUT_FORMATS),
    )

    input_kind, payload = load_rollup_payload(input)
    buckets = build_rollup_buckets(payload, dimension=by.value, top=top)
    metadata = RollupMetadata(
        generated_at=iso_utc_now(),
        input_path=str(input),
        input_kind=input_kind,
        dimension=by.value,
        bucket_count=len(buckets),
        top=top,
    )

    console.print(render_rollup_table(buckets, metadata))
    if output is not None:
        if format == OutputFormat.markdown:
            write_output(output, generate_rollup_markdown(buckets, metadata))
        elif format == OutputFormat.json:
            write_output(output, generate_rollup_json(buckets, metadata))
        console.print(f"[green]Wrote {format.value} output to {output}[/green]")


def register(app: typer.Typer, snapshot_app: typer.Typer) -> None:
    snapshot_app.command("create")(snapshot_create)
    snapshot_app.command("diff")(snapshot_diff)
    app.command()(rollup)

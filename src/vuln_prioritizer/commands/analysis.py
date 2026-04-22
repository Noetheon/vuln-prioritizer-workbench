"""Analyze/compare/explain/doctor command registrations."""

from __future__ import annotations

from pathlib import Path

import typer
from dotenv import load_dotenv
from rich.panel import Panel

from vuln_prioritizer.cli_support.analysis import (
    AnalysisRequest,
    ExplainRequest,
    build_priority_policy,
    handle_fail_on,
    handle_waiver_lifecycle_fail_on,
    prepare_analysis,
    prepare_explain,
)
from vuln_prioritizer.cli_support.common import (
    FULL_OUTPUT_FORMATS,
    REPORT_OUTPUT_FORMATS,
    TABLE_AND_JSON_OUTPUT_FORMATS,
    AttackSource,
    InputFormat,
    OutputFormat,
    PolicyProfile,
    PriorityFilter,
    ReportOutputFormat,
    SortBy,
    TableJsonOutputFormat,
    TargetKind,
    console,
    exit_input_validation,
    output_format_option,
    print_warnings,
    validate_command_formats,
    validate_output_mode,
    validate_unique_output_paths,
)
from vuln_prioritizer.cli_support.doctor_support import (
    build_doctor_report,
    render_doctor_table,
)
from vuln_prioritizer.config import (
    DEFAULT_CACHE_DIR,
    DEFAULT_CACHE_TTL_HOURS,
    DEFAULT_NVD_API_KEY_ENV,
)
from vuln_prioritizer.reporter import (
    build_analysis_report_payload,
    generate_compare_json,
    generate_compare_markdown,
    generate_doctor_json,
    generate_explain_json,
    generate_explain_markdown,
    generate_html_report,
    generate_json_report,
    generate_markdown_report,
    generate_sarif_report,
    generate_summary_markdown,
    render_compare_table,
    render_explain_view,
    render_findings_table,
    render_summary_panel,
    write_output,
)
from vuln_prioritizer.services.prioritization import PrioritizationService
from vuln_prioritizer.utils import normalize_cve_id


def analyze(
    ctx: typer.Context,
    input: Path = typer.Option(..., "--input", exists=True, dir_okay=False, readable=True),
    output: Path | None = typer.Option(None, "--output", dir_okay=False),
    html_output: Path | None = typer.Option(None, "--html-output", dir_okay=False),
    summary_output: Path | None = typer.Option(None, "--summary-output", dir_okay=False),
    format: OutputFormat = output_format_option(OutputFormat.markdown, FULL_OUTPUT_FORMATS),
    input_format: InputFormat = typer.Option(InputFormat.auto, "--input-format"),
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
    fail_on: PriorityFilter | None = typer.Option(None, "--fail-on"),
    fail_on_expired_waivers: bool = typer.Option(False, "--fail-on-expired-waivers"),
    fail_on_review_due_waivers: bool = typer.Option(False, "--fail-on-review-due-waivers"),
    max_cves: int | None = typer.Option(None, "--max-cves", min=1),
    offline_kev_file: Path | None = typer.Option(None, "--offline-kev-file", dir_okay=False),
    offline_attack_file: Path | None = typer.Option(None, "--offline-attack-file", dir_okay=False),
    nvd_api_key_env: str = typer.Option(DEFAULT_NVD_API_KEY_ENV, "--nvd-api-key-env"),
    no_cache: bool = typer.Option(False, "--no-cache"),
    cache_dir: Path = typer.Option(
        DEFAULT_CACHE_DIR, "--cache-dir", file_okay=False, dir_okay=True
    ),
    cache_ttl_hours: int = typer.Option(DEFAULT_CACHE_TTL_HOURS, "--cache-ttl-hours", min=1),
) -> None:
    """Analyze a CVE list and produce a prioritized terminal view and optional report."""
    load_dotenv()
    validate_output_mode(format, output)
    validate_unique_output_paths(
        {
            "--output": output,
            "--html-output": html_output,
            "--summary-output": summary_output,
        }
    )
    validate_command_formats(
        command_name="analyze",
        format=format,
        allowed_formats=set(FULL_OUTPUT_FORMATS),
    )

    findings, context = prepare_analysis(
        AnalysisRequest(
            input_path=input,
            output=output,
            format=format,
            input_format=input_format,
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

    console.print(render_findings_table(findings))
    console.print(render_summary_panel(context))
    print_warnings(context.warnings)

    payload = build_analysis_report_payload(findings, context)
    if output is not None:
        if format == OutputFormat.markdown:
            write_output(output, generate_markdown_report(findings, context))
        elif format == OutputFormat.json:
            write_output(output, generate_json_report(findings, context))
        elif format == OutputFormat.sarif:
            write_output(output, generate_sarif_report(findings, context))
        console.print(f"[green]Wrote {format.value} output to {output}[/green]")
    if html_output is not None:
        write_output(html_output, generate_html_report(payload))
        console.print(f"[green]Wrote html output to {html_output}[/green]")
    if summary_output is not None:
        write_output(summary_output, generate_summary_markdown(payload))
        console.print(f"[green]Wrote markdown summary to {summary_output}[/green]")
    if fail_on is not None:
        handle_fail_on(findings, fail_on)
    handle_waiver_lifecycle_fail_on(
        context,
        fail_on_expired_waivers=fail_on_expired_waivers,
        fail_on_review_due_waivers=fail_on_review_due_waivers,
    )


def compare(
    ctx: typer.Context,
    input: Path = typer.Option(..., "--input", exists=True, dir_okay=False, readable=True),
    output: Path | None = typer.Option(None, "--output", dir_okay=False),
    format: ReportOutputFormat = output_format_option(
        ReportOutputFormat.markdown, REPORT_OUTPUT_FORMATS
    ),
    input_format: InputFormat = typer.Option(InputFormat.auto, "--input-format"),
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
    nvd_api_key_env: str = typer.Option(DEFAULT_NVD_API_KEY_ENV, "--nvd-api-key-env"),
    no_cache: bool = typer.Option(False, "--no-cache"),
    cache_dir: Path = typer.Option(
        DEFAULT_CACHE_DIR, "--cache-dir", file_okay=False, dir_okay=True
    ),
    cache_ttl_hours: int = typer.Option(DEFAULT_CACHE_TTL_HOURS, "--cache-ttl-hours", min=1),
) -> None:
    """Compare a CVSS-only baseline with the enriched prioritization result."""
    load_dotenv()
    validate_output_mode(format, output)
    validate_command_formats(
        command_name="compare",
        format=format,
        allowed_formats=set(REPORT_OUTPUT_FORMATS),
    )

    findings, context = prepare_analysis(
        AnalysisRequest(
            input_path=input,
            output=output,
            format=format,
            input_format=input_format,
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

    prioritizer = PrioritizationService()
    comparisons = prioritizer.build_comparison(findings, sort_by=sort_by.value)
    changed_count = sum(1 for row in comparisons if row.changed)

    console.print(render_compare_table(comparisons))
    console.print(render_summary_panel(context, mode="compare", changed_count=changed_count))
    print_warnings(context.warnings)

    if output is not None:
        if format == OutputFormat.markdown:
            write_output(output, generate_compare_markdown(comparisons, context))
        elif format == OutputFormat.json:
            write_output(output, generate_compare_json(comparisons, context))
        console.print(f"[green]Wrote {format.value} output to {output}[/green]")


def explain(
    ctx: typer.Context,
    cve: str = typer.Option(..., "--cve"),
    output: Path | None = typer.Option(None, "--output", dir_okay=False),
    format: ReportOutputFormat = output_format_option(
        ReportOutputFormat.table, REPORT_OUTPUT_FORMATS
    ),
    no_attack: bool = typer.Option(False, "--no-attack"),
    attack_source: AttackSource = typer.Option(AttackSource.none, "--attack-source"),
    attack_mapping_file: Path | None = typer.Option(None, "--attack-mapping-file", dir_okay=False),
    attack_technique_metadata_file: Path | None = typer.Option(
        None, "--attack-technique-metadata-file", dir_okay=False
    ),
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
    offline_kev_file: Path | None = typer.Option(None, "--offline-kev-file", dir_okay=False),
    offline_attack_file: Path | None = typer.Option(None, "--offline-attack-file", dir_okay=False),
    nvd_api_key_env: str = typer.Option(DEFAULT_NVD_API_KEY_ENV, "--nvd-api-key-env"),
    no_cache: bool = typer.Option(False, "--no-cache"),
    cache_dir: Path = typer.Option(
        DEFAULT_CACHE_DIR, "--cache-dir", file_okay=False, dir_okay=True
    ),
    cache_ttl_hours: int = typer.Option(DEFAULT_CACHE_TTL_HOURS, "--cache-ttl-hours", min=1),
) -> None:
    """Explain the prioritization result for a single CVE."""
    load_dotenv()
    validate_output_mode(format, output)
    validate_command_formats(
        command_name="explain",
        format=format,
        allowed_formats=set(REPORT_OUTPUT_FORMATS),
    )

    normalized_cve = normalize_cve_id(cve)
    if normalized_cve is None:
        exit_input_validation(f"Invalid CVE identifier: {cve!r}")
        raise AssertionError("unreachable")

    result = prepare_explain(
        ExplainRequest(
            cve_id=normalized_cve,
            output=output,
            format=format,
            no_attack=no_attack,
            attack_source=attack_source,
            attack_mapping_file=attack_mapping_file,
            attack_technique_metadata_file=attack_technique_metadata_file,
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
            offline_kev_file=offline_kev_file,
            offline_attack_file=offline_attack_file,
            nvd_api_key_env=nvd_api_key_env,
            no_cache=no_cache,
            cache_dir=cache_dir,
            cache_ttl_hours=cache_ttl_hours,
        )
    )

    console.print(
        render_explain_view(
            result.finding,
            result.nvd,
            result.epss,
            result.kev,
            result.attack,
            result.comparison,
        )
    )
    print_warnings(result.warnings)

    if output is not None:
        if format == OutputFormat.markdown:
            write_output(
                output,
                generate_explain_markdown(
                    result.finding,
                    result.nvd,
                    result.epss,
                    result.kev,
                    result.attack,
                    result.context,
                    result.comparison,
                ),
            )
        elif format == OutputFormat.json:
            write_output(
                output,
                generate_explain_json(
                    result.finding,
                    result.nvd,
                    result.epss,
                    result.kev,
                    result.attack,
                    result.context,
                    result.comparison,
                ),
            )
        console.print(f"[green]Wrote {format.value} output to {output}[/green]")


def doctor(
    ctx: typer.Context,
    output: Path | None = typer.Option(None, "--output", dir_okay=False),
    format: TableJsonOutputFormat = output_format_option(
        TableJsonOutputFormat.table, TABLE_AND_JSON_OUTPUT_FORMATS
    ),
    live: bool = typer.Option(False, "--live"),
    cache_dir: Path = typer.Option(
        DEFAULT_CACHE_DIR, "--cache-dir", file_okay=False, dir_okay=True
    ),
    cache_ttl_hours: int = typer.Option(DEFAULT_CACHE_TTL_HOURS, "--cache-ttl-hours", min=1),
    waiver_file: Path | None = typer.Option(None, "--waiver-file", dir_okay=False),
    offline_kev_file: Path | None = typer.Option(None, "--offline-kev-file", dir_okay=False),
    attack_mapping_file: Path | None = typer.Option(None, "--attack-mapping-file", dir_okay=False),
    attack_technique_metadata_file: Path | None = typer.Option(
        None, "--attack-technique-metadata-file", dir_okay=False
    ),
) -> None:
    """Run local environment and data-source diagnostics."""
    validate_output_mode(format, output)
    validate_command_formats(
        command_name="doctor",
        format=format,
        allowed_formats=set(TABLE_AND_JSON_OUTPUT_FORMATS),
    )

    report = build_doctor_report(
        ctx,
        live=live,
        cache_dir=cache_dir,
        cache_ttl_hours=cache_ttl_hours,
        waiver_file=waiver_file,
        offline_kev_file=offline_kev_file,
        attack_mapping_file=attack_mapping_file,
        attack_technique_metadata_file=attack_technique_metadata_file,
    )

    console.print(
        Panel(
            "\n".join(
                [
                    f"Generated at: {report.generated_at}",
                    f"Runtime config: {report.config_file or 'Not discovered'}",
                    f"Live probes: {'enabled' if report.live else 'disabled'}",
                    f"Overall status: {report.summary.overall_status}",
                    (
                        "Check counts: "
                        f"{report.summary.ok_count} ok, "
                        f"{report.summary.degraded_count} degraded, "
                        f"{report.summary.error_count} error"
                    ),
                ]
            ),
            title="Doctor",
        )
    )
    console.print(render_doctor_table(report))

    if output is not None:
        write_output(output, generate_doctor_json(report))
        console.print(f"[green]Wrote json output to {output}[/green]")

    if any(check.status in {"degraded", "error"} for check in report.checks):
        raise typer.Exit(code=1)


def register(app: typer.Typer) -> None:
    app.command()(analyze)
    app.command()(compare)
    app.command()(explain)
    app.command()(doctor)

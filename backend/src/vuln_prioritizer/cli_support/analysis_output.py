"""Output emitters for analyze, compare, and explain CLI commands."""

from __future__ import annotations

from pathlib import Path

from vuln_prioritizer.cli_support.analysis import (
    ExplainResult,
    handle_fail_on,
    handle_provider_error_fail_on,
    handle_provider_staleness_fail_on,
    handle_waiver_lifecycle_fail_on,
)
from vuln_prioritizer.cli_support.common import (
    OutputFormat,
    PriorityFilter,
    ReportOutputFormat,
    SummaryTemplate,
    console,
    emit_stdout,
    print_warnings,
    should_emit_json_stdout,
)
from vuln_prioritizer.models import AnalysisContext, ComparisonFinding, PrioritizedFinding
from vuln_prioritizer.reporter import (
    build_analysis_report_payload,
    generate_compare_json,
    generate_compare_markdown,
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


def emit_analyze_result(
    findings: list[PrioritizedFinding],
    context: AnalysisContext,
    *,
    output: Path | None,
    html_output: Path | None,
    summary_output: Path | None,
    summary_template: SummaryTemplate,
    format: OutputFormat,
    fail_on: PriorityFilter | None,
    fail_on_provider_error: bool,
    fail_on_stale_provider_data: bool,
    fail_on_expired_waivers: bool,
    fail_on_review_due_waivers: bool,
) -> None:
    payload = build_analysis_report_payload(findings, context)
    if should_emit_json_stdout(format, output):
        if html_output is not None:
            write_output(html_output, generate_html_report(payload))
        if summary_output is not None:
            write_output(
                summary_output,
                generate_summary_markdown(payload, template=summary_template.value),
            )
        emit_stdout(generate_json_report(findings, context))
        _handle_analysis_fail_on(
            findings,
            context,
            fail_on=fail_on,
            fail_on_provider_error=fail_on_provider_error,
            fail_on_stale_provider_data=fail_on_stale_provider_data,
            fail_on_expired_waivers=fail_on_expired_waivers,
            fail_on_review_due_waivers=fail_on_review_due_waivers,
        )
        return

    console.print(render_findings_table(findings))
    console.print(render_summary_panel(context))
    print_warnings(context.warnings)

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
        write_output(
            summary_output,
            generate_summary_markdown(payload, template=summary_template.value),
        )
        console.print(f"[green]Wrote markdown summary to {summary_output}[/green]")
    _handle_analysis_fail_on(
        findings,
        context,
        fail_on=fail_on,
        fail_on_provider_error=fail_on_provider_error,
        fail_on_stale_provider_data=fail_on_stale_provider_data,
        fail_on_expired_waivers=fail_on_expired_waivers,
        fail_on_review_due_waivers=fail_on_review_due_waivers,
    )


def emit_compare_result(
    comparisons: list[ComparisonFinding],
    context: AnalysisContext,
    *,
    output: Path | None,
    format: ReportOutputFormat,
    fail_on_provider_error: bool,
    fail_on_stale_provider_data: bool,
) -> None:
    if should_emit_json_stdout(format, output):
        emit_stdout(generate_compare_json(comparisons, context))
        _handle_provider_fail_on(
            context,
            fail_on_provider_error=fail_on_provider_error,
            fail_on_stale_provider_data=fail_on_stale_provider_data,
        )
        return

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
    _handle_provider_fail_on(
        context,
        fail_on_provider_error=fail_on_provider_error,
        fail_on_stale_provider_data=fail_on_stale_provider_data,
    )


def emit_explain_result(
    result: ExplainResult,
    *,
    output: Path | None,
    format: ReportOutputFormat,
    fail_on_provider_error: bool,
) -> None:
    if should_emit_json_stdout(format, output):
        emit_stdout(
            generate_explain_json(
                result.finding,
                result.nvd,
                result.epss,
                result.kev,
                result.attack,
                result.context,
                result.comparison,
            )
        )
        handle_provider_error_fail_on(
            result.context,
            fail_on_provider_error=fail_on_provider_error,
        )
        return

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
    handle_provider_error_fail_on(
        result.context,
        fail_on_provider_error=fail_on_provider_error,
    )


def _handle_analysis_fail_on(
    findings: list[PrioritizedFinding],
    context: AnalysisContext,
    *,
    fail_on: PriorityFilter | None,
    fail_on_provider_error: bool,
    fail_on_stale_provider_data: bool,
    fail_on_expired_waivers: bool,
    fail_on_review_due_waivers: bool,
) -> None:
    if fail_on is not None:
        handle_fail_on(findings, fail_on)
    _handle_provider_fail_on(
        context,
        fail_on_provider_error=fail_on_provider_error,
        fail_on_stale_provider_data=fail_on_stale_provider_data,
    )
    handle_waiver_lifecycle_fail_on(
        context,
        fail_on_expired_waivers=fail_on_expired_waivers,
        fail_on_review_due_waivers=fail_on_review_due_waivers,
    )


def _handle_provider_fail_on(
    context: AnalysisContext,
    *,
    fail_on_provider_error: bool,
    fail_on_stale_provider_data: bool,
) -> None:
    handle_provider_error_fail_on(
        context,
        fail_on_provider_error=fail_on_provider_error,
    )
    handle_provider_staleness_fail_on(
        context,
        fail_on_stale_provider_data=fail_on_stale_provider_data,
    )

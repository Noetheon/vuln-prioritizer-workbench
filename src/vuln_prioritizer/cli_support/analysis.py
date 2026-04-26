"""CLI facade for analysis-oriented workflows."""

from __future__ import annotations

import typer

from vuln_prioritizer.models import AnalysisContext, PrioritizedFinding
from vuln_prioritizer.services.analysis import (
    AnalysisInputError,
    AnalysisNoFindingsError,
    AnalysisRequest,
    ExplainRequest,
    ExplainResult,
    build_active_filters,
    build_attack_summary_from_findings,
    build_data_sources,
    build_provider_diagnostics,
    build_provider_freshness,
    count_epss_hits,
    count_kev_hits,
    count_nvd_hits,
    normalize_priority_filters,
    provider_degraded,
    resolve_attack_options,
)
from vuln_prioritizer.services.analysis import (
    build_findings as _build_findings,
)
from vuln_prioritizer.services.analysis import (
    build_priority_policy as _build_priority_policy,
)
from vuln_prioritizer.services.analysis import (
    load_asset_records_or_exit as _load_asset_records,
)
from vuln_prioritizer.services.analysis import (
    load_context_profile_or_exit as _load_context_profile,
)
from vuln_prioritizer.services.analysis import (
    load_provider_snapshot_or_exit as _load_provider_snapshot,
)
from vuln_prioritizer.services.analysis import (
    load_vex_statements_or_exit as _load_vex_statements,
)
from vuln_prioritizer.services.analysis import (
    load_waiver_rules_or_exit as _load_waiver_rules,
)
from vuln_prioritizer.services.analysis import (
    prepare_analysis as _prepare_analysis,
)
from vuln_prioritizer.services.analysis import (
    prepare_explain as _prepare_explain,
)
from vuln_prioritizer.services.analysis import (
    prepare_saved_explain as _prepare_saved_explain,
)
from vuln_prioritizer.services.analysis import (
    validate_requested_attack_mode as _validate_requested_attack_mode,
)

from .common import PRIORITY_LABELS, PriorityFilter, console, exit_input_validation


def _exit_for_analysis_error(exc: AnalysisInputError) -> None:
    exit_input_validation(str(exc))


def build_priority_policy(*args, **kwargs):  # type: ignore[no-untyped-def]
    try:
        return _build_priority_policy(*args, **kwargs)
    except AnalysisInputError as exc:
        _exit_for_analysis_error(exc)
    raise AssertionError("unreachable")


def load_asset_records_or_exit(*args, **kwargs):  # type: ignore[no-untyped-def]
    try:
        return _load_asset_records(*args, **kwargs)
    except AnalysisInputError as exc:
        _exit_for_analysis_error(exc)
    raise AssertionError("unreachable")


def load_vex_statements_or_exit(*args, **kwargs):  # type: ignore[no-untyped-def]
    try:
        return _load_vex_statements(*args, **kwargs)
    except AnalysisInputError as exc:
        _exit_for_analysis_error(exc)
    raise AssertionError("unreachable")


def load_waiver_rules_or_exit(*args, **kwargs):  # type: ignore[no-untyped-def]
    try:
        return _load_waiver_rules(*args, **kwargs)
    except AnalysisInputError as exc:
        _exit_for_analysis_error(exc)
    raise AssertionError("unreachable")


def load_context_profile_or_exit(*args, **kwargs):  # type: ignore[no-untyped-def]
    try:
        return _load_context_profile(*args, **kwargs)
    except AnalysisInputError as exc:
        _exit_for_analysis_error(exc)
    raise AssertionError("unreachable")


def load_provider_snapshot_or_exit(*args, **kwargs):  # type: ignore[no-untyped-def]
    try:
        return _load_provider_snapshot(*args, **kwargs)
    except AnalysisInputError as exc:
        _exit_for_analysis_error(exc)
    raise AssertionError("unreachable")


def validate_requested_attack_mode(*args, **kwargs) -> None:  # type: ignore[no-untyped-def]
    try:
        _validate_requested_attack_mode(*args, **kwargs)
    except AnalysisInputError as exc:
        _exit_for_analysis_error(exc)


def build_findings(*args, **kwargs):  # type: ignore[no-untyped-def]
    try:
        return _build_findings(*args, **kwargs)
    except AnalysisInputError as exc:
        _exit_for_analysis_error(exc)
    raise AssertionError("unreachable")


def prepare_analysis(request: AnalysisRequest) -> tuple[list[PrioritizedFinding], AnalysisContext]:
    try:
        return _prepare_analysis(request)
    except AnalysisNoFindingsError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from exc
    except AnalysisInputError as exc:
        _exit_for_analysis_error(exc)
    raise AssertionError("unreachable")


def prepare_explain(request: ExplainRequest) -> ExplainResult:
    try:
        return _prepare_explain(request)
    except AnalysisNoFindingsError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from exc
    except AnalysisInputError as exc:
        _exit_for_analysis_error(exc)
    raise AssertionError("unreachable")


def prepare_saved_explain(*args, **kwargs) -> ExplainResult:  # type: ignore[no-untyped-def]
    try:
        return _prepare_saved_explain(*args, **kwargs)
    except AnalysisInputError as exc:
        _exit_for_analysis_error(exc)
    raise AssertionError("unreachable")


def handle_fail_on(findings: list[PrioritizedFinding], fail_on: PriorityFilter) -> None:
    threshold = PRIORITY_LABELS[fail_on]
    ordered = {"Critical": 1, "High": 2, "Medium": 3, "Low": 4}
    active_findings = [finding for finding in findings if not finding.waived]
    if any(ordered[finding.priority_label] <= ordered[threshold] for finding in active_findings):
        raise typer.Exit(code=1)


def handle_waiver_lifecycle_fail_on(
    context: AnalysisContext,
    *,
    fail_on_expired_waivers: bool,
    fail_on_review_due_waivers: bool,
) -> None:
    if fail_on_expired_waivers and context.expired_waiver_count:
        console.print(
            "[red]Policy check failed:[/red] expired waivers were detected in the current findings."
        )
        raise typer.Exit(code=1)
    if fail_on_review_due_waivers and (
        context.waiver_review_due_count or context.expired_waiver_count
    ):
        console.print(
            "[red]Policy check failed:[/red] review-due or expired waivers were "
            "detected in the current findings."
        )
        raise typer.Exit(code=1)


def handle_provider_error_fail_on(
    context: AnalysisContext,
    *,
    fail_on_provider_error: bool,
) -> None:
    if not fail_on_provider_error or not context.provider_degraded:
        return
    console.print("[red]Policy check failed:[/red] provider enrichment degraded during the run.")
    raise typer.Exit(code=1)


def handle_provider_staleness_fail_on(
    context: AnalysisContext,
    *,
    fail_on_stale_provider_data: bool,
) -> None:
    if not fail_on_stale_provider_data or not context.provider_stale:
        return
    sources = ", ".join(sorted(context.provider_stale_sources)) or "unknown"
    console.print(
        "[red]Policy check failed:[/red] provider data exceeded "
        f"--max-provider-age-hours for: {sources}."
    )
    raise typer.Exit(code=1)


__all__ = [
    "AnalysisRequest",
    "ExplainRequest",
    "ExplainResult",
    "build_active_filters",
    "build_attack_summary_from_findings",
    "build_data_sources",
    "build_findings",
    "build_priority_policy",
    "build_provider_diagnostics",
    "build_provider_freshness",
    "count_epss_hits",
    "count_kev_hits",
    "count_nvd_hits",
    "handle_fail_on",
    "handle_provider_error_fail_on",
    "handle_provider_staleness_fail_on",
    "handle_waiver_lifecycle_fail_on",
    "load_asset_records_or_exit",
    "load_context_profile_or_exit",
    "load_provider_snapshot_or_exit",
    "load_vex_statements_or_exit",
    "load_waiver_rules_or_exit",
    "normalize_priority_filters",
    "prepare_analysis",
    "prepare_explain",
    "prepare_saved_explain",
    "provider_degraded",
    "resolve_attack_options",
    "validate_requested_attack_mode",
]

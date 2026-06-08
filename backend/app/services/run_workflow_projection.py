"""Public projections for analysis runs backed by Decision/Evidence v2."""

from __future__ import annotations

from sqlmodel import Session

from app.decision_core.readmodels import decision_run_view
from app.models import (
    AnalysisRun,
    AnalysisRunPublic,
    AnalysisRunSummaryPublic,
    WorkflowRunPublic,
)
from app.services.run_workflow_metadata import redact_public_payload


def analysis_run_public(
    run: AnalysisRun,
    *,
    session: Session | None = None,
    workflow: WorkflowRunPublic | None = None,
) -> AnalysisRunPublic:
    """Return the public analysis-run response from the v2 evidence source."""
    view = decision_run_view(run, session=session)
    return AnalysisRunPublic(
        id=run.id,
        project_id=run.project_id,
        provider_snapshot_id=run.provider_snapshot_id,
        input_type=run.input_type,
        filename=run.filename,
        status=run.status,
        started_at=run.started_at,
        finished_at=run.finished_at,
        error_message=redact_public_payload(run.error_message),
        evidence=view.evidence,
        diagnostics=view.diagnostics,
        uploads=view.uploads,
        provider_snapshot=view.provider_snapshot,
        counts=view.counts,
        warnings=view.warnings,
        parse_errors=view.parse_errors,
        workflow=workflow,
    )


def analysis_run_summary_public(
    run: AnalysisRun,
    *,
    session: Session | None = None,
    workflow: WorkflowRunPublic | None = None,
) -> AnalysisRunSummaryPublic:
    """Return the public run-summary response from Evidence v2."""
    view = decision_run_view(run, session=session)
    counts = view.counts
    return AnalysisRunSummaryPublic(
        id=run.id,
        project_id=run.project_id,
        input_type=run.input_type,
        filename=run.filename,
        status=run.status,
        started_at=run.started_at,
        finished_at=run.finished_at,
        created_findings=counts.created_findings,
        updated_findings=counts.updated_findings,
        ignored_lines=counts.ignored_lines,
        rows_read=counts.rows_read,
        occurrence_count=counts.occurrence_count,
        finding_count=counts.finding_count,
        counts_by_priority=counts.counts_by_priority,
        kev_hits=counts.kev_hits,
        provider_snapshot_id=run.provider_snapshot_id,
        provider_degraded=view.provider_degraded,
        warnings=view.warnings,
        parse_errors=view.parse_errors,
        evidence=view.evidence,
        diagnostics=view.diagnostics,
        uploads=view.uploads,
        provider_snapshot=view.provider_snapshot,
        analysis_decision_scope=view.analysis_decision_scope,
        persistence_scope=view.persistence_scope,
        workflow=workflow,
    )

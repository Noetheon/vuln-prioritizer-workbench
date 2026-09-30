"""Public projections for analysis runs backed by Decision/Evidence v2."""

from __future__ import annotations

from sqlalchemy.orm import object_session
from sqlmodel import Session

from app.decision_core.readmodels import decision_run_view
from app.models import (
    AnalysisRun,
    AnalysisRunPublic,
    AnalysisRunSummaryPublic,
    WorkflowRunPublic,
)
from app.models.decision_summary import RunDecisionSummaryPublic
from app.services.decision_guidance_summary import (
    project_state_decision_summary,
    run_decision_summary,
)
from app.services.project_state import current_project_state, is_project_state_run
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
    active_session = session or object_session(run)
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
        resolved_findings=counts.resolved_findings,
        reopened_findings=counts.reopened_findings,
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
        decision_summary=_decision_summary(
            active_session, run, has_evidence=view.evidence is not None
        ),
        project_state_current=(
            _project_state_current(active_session, run) if is_project_state_run(run) else None
        ),
    )


def _project_state_current(session: object, run: AnalysisRun) -> bool | None:
    if not isinstance(session, Session):
        return None
    evidence = decision_run_view(run, session=session).evidence
    recorded = evidence.evaluation.input_sha256 if evidence and evidence.evaluation else None
    return (
        recorded is not None
        and recorded == current_project_state(session, run.project_id).fingerprint
    )


def _decision_summary(
    session: object, run: AnalysisRun, *, has_evidence: bool
) -> RunDecisionSummaryPublic | None:
    if not isinstance(session, Session) or not has_evidence:
        return None
    if not is_project_state_run(run):
        return run_decision_summary(session, run.id)
    # A recorded project state has no evidence of its own; summarize the
    # current decisions only while they still match the recording.
    if not _project_state_current(session, run):
        return None
    return project_state_decision_summary(session, run.project_id)

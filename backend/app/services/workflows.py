"""Public workflow projection helpers."""

from __future__ import annotations

import uuid
from typing import Any

from sqlmodel import Session

from app.models import (
    AnalysisRun,
    AnalysisRunStatus,
    WorkflowEvent,
    WorkflowEventPublic,
    WorkflowRun,
    WorkflowRunKind,
    WorkflowRunPublic,
    WorkflowRunStatus,
)
from app.repositories import RunRepository, WorkflowRepository
from vuln_prioritizer.security_redaction import redact_value

_TERMINAL_ANALYSIS_STATUSES = {
    AnalysisRunStatus.SUCCEEDED,
    AnalysisRunStatus.COMPLETED,
    AnalysisRunStatus.COMPLETED_WITH_ERRORS,
    AnalysisRunStatus.FAILED,
    AnalysisRunStatus.CANCELLED,
}

_CANCELLABLE_ANALYSIS_WORKFLOW_KINDS = {
    WorkflowRunKind.IMPORT,
    WorkflowRunKind.PROVIDER_UPDATE,
}


def workflow_event_public(event: WorkflowEvent) -> WorkflowEventPublic:
    """Return a redacted public workflow event."""
    return WorkflowEventPublic(
        id=event.id,
        workflow_run_id=event.workflow_run_id,
        sequence=event.sequence,
        event_type=event.event_type,
        status=event.status,
        stage=event.stage,
        message=_redacted_text(event.message),
        progress_current=event.progress_current,
        progress_total=event.progress_total,
        artifact_kind=event.artifact_kind,
        artifact_id=event.artifact_id,
        details=_redacted_payload(event.metadata_json),
        created_at=event.created_at,
    )


def workflow_run_public(
    workflow: WorkflowRun,
    *,
    latest_event: WorkflowEvent | None = None,
) -> WorkflowRunPublic:
    """Return redacted public workflow state."""
    return WorkflowRunPublic(
        id=workflow.id,
        kind=workflow.kind,
        status=workflow.status,
        title=workflow.title,
        handler=workflow.handler,
        project_id=workflow.project_id,
        analysis_run_id=workflow.analysis_run_id,
        report_id=workflow.report_id,
        parent_workflow_run_id=workflow.parent_workflow_run_id,
        current_stage=workflow.current_stage,
        progress_current=workflow.progress_current,
        progress_total=workflow.progress_total,
        retry_count=workflow.retry_count,
        max_retries=workflow.max_retries,
        attempt_count=workflow.attempt_count,
        max_attempts=workflow.max_attempts,
        cancellation_requested=workflow.cancellation_requested,
        error_message=_redacted_text(workflow.error_message),
        artifact_refs=_redacted_artifacts(workflow.artifact_refs_json),
        details=_redacted_payload(workflow.metadata_json),
        terminal_code=workflow.terminal_code,
        created_at=workflow.created_at,
        updated_at=workflow.updated_at,
        started_at=workflow.started_at,
        finished_at=workflow.finished_at,
        next_retry_at=workflow.next_retry_at,
        last_heartbeat_at=workflow.last_heartbeat_at,
        lease_expires_at=workflow.lease_expires_at,
        cancel_requested_at=workflow.cancel_requested_at,
        latest_event=workflow_event_public(latest_event) if latest_event is not None else None,
    )


def latest_analysis_workflow_public(
    session: Session,
    *,
    analysis_run_id: uuid.UUID,
    kind: WorkflowRunKind | str | None = None,
) -> WorkflowRunPublic | None:
    """Return the latest public workflow for an analysis run."""
    repository = WorkflowRepository(session)
    workflow = repository.get_latest_analysis_workflow(
        analysis_run_id=analysis_run_id,
        kind=kind,
    )
    if workflow is None:
        return None
    return workflow_run_public(workflow, latest_event=repository.latest_event(workflow.id))


def latest_report_workflow_public(
    session: Session,
    *,
    report_id: uuid.UUID,
) -> WorkflowRunPublic | None:
    """Return the latest public workflow for a report artifact."""
    repository = WorkflowRepository(session)
    workflow = repository.get_latest_report_workflow(report_id)
    if workflow is None:
        return None
    return workflow_run_public(workflow, latest_event=repository.latest_event(workflow.id))


def request_workflow_cancellation(
    session: Session,
    workflow_id: uuid.UUID,
    *,
    message: str = "Cancellation requested by user.",
) -> WorkflowRun:
    """Request cancellation and synchronize immediately cancelled linked runs."""
    repository = WorkflowRepository(session)
    workflow = repository.request_cancel(workflow_id, message=message)
    if workflow.status == WorkflowRunStatus.CANCELLED:
        _cancel_linked_analysis_run(session, workflow, message=message)
    return workflow


def finish_cancelled_workflow(
    session: Session,
    workflow_id: uuid.UUID,
    *,
    message: str = "Workflow cancelled.",
) -> WorkflowRun | None:
    """Finish a cooperatively cancelled workflow and synchronize linked run state."""
    repository = WorkflowRepository(session)
    workflow = repository.cancel_if_requested(workflow_id, message=message)
    if workflow is not None and workflow.status == WorkflowRunStatus.CANCELLED:
        _cancel_linked_analysis_run(session, workflow, message=message)
    return workflow


def _redacted_payload(payload: dict[str, Any] | None) -> dict[str, Any]:
    redacted, _paths = redact_value(payload or {})
    return redacted if isinstance(redacted, dict) else {}


def _redacted_artifacts(payload: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    redacted, _paths = redact_value(payload or [])
    if not isinstance(redacted, list):
        return []
    return [dict(item) for item in redacted if isinstance(item, dict)]


def _redacted_text(value: str | None) -> str | None:
    if value is None:
        return None
    redacted, _paths = redact_value(value)
    return redacted if isinstance(redacted, str) else None


def _cancel_linked_analysis_run(
    session: Session,
    workflow: WorkflowRun,
    *,
    message: str,
) -> AnalysisRun | None:
    if (
        workflow.kind not in _CANCELLABLE_ANALYSIS_WORKFLOW_KINDS
        or workflow.analysis_run_id is None
    ):
        return None
    run_repository = RunRepository(session)
    run = run_repository.get_analysis_run(workflow.analysis_run_id)
    if run is None or run.status in _TERMINAL_ANALYSIS_STATUSES:
        return run

    return run_repository.finish_analysis_run(
        run.id,
        status=AnalysisRunStatus.CANCELLED,
        error_message=message,
    )

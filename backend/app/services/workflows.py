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
from app.services.import_execution_summary import _job_payload, _job_status_entry
from app.services.run_workflow_metadata import (
    merge_error_payload,
    merge_summary_payload,
    workflow_error_payload_or_empty,
    workflow_import_job_payload,
    workflow_summary_payload,
)
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
        execution_mode=workflow.execution_mode,
        project_id=workflow.project_id,
        analysis_run_id=workflow.analysis_run_id,
        report_id=workflow.report_id,
        parent_workflow_run_id=workflow.parent_workflow_run_id,
        current_stage=workflow.current_stage,
        progress_current=workflow.progress_current,
        progress_total=workflow.progress_total,
        retry_count=workflow.retry_count,
        max_retries=workflow.max_retries,
        cancellation_requested=workflow.cancellation_requested,
        error_message=_redacted_text(workflow.error_message),
        error_details=_redacted_payload(workflow.error_details_json),
        details=_redacted_payload(workflow.metadata_json),
        created_at=workflow.created_at,
        updated_at=workflow.updated_at,
        started_at=workflow.started_at,
        finished_at=workflow.finished_at,
        next_retry_at=workflow.next_retry_at,
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

    failure = {
        "message": message,
        "stage": "cancelled",
        "error_type": "WorkflowCancelled",
    }
    updates: dict[str, Any] = {"background_error": failure}
    error_updates: dict[str, Any] = {"background_error": failure}
    import_job = _cancelled_import_job(run, workflow=workflow)
    if import_job is not None:
        updates["import_job"] = import_job
        error_updates["import_job"] = import_job

    return run_repository.finish_analysis_run(
        run.id,
        status=AnalysisRunStatus.CANCELLED,
        error_message=message,
        error_json=merge_error_payload(
            workflow_error_payload_or_empty(run),
            **error_updates,
        ),
        summary_json=merge_summary_payload(
            workflow_summary_payload(run),
            **updates,
        ),
    )


def _cancelled_import_job(
    run: AnalysisRun,
    *,
    workflow: WorkflowRun,
) -> dict[str, Any] | None:
    existing_job = workflow_import_job_payload(run)
    if not isinstance(existing_job, dict) and workflow.kind != WorkflowRunKind.IMPORT:
        return None
    job_id = (
        str(existing_job.get("id") or workflow.id)
        if isinstance(existing_job, dict)
        else str(workflow.id)
    )
    raw_history = existing_job.get("status_history") if isinstance(existing_job, dict) else None
    history = (
        [item for item in raw_history if isinstance(item, dict)]
        if isinstance(raw_history, list)
        else []
    )
    if not history:
        history = [_job_status_entry("pending")]
    execution_mode = (
        str(existing_job.get("execution_mode") or workflow.execution_mode)
        if isinstance(existing_job, dict)
        else workflow.execution_mode
    )
    return _job_payload(
        job_id=job_id,
        status="cancelled",
        status_history=_append_job_status(history, "cancelled"),
        execution_mode=execution_mode,
    )


def _append_job_status(
    status_history: list[dict[str, Any]],
    status: str,
) -> list[dict[str, Any]]:
    if status_history and status_history[-1].get("status") == status:
        return status_history
    return [*status_history, _job_status_entry(status)]

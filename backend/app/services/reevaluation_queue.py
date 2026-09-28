"""Queue a background re-evaluation of a project's existing findings."""

from __future__ import annotations

import uuid

from sqlmodel import Session

from app.models import AnalysisRun, WorkflowRunKind, WorkflowRunStatus
from app.models.evaluations import EvaluationCreate
from app.repositories import RunRepository, WorkflowRepository


def enqueue_project_reevaluation(
    session: Session,
    project_id: uuid.UUID,
    payload: EvaluationCreate,
) -> AnalysisRun:
    """Create the evaluation run and its pending workflow; the caller commits."""
    run = RunRepository(session).create_analysis_run(
        project_id=project_id,
        input_type="reevaluation",
        provider_snapshot_id=payload.provider_snapshot_id,
    )
    repository = WorkflowRepository(session)
    workflow = repository.ensure_analysis_workflow(
        kind=WorkflowRunKind.REEVALUATION,
        analysis_run_id=run.id,
        project_id=project_id,
        title="Evaluate existing findings",
        handler="app.services.reevaluation_execution.execute_reevaluation_workflow",
        current_stage="queued",
        status=WorkflowRunStatus.PENDING,
        metadata_json={"reason": payload.reason},
    )
    repository.set_workflow_payload(
        workflow.id,
        payload_json=payload.model_dump(mode="json"),
        queue_name="default",
        max_retries=0,
    )
    return run

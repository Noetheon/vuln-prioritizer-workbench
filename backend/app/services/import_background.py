"""Background execution helpers for deferred Workbench imports."""

from __future__ import annotations

import uuid
from datetime import timedelta
from typing import cast

from sqlalchemy.engine import Engine
from sqlalchemy.orm import object_session
from sqlmodel import Session

from app.core.config import Settings
from app.core.local_actor import configured_local_actor
from app.models import AnalysisRun, AnalysisRunStatus, WorkflowRunKind, WorkflowRunStatus
from app.models.base import get_datetime_utc
from app.repositories import RunRepository, WorkflowRepository
from app.services.import_errors import ImportServiceError
from app.services.import_execution import (
    ProjectImportUploadRequest,
    execute_project_import_upload,
)
from app.services.import_execution_summary import _job_payload, _job_status_entry
from app.services.run_workflow_metadata import merge_summary_payload

_TERMINAL_IMPORT_STATUSES = {
    AnalysisRunStatus.SUCCEEDED,
    AnalysisRunStatus.COMPLETED,
    AnalysisRunStatus.COMPLETED_WITH_ERRORS,
    AnalysisRunStatus.FAILED,
    AnalysisRunStatus.CANCELLED,
}


def reconcile_stale_background_import_runs(
    *,
    engine: Engine,
    settings: Settings,
) -> int:
    """Fail old background imports that could not survive a process restart."""
    stale_before = get_datetime_utc() - timedelta(minutes=settings.BACKGROUND_IMPORT_STALE_MINUTES)
    reconciled = 0
    with Session(engine) as session:
        run_repo = RunRepository(session)
        for run in run_repo.list_active_analysis_runs_started_before(stale_before):
            if not _is_background_import_run(run):
                continue
            failed = mark_import_run_background_failed(
                session=session,
                run_id=run.id,
                error_message=(
                    "Background import did not finish before the Workbench process restarted."
                ),
            )
            if failed is not None and failed.status == AnalysisRunStatus.FAILED:
                reconciled += 1
    return reconciled


async def execute_project_import_upload_background(
    engine: Engine,
    settings: Settings,
    project_id: uuid.UUID,
    actor_id: uuid.UUID,
    upload: ProjectImportUploadRequest,
    run_id: uuid.UUID,
) -> None:
    """Resume a deferred import run outside the request/response path."""
    _ = actor_id
    with Session(engine) as session:
        local_actor = configured_local_actor(settings)
        try:
            await execute_project_import_upload(
                project_id=project_id,
                session=session,
                local_actor=local_actor,
                settings=settings,
                upload=upload,
                existing_run_id=run_id,
                execution_mode="background",
            )
        except ImportServiceError:
            return
        except Exception:
            session.rollback()
            mark_import_run_background_failed(session=session, run_id=run_id)


def mark_import_run_background_failed(
    *,
    session: Session,
    run_id: uuid.UUID,
    error_message: str = "Import execution failed.",
) -> AnalysisRun | None:
    """Mark a deferred import run failed when the background task exits unexpectedly."""
    run_repo = RunRepository(session)
    run = run_repo.get_analysis_run(run_id)
    if run is None or run.status in _TERMINAL_IMPORT_STATUSES:
        return run

    workflow_repository = WorkflowRepository(session)
    workflow = workflow_repository.get_latest_analysis_workflow(
        analysis_run_id=run.id,
        kind=WorkflowRunKind.IMPORT,
    )
    failed_run = run_repo.finish_analysis_run(
        run.id,
        status=AnalysisRunStatus.FAILED,
        error_message=error_message,
    )
    if workflow is not None and workflow.status != WorkflowRunStatus.FAILED:
        workflow.result_json = merge_summary_payload(
            workflow.result_json,
            import_job=_failed_import_job(
                workflow.result_json,
                execution_mode=workflow.execution_mode,
            ),
        )
        workflow_repository.finish_workflow(
            workflow.id,
            status=WorkflowRunStatus.FAILED,
            stage="background_import",
            message=error_message,
            error_message=error_message,
            error_json={
                "background_error": {
                    "message": error_message,
                    "stage": "background_import",
                    "error_type": "BackgroundImportError",
                }
            },
            diagnostics_json={
                "background_error": {
                    "message": error_message,
                    "stage": "background_import",
                    "error_type": "BackgroundImportError",
                }
            },
        )
    session.commit()
    return failed_run


def _failed_import_job(result_json: dict[str, object], *, execution_mode: str) -> dict[str, object]:
    existing_job = result_json.get("import_job")
    history: list[dict[str, str]] = []
    job_id = ""
    if isinstance(existing_job, dict):
        job_id = str(existing_job.get("id") or "")
        raw_history = existing_job.get("status_history")
        if isinstance(raw_history, list):
            history = [item for item in raw_history if isinstance(item, dict)]
    if not history:
        history = [_job_status_entry("pending")]
    if history[-1].get("status") != "failed":
        history = [*history, _job_status_entry("failed")]
    return _job_payload(
        job_id=job_id or "background-import",
        status="failed",
        status_history=history,
        execution_mode=execution_mode,
    )


def _is_background_import_run(run: AnalysisRun) -> bool:
    session = cast(Session | None, object_session(run))
    if session is None:
        return False
    workflow = WorkflowRepository(session).get_latest_analysis_workflow(
        analysis_run_id=run.id,
        kind=WorkflowRunKind.IMPORT,
    )
    return workflow is not None and workflow.execution_mode == "background"

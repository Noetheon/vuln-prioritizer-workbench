"""Background execution helpers for deferred Workbench imports."""

from __future__ import annotations

import uuid
from datetime import timedelta

from sqlalchemy.engine import Engine
from sqlmodel import Session

from app.core.config import Settings
from app.core.db import ensure_configured_superuser
from app.models import AnalysisRun, AnalysisRunStatus, User
from app.models.api_tokens import ApiTokenContext, attach_api_token_context
from app.models.base import get_datetime_utc
from app.repositories import RunRepository
from app.services.import_errors import ImportServiceError
from app.services.import_execution import (
    ProjectImportUploadRequest,
    execute_project_import_upload,
)
from app.services.import_execution_summary import _job_payload, _job_status_entry

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
    user_id: uuid.UUID,
    upload: ProjectImportUploadRequest,
    run_id: uuid.UUID,
    api_token_context: ApiTokenContext | None = None,
) -> None:
    """Resume a deferred import run outside the request/response path."""
    with Session(engine) as session:
        current_user = session.get(User, user_id)
        if current_user is None:
            current_user = ensure_configured_superuser(session, active_settings=settings)
        if api_token_context is not None:
            attach_api_token_context(
                current_user,
                token_id=api_token_context.token_id,
                project_id=api_token_context.project_id,
                scopes=set(api_token_context.scopes),
            )
        try:
            await execute_project_import_upload(
                project_id=project_id,
                session=session,
                current_user=current_user,
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

    job_id = str(uuid.uuid4())
    job_history = [_job_status_entry("pending")]
    existing_job = run.summary_json.get("import_job")
    if isinstance(existing_job, dict):
        job_id = str(existing_job.get("id") or job_id)
        raw_history = existing_job.get("status_history")
        if isinstance(raw_history, list) and raw_history:
            job_history = [item for item in raw_history if isinstance(item, dict)]
    failed_history = _append_job_status(job_history, "failed")
    failed_run = run_repo.finish_analysis_run(
        run.id,
        status=AnalysisRunStatus.FAILED,
        error_message=error_message,
        error_json={
            "background_error": {"message": error_message, "stage": "background_import"},
            "import_job": _job_payload(
                job_id=job_id,
                status="failed",
                status_history=failed_history,
                execution_mode="background",
            ),
        },
        summary_json={
            **run.summary_json,
            "background_error": {"message": error_message, "stage": "background_import"},
            "import_job": _job_payload(
                job_id=job_id,
                status="failed",
                status_history=failed_history,
                execution_mode="background",
            ),
        },
    )
    session.commit()
    return failed_run


def _append_job_status(
    status_history: list[dict[str, str]],
    status: str,
) -> list[dict[str, str]]:
    if status_history and status_history[-1].get("status") == status:
        return status_history
    return [*status_history, _job_status_entry(status)]


def _is_background_import_run(run: AnalysisRun) -> bool:
    job = run.summary_json.get("import_job")
    return isinstance(job, dict) and job.get("execution_mode") == "background"

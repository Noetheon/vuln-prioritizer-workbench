"""Background execution helpers for deferred Workbench imports."""

from __future__ import annotations

import uuid

from sqlalchemy.engine import Engine
from sqlmodel import Session

from app.core.config import Settings
from app.core.db import ensure_configured_superuser
from app.models import AnalysisRun, AnalysisRunStatus, User
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


async def execute_project_import_upload_background(
    engine: Engine,
    settings: Settings,
    project_id: uuid.UUID,
    user_id: uuid.UUID,
    upload: ProjectImportUploadRequest,
    run_id: uuid.UUID,
) -> None:
    """Resume a deferred import run outside the request/response path."""
    with Session(engine) as session:
        current_user = session.get(User, user_id)
        if current_user is None:
            current_user = ensure_configured_superuser(session, active_settings=settings)
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

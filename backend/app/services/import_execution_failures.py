"""Analysis failure handling for Workbench import execution."""

from __future__ import annotations

import uuid
from typing import NoReturn

from sqlmodel import Session

from app.core.local_actor import LocalWorkbenchActor
from app.models import AnalysisRun, AnalysisRunStatus
from app.repositories import RunRepository
from app.services.import_errors import ImportServiceError
from app.services.import_execution_summary import _record_import_audit
from app.services.import_uploads import (
    sanitize_parser_error_message as _sanitize_parser_error_message,
)


def raise_analysis_failure(
    *,
    session: Session,
    run_repo: RunRepository,
    run: AnalysisRun,
    local_actor: LocalWorkbenchActor,
    project_id: uuid.UUID,
    job_id: str,
    job_history: list[dict[str, str]],
    ignored_lines: int,
    input_type: str,
    exc: Exception,
) -> NoReturn:
    """Raise analysis failure function."""
    analysis_error_message = _sanitize_parser_error_message(str(exc))
    analysis_error = {
        "message": analysis_error_message,
        "stage": "enrich_score_explain",
        "error_type": exc.__class__.__name__,
    }
    failed_run = run_repo.finish_analysis_run(
        run.id,
        status=AnalysisRunStatus.FAILED,
        error_message=analysis_error_message,
    )
    _ = job_id, job_history, analysis_error
    _record_import_audit(
        session,
        local_actor=local_actor,
        project_id=project_id,
        run_id=failed_run.id,
        status="failure",
        stage="analysis",
        input_type=input_type,
    )
    session.commit()
    raise ImportServiceError(
        status_code=422,
        detail={
            "message": "Import analysis failed.",
            "analysis_run_id": str(failed_run.id),
            "ignored_lines": ignored_lines,
            "analysis_error": analysis_error,
        },
    ) from exc

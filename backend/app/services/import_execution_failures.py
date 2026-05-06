"""Failure handling stages for Workbench import execution."""

from __future__ import annotations

import uuid
from typing import NoReturn

from fastapi import HTTPException
from sqlmodel import Session

from app.models import AnalysisRun, AnalysisRunStatus, User
from app.repositories import RunRepository
from app.services.import_execution_summary import (
    _job_payload,
    _job_status_entry,
    _record_import_audit,
)
from app.services.import_uploads import (
    sanitize_parser_error_message as _sanitize_parser_error_message,
)


def raise_analysis_failure(
    *,
    session: Session,
    run_repo: RunRepository,
    run: AnalysisRun,
    current_user: User,
    project_id: uuid.UUID,
    job_id: str,
    job_history: list[dict[str, str]],
    ignored_lines: int,
    input_type: str,
    exc: Exception,
) -> NoReturn:
    analysis_error_message = _sanitize_parser_error_message(str(exc))
    analysis_error = {
        "message": analysis_error_message,
        "stage": "enrich_score_explain",
        "error_type": exc.__class__.__name__,
    }
    failed_history = [*job_history, _job_status_entry("failed")]
    failed_run = run_repo.finish_analysis_run(
        run.id,
        status=AnalysisRunStatus.FAILED,
        error_message=analysis_error_message,
        error_json={
            "analysis_error": analysis_error,
            "created_findings": 0,
            "updated_findings": 0,
            "ignored_lines": ignored_lines,
            "import_job": _job_payload(
                job_id=job_id,
                status="failed",
                status_history=failed_history,
            ),
        },
        summary_json={
            **run.summary_json,
            "import_job": _job_payload(
                job_id=job_id,
                status="failed",
                status_history=failed_history,
            ),
            "analysis_error": analysis_error,
            "parse_errors": [],
            "created_findings": 0,
            "updated_findings": 0,
            "ignored_lines": ignored_lines,
        },
    )
    _record_import_audit(
        session,
        current_user=current_user,
        project_id=project_id,
        run_id=failed_run.id,
        status="failure",
        stage="analysis",
        input_type=input_type,
    )
    session.commit()
    raise HTTPException(
        status_code=422,
        detail={
            "message": "Import analysis failed.",
            "analysis_run_id": str(failed_run.id),
            "ignored_lines": ignored_lines,
            "analysis_error": analysis_error,
        },
    ) from exc

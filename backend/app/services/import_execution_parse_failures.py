"""Parse failure handling for Workbench import execution."""

from __future__ import annotations

import uuid
from typing import Any, NoReturn

from sqlmodel import Session

from app.core.local_actor import LocalWorkbenchActor
from app.models import AnalysisRun, AnalysisRunStatus
from app.repositories import RunRepository
from app.services.import_errors import ImportServiceError
from app.services.import_execution_context import _parse_errors
from app.services.import_execution_summary import _record_import_audit
from app.services.import_uploads import (
    sanitize_parser_error_message as _sanitize_parser_error_message,
)


def raise_parse_failure(
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
    filename: str,
    exc: Exception,
    execution_mode: str = "request",
) -> NoReturn:
    """Raise parse failure function."""
    parse_errors = _parse_errors(exc, filename=filename, input_type=input_type)
    failed_run = _finish_failed_parse_run(
        run_repo=run_repo,
        run=run,
        job_id=job_id,
        job_history=job_history,
        ignored_lines=ignored_lines,
        parse_errors=parse_errors,
        exc=exc,
        execution_mode=execution_mode,
    )
    _record_import_audit(
        session,
        local_actor=local_actor,
        project_id=project_id,
        run_id=failed_run.id,
        status="failure",
        stage="parse",
        input_type=input_type,
    )
    session.commit()
    raise ImportServiceError(
        status_code=422,
        detail={
            "message": "Import parsing failed.",
            "analysis_run_id": str(failed_run.id),
            "ignored_lines": ignored_lines,
            "parse_errors": parse_errors,
        },
    ) from exc


def raise_sidecar_parse_failure(
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
    error_key: str,
    response_message: str,
    filename: str | None,
    stage: str,
    exc: Exception,
    execution_mode: str = "request",
) -> NoReturn:
    """Raise sidecar parse failure function."""
    sidecar_error = _sidecar_error_payload(
        error_key=error_key,
        filename=filename,
        stage=stage,
        exc=exc,
    )
    failed_run = _finish_failed_sidecar_run(
        run_repo=run_repo,
        run=run,
        job_id=job_id,
        job_history=job_history,
        ignored_lines=ignored_lines,
        error_key=error_key,
        sidecar_error=sidecar_error,
        execution_mode=execution_mode,
    )
    _record_import_audit(
        session,
        local_actor=local_actor,
        project_id=project_id,
        run_id=failed_run.id,
        status="failure",
        stage=stage,
        input_type=input_type,
    )
    session.commit()
    raise ImportServiceError(
        status_code=422,
        detail={
            "message": response_message,
            "analysis_run_id": str(failed_run.id),
            error_key: sidecar_error,
        },
    ) from exc


def _finish_failed_parse_run(
    *,
    run_repo: RunRepository,
    run: AnalysisRun,
    job_id: str,
    job_history: list[dict[str, str]],
    ignored_lines: int,
    parse_errors: list[dict[str, Any]],
    exc: Exception,
    execution_mode: str,
) -> AnalysisRun:
    """Finish failed parse run function."""
    _ = job_id, job_history, ignored_lines, parse_errors, execution_mode
    return run_repo.finish_analysis_run(
        run.id,
        status=AnalysisRunStatus.FAILED,
        error_message=_sanitize_parser_error_message(str(exc)),
    )


def _sidecar_error_payload(
    *,
    error_key: str,
    filename: str | None,
    stage: str,
    exc: Exception,
) -> dict[str, Any]:
    """Sidecar error payload function."""
    _ = error_key
    return {
        "message": _sanitize_parser_error_message(str(exc)),
        "filename": filename,
        "stage": stage,
        "error_type": exc.__class__.__name__,
    }


def _finish_failed_sidecar_run(
    *,
    run_repo: RunRepository,
    run: AnalysisRun,
    job_id: str,
    job_history: list[dict[str, str]],
    ignored_lines: int,
    error_key: str,
    sidecar_error: dict[str, Any],
    execution_mode: str,
) -> AnalysisRun:
    """Finish failed sidecar run function."""
    _ = job_id, job_history, ignored_lines, error_key, execution_mode
    return run_repo.finish_analysis_run(
        run.id,
        status=AnalysisRunStatus.FAILED,
        error_message=str(sidecar_error["message"]),
    )

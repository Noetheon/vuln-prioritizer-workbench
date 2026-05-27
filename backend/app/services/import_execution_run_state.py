"""Analysis-run state transitions for Workbench import execution."""

from __future__ import annotations

import uuid
from typing import Any

from app.models import AnalysisRun, AnalysisRunStatus
from app.repositories import RunRepository
from app.services.import_errors import ImportServiceError
from app.services.import_execution_summary import _job_payload, _job_status_entry
from app.services.import_execution_types import (
    PreparedImportUpload,
    ResolvedImportRun,
    StoredImportArtifacts,
)
from app.services.import_execution_upload_prepare import initial_upload_summary
from app.services.import_uploads import (
    upload_summary_with_path as _upload_summary_with_path,
)
from app.services.run_workflow_metadata import (
    merge_summary_payload,
    update_workflow_summary,
    workflow_import_job_payload,
    workflow_summary_payload,
)


def resolve_import_run(
    *,
    run_repo: RunRepository,
    project_id: uuid.UUID,
    prepared: PreparedImportUpload,
    existing_run_id: uuid.UUID | None,
    execution_mode: str,
) -> ResolvedImportRun:
    """Create a pending run or recover existing run state for a retry."""
    if existing_run_id is not None:
        run = run_repo.get_analysis_run(existing_run_id)
        if run is None:
            raise ImportServiceError(
                status_code=404,
                detail="Analysis run not found",
            )
        job_id, job_history = _extract_existing_job_state(run)
        return ResolvedImportRun(
            run=run,
            job_id=job_id,
            job_history=job_history,
            already_finished=run.status
            not in {AnalysisRunStatus.PENDING, AnalysisRunStatus.RUNNING},
        )

    job_id = str(uuid.uuid4())
    job_history = [_job_status_entry("pending")]
    run = run_repo.create_analysis_run(
        project_id=project_id,
        input_type=prepared.input_type,
        filename=prepared.stored_filename,
        status=AnalysisRunStatus.PENDING,
        summary_json=_initial_run_summary(
            prepared,
            job_id=job_id,
            job_history=job_history,
            execution_mode=execution_mode,
        ),
    )
    return ResolvedImportRun(run=run, job_id=job_id, job_history=job_history)


def apply_stored_upload_summaries(
    run: AnalysisRun,
    *,
    resolved_run: ResolvedImportRun,
    artifacts: StoredImportArtifacts,
    execution_mode: str,
) -> None:
    """Attach storage refs for persisted upload artifacts to the run summary."""
    summary = workflow_summary_payload(run)
    input_upload = summary.get("input_upload")
    update_workflow_summary(
        run,
        import_job=_job_payload(
            job_id=resolved_run.job_id,
            status="pending",
            status_history=resolved_run.job_history,
            execution_mode=execution_mode,
        ),
        input_upload={
            **(input_upload if isinstance(input_upload, dict) else {}),
            "path": artifacts.upload_ref,
            "storage_ref": artifacts.upload_ref,
        },
        asset_context_upload=_upload_summary_with_path(
            summary.get("asset_context_upload"),
            path=artifacts.asset_context_ref,
        ),
        vex_upload=_upload_summary_with_path(
            summary.get("vex_upload"),
            path=artifacts.vex_ref,
        ),
    )


def mark_import_run_running(
    run: AnalysisRun,
    *,
    job_id: str,
    job_history: list[dict[str, str]],
    execution_mode: str,
) -> list[dict[str, str]]:
    """Mark a pending import run as actively running."""
    run.status = AnalysisRunStatus.RUNNING
    running_history = _append_job_status(job_history, "running")
    update_workflow_summary(
        run,
        import_job=_job_payload(
            job_id=job_id,
            status="running",
            status_history=running_history,
            execution_mode=execution_mode,
        ),
    )
    return running_history


def _append_job_status(
    status_history: list[dict[str, str]],
    status: str,
) -> list[dict[str, str]]:
    if status_history and status_history[-1].get("status") == status:
        return status_history
    return [*status_history, _job_status_entry(status)]


def _initial_run_summary(
    prepared: PreparedImportUpload,
    *,
    job_id: str,
    job_history: list[dict[str, str]],
    execution_mode: str,
) -> dict[str, Any]:
    upload_summary = initial_upload_summary(prepared)
    return merge_summary_payload(
        None,
        import_job=_job_payload(
            job_id=job_id,
            status="pending",
            status_history=job_history,
            execution_mode=execution_mode,
        ),
        **upload_summary,
        created_findings=0,
        updated_findings=0,
        parse_errors=[],
    )


def _extract_existing_job_state(run: AnalysisRun) -> tuple[str, list[dict[str, str]]]:
    job_id = str(uuid.uuid4())
    job_history = [_job_status_entry("pending")]
    existing_job = workflow_import_job_payload(run)
    if not isinstance(existing_job, dict):
        return job_id, job_history

    job_id = str(existing_job.get("id") or job_id)
    raw_history = existing_job.get("status_history")
    if isinstance(raw_history, list) and raw_history:
        job_history = [item for item in raw_history if isinstance(item, dict)]
    return job_id, job_history

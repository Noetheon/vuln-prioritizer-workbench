"""Workbench job API routes."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from vuln_prioritizer.api.deps import get_db_session, get_workbench_settings
from vuln_prioritizer.api.schemas import (
    ProviderUpdateJobRequest,
    WorkbenchJobCreateRequest,
    WorkbenchJobListResponse,
    WorkbenchJobResponse,
)
from vuln_prioritizer.api.workbench_payloads import _workbench_job_payload
from vuln_prioritizer.api.workbench_providers import _create_provider_update_job_record
from vuln_prioritizer.db.repositories import WorkbenchRepository
from vuln_prioritizer.services.workbench_job_runner import execute_queued_workbench_job
from vuln_prioritizer.workbench_config import WorkbenchSettings

job_router = APIRouter()


@job_router.get("/jobs", response_model=WorkbenchJobListResponse)
def list_workbench_jobs(
    session: Annotated[Session, Depends(get_db_session)],
    project_id: str | None = None,
    status: str | None = None,
    kind: str | None = None,
    limit: int = Query(default=100, ge=1, le=500),
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    return {
        "items": [
            _workbench_job_payload(job)
            for job in repo.list_workbench_jobs(
                project_id=project_id,
                status=status,
                kind=kind,
                limit=limit,
            )
        ]
    }


@job_router.get("/jobs/{job_id}", response_model=WorkbenchJobResponse)
def get_workbench_job(
    job_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    job = WorkbenchRepository(session).get_workbench_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Workbench job not found.")
    return _workbench_job_payload(job)


@job_router.post("/jobs", response_model=WorkbenchJobResponse)
def enqueue_workbench_job(
    payload: WorkbenchJobCreateRequest,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    if payload.project_id is not None and repo.get_project(payload.project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    job = repo.enqueue_workbench_job(
        kind=payload.kind,
        project_id=payload.project_id,
        target_type=payload.target_type,
        target_id=payload.target_id,
        payload_json=payload.payload,
        idempotency_key=payload.idempotency_key,
        priority=payload.priority,
        max_attempts=payload.max_attempts,
    )
    repo.create_audit_event(
        project_id=job.project_id,
        event_type="workbench_job.queued",
        target_type="workbench_job",
        target_id=job.id,
        message=f"Workbench job {job.kind!r} was queued.",
    )
    session.commit()
    return _workbench_job_payload(job)


@job_router.post("/jobs/{job_id}/retry", response_model=WorkbenchJobResponse)
def retry_workbench_job(
    job_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    job = repo.get_workbench_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Workbench job not found.")
    job = repo.retry_workbench_job(job)
    repo.create_audit_event(
        project_id=job.project_id,
        event_type="workbench_job.retry_queued",
        target_type="workbench_job",
        target_id=job.id,
        message=f"Workbench job {job.kind!r} was queued for retry.",
    )
    session.commit()
    return _workbench_job_payload(job)


@job_router.post("/jobs/{job_id}/run", response_model=WorkbenchJobResponse)
def run_queued_workbench_job(
    job_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    job = repo.get_workbench_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Workbench job not found.")
    if job.status == "completed":
        return _workbench_job_payload(job)
    if job.status != "queued":
        raise HTTPException(status_code=409, detail="Only queued Workbench jobs can be run.")

    repo.start_workbench_job(job, worker_id="api-local-runner")
    repo.update_workbench_job_progress(job, progress=25, message=f"{job.kind} started")
    nested = session.begin_nested()
    try:
        result_json = execute_queued_workbench_job(
            repo=repo,
            session=session,
            settings=settings,
            job=job,
            provider_update_runner=_run_provider_update_job,
        )
    except Exception as exc:
        nested.rollback()
        session.refresh(job)
        error_message = _workbench_job_error_message(exc)
        repo.fail_workbench_job(job, error_message=error_message, retryable=False)
        repo.create_audit_event(
            project_id=job.project_id,
            event_type="workbench_job.failed",
            target_type="workbench_job",
            target_id=job.id,
            message=f"Workbench job {job.kind!r} failed.",
            metadata_json={"error": error_message},
        )
        session.commit()
        return _workbench_job_payload(job)
    nested.commit()
    repo.complete_workbench_job(job, result_json=result_json)
    repo.create_audit_event(
        project_id=job.project_id,
        event_type="workbench_job.completed",
        target_type="workbench_job",
        target_id=job.id,
        message=f"Workbench job {job.kind!r} completed.",
    )
    session.commit()
    return _workbench_job_payload(job)


def _run_provider_update_job(
    repo: WorkbenchRepository,
    settings: WorkbenchSettings,
    payload: dict[str, Any],
) -> tuple[Any, list[str]]:
    provider_payload = ProviderUpdateJobRequest.model_validate(payload)
    provider_job = _create_provider_update_job_record(
        repo=repo,
        settings=settings,
        payload=provider_payload,
    )
    return provider_job, list(provider_payload.sources)


def _workbench_job_error_message(exc: Exception) -> str:
    if isinstance(exc, HTTPException):
        return "Workbench job request failed."
    return "Workbench job execution failed."

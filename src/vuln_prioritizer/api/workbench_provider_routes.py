"""Workbench provider API routes."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from vuln_prioritizer.api.deps import get_db_session, get_workbench_settings
from vuln_prioritizer.api.schemas import (
    ProviderStatusResponse,
    ProviderUpdateJobRequest,
    ProviderUpdateJobResponse,
    ProviderUpdateJobsListResponse,
)
from vuln_prioritizer.api.workbench_providers import (
    _create_provider_update_job_record,
    _provider_status_payload,
    _provider_update_job_payload,
)
from vuln_prioritizer.db.repositories import WorkbenchRepository
from vuln_prioritizer.services.workbench_jobs import run_sync_workbench_job
from vuln_prioritizer.workbench_config import WorkbenchSettings

provider_router = APIRouter()


@provider_router.get("/providers/status", response_model=ProviderStatusResponse)
def provider_status(
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
) -> dict[str, Any]:
    snapshot = WorkbenchRepository(session).get_latest_provider_snapshot()
    return _provider_status_payload(snapshot, settings=settings)


@provider_router.get("/providers/update-jobs", response_model=ProviderUpdateJobsListResponse)
def list_provider_update_jobs(
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    return {
        "items": [
            _provider_update_job_payload(job)
            for job in WorkbenchRepository(session).list_provider_update_jobs()
        ]
    }


@provider_router.post("/providers/update-jobs", response_model=ProviderUpdateJobResponse)
def create_provider_update_job(
    payload: ProviderUpdateJobRequest,
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    durable_job, job = run_sync_workbench_job(
        session=session,
        kind="provider_update",
        payload_json=payload.model_dump(),
        operation=lambda active_repo, _active_job: _create_provider_update_job_record(
            repo=active_repo,
            settings=settings,
            payload=payload,
        ),
        result=lambda value: {
            "provider_update_job_id": value.id,
            "status": value.status,
            "new_snapshot_id": (value.metadata_json or {}).get("new_snapshot_id"),
        },
    )
    job.metadata_json = {**(job.metadata_json or {}), "job_id": durable_job.id}
    repo.create_audit_event(
        event_type="provider_update_job.created",
        target_type="provider_update_job",
        target_id=job.id,
        message="Provider update job was created.",
        metadata_json={"status": job.status, "sources": list(payload.sources)},
    )
    session.commit()
    return _provider_update_job_payload(job)

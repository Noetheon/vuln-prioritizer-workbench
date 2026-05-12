"""Provider status routes for the Workbench API."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request, status

from app.api.deps import LocalActor, SessionDep
from app.core.app_state import workbench_settings
from app.core.config import Settings
from app.models import (
    AnalysisRunStatus,
    ProviderStatusPublic,
    ProviderUpdateJobCreate,
    ProviderUpdateJobPublic,
    ProviderUpdateJobsPublic,
)
from app.repositories import RunRepository
from app.services.audit import record_audit_event
from app.services.provider_status import (
    provider_status_payload,
    provider_update_job_public,
)
from app.services.provider_updates import (
    ProviderUpdateConflict,
    ProviderUpdateValidationError,
)
from app.services.provider_updates import (
    create_provider_update_job as execute_provider_update_job,
)

router = APIRouter(prefix="/providers", tags=["providers"])


@router.get("/update-jobs", response_model=ProviderUpdateJobsPublic)
def list_provider_update_jobs(
    request: Request,
    session: SessionDep,
    _local_actor: LocalActor,
) -> ProviderUpdateJobsPublic:
    """Return provider update jobs newest first."""
    active_settings = _request_settings(request)
    jobs = [
        job
        for run in RunRepository(session).list_provider_update_runs()
        if (job := provider_update_job_public(run, active_settings=active_settings)) is not None
    ]
    return ProviderUpdateJobsPublic(data=jobs, count=len(jobs))


@router.post("/update-jobs", response_model=ProviderUpdateJobPublic)
def create_provider_update_job(
    request: Request,
    session: SessionDep,
    payload: ProviderUpdateJobCreate,
    local_actor: LocalActor,
) -> ProviderUpdateJobPublic:
    """Synchronously create a cache-friendly provider snapshot refresh job."""
    active_settings = _request_settings(request)
    try:
        run = execute_provider_update_job(
            session,
            settings=active_settings,
            payload=payload,
        )
    except ProviderUpdateValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc
    except ProviderUpdateConflict as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc

    record_audit_event(
        session,
        action="provider.update_job.create",
        resource_type="analysis_run",
        resource_id=run.id,
        status="failure" if run.status == AnalysisRunStatus.FAILED else "success",
        actor=local_actor,
        detail={"sources": list(payload.sources), "status": str(run.status)},
    )
    session.commit()
    session.refresh(run)
    job = provider_update_job_public(run, active_settings=active_settings)
    if job is None:  # Defensive; the service always returns a provider_update run.
        raise HTTPException(status_code=500, detail="Provider update job could not be read.")
    return job


@router.get("/status", response_model=ProviderStatusPublic)
def read_provider_status(
    request: Request,
    session: SessionDep,
    _local_actor: LocalActor,
) -> ProviderStatusPublic:
    """Return provider status from the latest stored SQLModel provider snapshot."""
    repository = RunRepository(session)
    snapshot = repository.get_latest_provider_snapshot()
    latest_update_run = repository.get_latest_provider_update_run()
    return provider_status_payload(
        snapshot,
        latest_update_run=latest_update_run,
        active_settings=_request_settings(request),
    )


def _request_settings(request: Request) -> Settings:
    return workbench_settings(request, required=False)

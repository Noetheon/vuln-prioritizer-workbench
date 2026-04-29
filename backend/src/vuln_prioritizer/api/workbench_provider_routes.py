"""Workbench provider API routes."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from vuln_prioritizer.api.deps import get_db_session, get_workbench_settings
from vuln_prioritizer.api.schemas import (
    ProviderSnapshotImportResponse,
    ProviderSnapshotListResponse,
    ProviderSnapshotRecordResponse,
    ProviderStatusResponse,
    ProviderUpdateJobRequest,
    ProviderUpdateJobResponse,
)
from vuln_prioritizer.api.workbench_providers import (
    _create_provider_update_job_record,
    _persist_imported_provider_snapshot,
    _provider_snapshot_payload,
    _provider_status_payload,
    _provider_update_job_payload,
    _resolve_provider_snapshot_artifact_path,
)
from vuln_prioritizer.api.workbench_uploads import (
    SAFE_SNAPSHOT_FILENAME_RE,
    _read_bounded_upload,
    _reject_unsafe_upload_filename,
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
    repo = WorkbenchRepository(session)
    jobs = repo.list_provider_update_jobs()
    return _provider_status_payload(
        repo.get_latest_provider_snapshot(),
        settings=settings,
        latest_update_job=jobs[0] if jobs else None,
    )


@provider_router.get("/providers/snapshots", response_model=ProviderSnapshotListResponse)
def list_provider_snapshots(
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    return {"items": [_provider_snapshot_payload(item) for item in repo.list_provider_snapshots()]}


@provider_router.get(
    "/providers/snapshots/{snapshot_id}",
    response_model=ProviderSnapshotRecordResponse,
)
def get_provider_snapshot(
    snapshot_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    snapshot = _get_provider_snapshot_or_404(session, snapshot_id)
    return _provider_snapshot_payload(snapshot)


@provider_router.get("/providers/snapshots/{snapshot_id}/download")
def download_provider_snapshot(
    snapshot_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
) -> FileResponse:
    snapshot = _get_provider_snapshot_or_404(session, snapshot_id)
    path = _resolve_provider_snapshot_artifact_path(snapshot, settings=settings)
    return FileResponse(
        path,
        media_type="application/json",
        filename=f"provider-snapshot-{snapshot.id}.json",
    )


@provider_router.post(
    "/providers/snapshots/import",
    response_model=ProviderSnapshotImportResponse,
)
async def import_provider_snapshot(
    file: Annotated[UploadFile, File()],
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
) -> dict[str, Any]:
    filename = file.filename or "provider-snapshot.json"
    _reject_unsafe_upload_filename(filename)
    if not SAFE_SNAPSHOT_FILENAME_RE.fullmatch(Path(filename).name):
        raise HTTPException(status_code=422, detail="Provider snapshot filename must be JSON.")
    content = await _read_bounded_upload(file, settings=settings)
    snapshot = _persist_imported_provider_snapshot(
        repo=WorkbenchRepository(session),
        settings=settings,
        filename=filename,
        content=content,
    )
    session.commit()
    return {"imported": True, "item": _provider_snapshot_payload(snapshot)}


@provider_router.get("/providers/update-jobs")
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


def _get_provider_snapshot_or_404(session: Session, snapshot_id: str) -> Any:
    repo = WorkbenchRepository(session)
    for snapshot in repo.list_provider_snapshots():
        if snapshot.id == snapshot_id:
            return snapshot
    raise HTTPException(status_code=404, detail="Provider snapshot not found.")

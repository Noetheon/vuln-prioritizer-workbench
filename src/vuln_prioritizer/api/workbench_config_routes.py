"""Project configuration API routes."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from vuln_prioritizer.api.deps import get_db_session
from vuln_prioritizer.api.schemas import (
    ProjectConfigDiffResponse,
    ProjectConfigRequest,
    ProjectConfigResponse,
)
from vuln_prioritizer.api.workbench_payloads import (
    _project_config_payload,
)
from vuln_prioritizer.api.workbench_route_support import (
    _config_diff_payload,
)
from vuln_prioritizer.db.repositories import WorkbenchRepository
from vuln_prioritizer.runtime_config import RuntimeConfigDocument

router = APIRouter()


@router.post("/projects/{project_id}/settings/config", response_model=ProjectConfigResponse)
def save_project_config(
    project_id: str,
    payload: ProjectConfigRequest,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    if repo.get_project(project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    try:
        document = RuntimeConfigDocument.model_validate(payload.config)
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Invalid project config: {exc}") from exc
    snapshot = repo.save_project_config_snapshot(
        project_id=project_id,
        source="api",
        config_json=document.model_dump(),
    )
    repo.create_audit_event(
        project_id=project_id,
        event_type="project_config.saved",
        target_type="project_config_snapshot",
        target_id=snapshot.id,
        message="Project config snapshot was saved.",
    )
    session.commit()
    return _project_config_payload(snapshot)


@router.get("/projects/{project_id}/settings/config")
def get_project_config(
    project_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    if repo.get_project(project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    snapshot = repo.get_latest_project_config_snapshot(project_id)
    return {"item": _project_config_payload(snapshot) if snapshot is not None else None}


@router.get("/projects/{project_id}/settings/config/history")
def list_project_config_history(
    project_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    limit: int = Query(default=50, ge=1, le=200),
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    if repo.get_project(project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    return {
        "items": [
            _project_config_payload(snapshot)
            for snapshot in repo.list_project_config_snapshots(project_id, limit=limit)
        ]
    }


@router.get("/projects/{project_id}/settings/config/defaults")
def get_project_config_defaults(
    project_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    if repo.get_project(project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    return {"config": RuntimeConfigDocument().model_dump()}


@router.get("/projects/{project_id}/settings/config/{snapshot_id}/export")
def export_project_config_snapshot(
    project_id: str,
    snapshot_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> JSONResponse:
    repo = WorkbenchRepository(session)
    snapshot = repo.get_project_config_snapshot(snapshot_id)
    if snapshot is None or snapshot.project_id != project_id:
        raise HTTPException(status_code=404, detail="Project config snapshot not found.")
    response = JSONResponse(snapshot.config_json or {})
    response.headers["Content-Disposition"] = (
        f'attachment; filename="vuln-prioritizer-config-{snapshot.id}.json"'
    )
    return response


@router.get(
    "/projects/{project_id}/settings/config/{snapshot_id}/diff",
    response_model=ProjectConfigDiffResponse,
)
def diff_project_config_snapshot(
    project_id: str,
    snapshot_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    base_id: str | None = None,
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    target = repo.get_project_config_snapshot(snapshot_id)
    if target is None or target.project_id != project_id:
        raise HTTPException(status_code=404, detail="Project config snapshot not found.")
    if base_id is not None:
        base = repo.get_project_config_snapshot(base_id)
        if base is None or base.project_id != project_id:
            raise HTTPException(status_code=404, detail="Base config snapshot not found.")
    else:
        history = repo.list_project_config_snapshots(project_id, limit=200)
        older = [
            snapshot
            for snapshot in history
            if snapshot.id != target.id and snapshot.created_at <= target.created_at
        ]
        base = older[0] if older else None
    return _config_diff_payload(base=base, target=target)


@router.post(
    "/projects/{project_id}/settings/config/{snapshot_id}/rollback",
    response_model=ProjectConfigResponse,
)
def rollback_project_config_snapshot(
    project_id: str,
    snapshot_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    target = repo.get_project_config_snapshot(snapshot_id)
    if target is None or target.project_id != project_id:
        raise HTTPException(status_code=404, detail="Project config snapshot not found.")
    snapshot = repo.save_project_config_snapshot(
        project_id=project_id,
        source=f"rollback:{target.id}",
        config_json=target.config_json or {},
    )
    repo.create_audit_event(
        project_id=project_id,
        event_type="project_config.rolled_back",
        target_type="project_config_snapshot",
        target_id=snapshot.id,
        message="Project config snapshot was rolled back.",
        metadata_json={"rolled_back_to": target.id},
    )
    session.commit()
    return _project_config_payload(snapshot)

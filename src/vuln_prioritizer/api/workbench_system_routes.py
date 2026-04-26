"""System, diagnostics, and token API routes."""

from __future__ import annotations

import secrets
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from vuln_prioritizer import __version__
from vuln_prioritizer.api.deps import get_db_session, get_workbench_settings
from vuln_prioritizer.api.schemas import (
    ApiTokenCreateRequest,
    ApiTokenCreateResponse,
    ApiTokenResponse,
)
from vuln_prioritizer.api.workbench_payloads import (
    _api_token_payload,
)
from vuln_prioritizer.api.workbench_route_support import (
    _api_token_hash,
    _artifact_disk_usage,
    _directory_diagnostics,
)
from vuln_prioritizer.cache import FileCache
from vuln_prioritizer.config import DEFAULT_CACHE_TTL_HOURS
from vuln_prioritizer.db.migrations import CURRENT_REVISION
from vuln_prioritizer.db.repositories import WorkbenchRepository
from vuln_prioritizer.workbench_config import WorkbenchSettings

router = APIRouter()

API_TOKEN_PREFIX = "vpr_"


@router.get("/health")
def health(
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    return {
        "status": "ok",
        "database": "ok",
        "projects": len(repo.list_projects()),
        "upload_dir": str(settings.upload_dir),
        "report_dir": str(settings.report_dir),
    }


@router.get("/version")
def version() -> dict[str, Any]:
    return {"version": __version__, "app": "Vuln Prioritizer Workbench"}


@router.get("/diagnostics")
def diagnostics(
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    projects = repo.list_projects()
    reports = [
        report.path for project in projects for report in repo.list_project_reports(project.id)
    ]
    bundles = [
        bundle.path
        for project in projects
        for bundle in repo.list_project_evidence_bundles(project.id)
    ]
    cache = FileCache(settings.provider_cache_dir, DEFAULT_CACHE_TTL_HOURS)
    return {
        "status": "ok",
        "database": "ok",
        "migration_revision": CURRENT_REVISION,
        "projects": len(projects),
        "upload_dir": str(settings.upload_dir),
        "report_dir": str(settings.report_dir),
        "provider_snapshot_dir": str(settings.provider_snapshot_dir),
        "provider_cache_dir": str(settings.provider_cache_dir),
        "directories": {
            "upload": _directory_diagnostics(settings.upload_dir),
            "report": _directory_diagnostics(settings.report_dir),
            "provider_snapshot": _directory_diagnostics(settings.provider_snapshot_dir),
            "provider_cache": _directory_diagnostics(settings.provider_cache_dir),
        },
        "provider_cache": {
            source: cache.inspect_namespace(source) for source in ("nvd", "epss", "kev")
        },
        "jobs": {
            "queued": len(repo.list_workbench_jobs(status="queued", limit=500)),
            "running": len(repo.list_workbench_jobs(status="running", limit=500)),
            "failed": len(repo.list_workbench_jobs(status="failed", limit=500)),
        },
        "artifact_disk_usage_bytes": _artifact_disk_usage(reports + bundles),
        "max_upload_bytes": settings.max_upload_bytes,
        "api_tokens_active": repo.has_active_api_tokens(),
    }


@router.post("/tokens", response_model=ApiTokenCreateResponse)
def create_api_token(
    payload: ApiTokenCreateRequest,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    name = payload.name.strip()
    if not name:
        raise HTTPException(status_code=422, detail="Token name is required.")
    token_value = API_TOKEN_PREFIX + secrets.token_urlsafe(32)
    token = WorkbenchRepository(session).create_api_token(
        name=name,
        token_hash=_api_token_hash(token_value),
    )
    WorkbenchRepository(session).create_audit_event(
        event_type="api_token.created",
        target_type="api_token",
        target_id=token.id,
        actor=name,
        message=f"API token {name!r} was created.",
    )
    session.commit()
    return {
        "id": token.id,
        "name": token.name,
        "token": token_value,
        "created_at": token.created_at.isoformat(),
    }


@router.get("/tokens", response_model=dict[str, list[ApiTokenResponse]])
def list_api_tokens(session: Annotated[Session, Depends(get_db_session)]) -> dict[str, Any]:
    return {
        "items": [
            _api_token_payload(token) for token in WorkbenchRepository(session).list_api_tokens()
        ]
    }


@router.delete("/tokens/{token_id}", response_model=ApiTokenResponse)
def revoke_api_token(
    token_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    token = repo.get_api_token(token_id)
    if token is None:
        raise HTTPException(status_code=404, detail="API token not found.")
    repo.revoke_api_token(token)
    repo.create_audit_event(
        event_type="api_token.revoked",
        target_type="api_token",
        target_id=token.id,
        actor=token.name,
        message=f"API token {token.name!r} was revoked.",
    )
    session.commit()
    return _api_token_payload(token)

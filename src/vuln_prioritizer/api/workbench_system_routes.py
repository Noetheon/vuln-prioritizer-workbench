"""System, diagnostics, and token API routes."""

from __future__ import annotations

import secrets
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from vuln_prioritizer import __version__
from vuln_prioritizer.api.deps import get_db_session, get_workbench_settings
from vuln_prioritizer.api.schemas import (
    ApiTokenCreateRequest,
    ApiTokenCreateResponse,
    ApiTokenDeleteResponse,
    ApiTokensListResponse,
    HealthResponse,
    VersionResponse,
    WorkbenchArtifactsResponse,
    WorkbenchBootstrapResponse,
)
from vuln_prioritizer.api.workbench_payloads import (
    _api_token_payload,
    _project_payload,
)
from vuln_prioritizer.api.workbench_providers import _provider_status_payload
from vuln_prioritizer.api.workbench_route_support import (
    _api_token_hash,
    _artifact_disk_usage,
    _directory_diagnostics,
)
from vuln_prioritizer.api.workbench_uploads import (
    SAFE_ATTACK_FILENAME_RE,
    SAFE_SNAPSHOT_FILENAME_RE,
)
from vuln_prioritizer.cache import FileCache
from vuln_prioritizer.config import DEFAULT_CACHE_TTL_HOURS
from vuln_prioritizer.db.migrations import CURRENT_REVISION
from vuln_prioritizer.db.repositories import WorkbenchRepository
from vuln_prioritizer.services.workbench_analysis import SUPPORTED_WORKBENCH_INPUT_FORMATS
from vuln_prioritizer.workbench_config import WorkbenchSettings

router = APIRouter()

API_TOKEN_PREFIX = "vpr_"
SUPPORTED_REPORT_FORMATS = ("json", "markdown", "html", "csv", "sarif")
SUPPORTED_ATTACK_SOURCES = ("none", "ctid-json")


@router.get("/health", response_model=HealthResponse)
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


@router.get("/version", response_model=VersionResponse)
def version() -> dict[str, Any]:
    return {"version": __version__, "app": "Vuln Prioritizer Workbench"}


@router.get("/workbench/bootstrap", response_model=WorkbenchBootstrapResponse)
def workbench_bootstrap(
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    projects = repo.list_projects()
    tokens = repo.list_api_tokens()
    active_token_count = _active_api_token_count(tokens)
    return {
        "app": "Vuln Prioritizer Workbench",
        "version": __version__,
        "projects": [_project_payload(project) for project in projects],
        "latest_project_id": projects[-1].id if projects else None,
        "provider_status": _provider_status_payload(
            repo.get_latest_provider_snapshot(),
            settings=settings,
        ),
        "token_auth": {
            "active_count": active_token_count,
            "requires_token_for_mutations": active_token_count > 0,
        },
        "supported_input_formats": sorted(SUPPORTED_WORKBENCH_INPUT_FORMATS),
        "supported_report_formats": list(SUPPORTED_REPORT_FORMATS),
        "supported_attack_sources": list(SUPPORTED_ATTACK_SOURCES),
        "limits": {
            "max_upload_mb": settings.max_upload_mb,
            "max_upload_bytes": settings.max_upload_bytes,
        },
    }


@router.get("/workbench/artifacts", response_model=WorkbenchArtifactsResponse)
def list_workbench_artifacts(
    settings: Annotated[WorkbenchSettings, Depends(get_workbench_settings)],
) -> dict[str, Any]:
    provider_snapshots = _provider_snapshot_artifact_options(settings)
    attack_artifacts = _safe_json_artifact_options(
        settings.attack_artifact_dir,
        kind="attack_artifact",
        source="attack_artifact_dir",
        filename_pattern=SAFE_ATTACK_FILENAME_RE,
    )
    items = provider_snapshots + attack_artifacts
    return {
        "items": items,
        "provider_snapshots": provider_snapshots,
        "attack_artifacts": attack_artifacts,
        "total": len(items),
    }


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


@router.get("/tokens", response_model=ApiTokensListResponse)
def list_api_tokens(session: Annotated[Session, Depends(get_db_session)]) -> dict[str, Any]:
    tokens = WorkbenchRepository(session).list_api_tokens()
    active_token_count = _active_api_token_count(tokens)
    return {
        "items": [_api_token_payload(token) for token in tokens],
        "active_count": active_token_count,
        "requires_token_for_mutations": active_token_count > 0,
    }


@router.delete("/tokens/{token_id}", response_model=ApiTokenDeleteResponse)
def revoke_api_token(
    token_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    token = repo.get_api_token(token_id)
    if token is None:
        raise HTTPException(status_code=404, detail="API token not found.")
    if token.revoked_at is None and _active_api_token_count(repo.list_api_tokens()) <= 1:
        raise HTTPException(
            status_code=409,
            detail="Cannot revoke the last active API token. Create a replacement token first.",
        )
    revoked = repo.revoke_api_token(token)
    repo.create_audit_event(
        event_type="api_token.revoked",
        target_type="api_token",
        target_id=token.id,
        actor=token.name,
        message=f"API token {token.name!r} was revoked.",
    )
    session.commit()
    if revoked.revoked_at is None:
        raise RuntimeError("API token revoke did not set revoked_at.")
    return {
        "id": revoked.id,
        "deleted": True,
        "revoked": True,
        "revoked_at": revoked.revoked_at.isoformat(),
    }


def _active_api_token_count(tokens: list[Any]) -> int:
    return sum(1 for token in tokens if token.revoked_at is None)


def _provider_snapshot_artifact_options(settings: WorkbenchSettings) -> list[dict[str, Any]]:
    provider_items = _safe_json_artifact_options(
        settings.provider_snapshot_dir,
        kind="provider_snapshot",
        source="provider_snapshot_dir",
        filename_pattern=SAFE_SNAPSHOT_FILENAME_RE,
    )
    cache_items = _safe_json_artifact_options(
        settings.provider_cache_dir,
        kind="provider_snapshot",
        source="provider_cache_dir",
        filename_pattern=SAFE_SNAPSHOT_FILENAME_RE,
    )
    by_filename: dict[str, dict[str, Any]] = {}
    for item in [*cache_items, *provider_items]:
        by_filename.setdefault(item["filename"], item)
    return sorted(by_filename.values(), key=lambda item: item["filename"])


def _safe_json_artifact_options(
    directory: Path,
    *,
    kind: str,
    source: str,
    filename_pattern: Any,
) -> list[dict[str, Any]]:
    if not directory.is_dir():
        return []
    items: list[dict[str, Any]] = []
    for path in sorted(directory.glob("*.json")):
        if not path.is_file() or not filename_pattern.match(path.name):
            continue
        stat_result = path.stat()
        items.append(
            {
                "filename": path.name,
                "kind": kind,
                "source": source,
                "size_bytes": stat_result.st_size,
                "modified_at": datetime.fromtimestamp(
                    stat_result.st_mtime,
                    tz=UTC,
                ).isoformat(),
            }
        )
    return sorted(items, key=lambda item: item["filename"])

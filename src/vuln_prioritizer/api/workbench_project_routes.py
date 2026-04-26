"""Project, asset, audit, and waiver API routes."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from vuln_prioritizer.api.deps import get_db_session
from vuln_prioritizer.api.schemas import (
    AssetResponse,
    AssetUpdateRequest,
    AuditEventResponse,
    ProjectCreateRequest,
    ProjectResponse,
    WaiverRequest,
    WaiverResponse,
)
from vuln_prioritizer.api.workbench_payloads import (
    _asset_payload,
    _audit_event_payload,
    _project_payload,
)
from vuln_prioritizer.api.workbench_route_support import (
    _asset_audit_snapshot,
)
from vuln_prioritizer.api.workbench_waivers import (
    _count_matching_waiver_findings,
    _strip_or_none,
    _sync_project_waivers,
    _validated_waiver_values,
    _waiver_payload,
)
from vuln_prioritizer.db.repositories import WorkbenchRepository

router = APIRouter()


@router.get("/projects")
def list_projects(session: Annotated[Session, Depends(get_db_session)]) -> dict[str, Any]:
    projects = WorkbenchRepository(session).list_projects()
    return {"items": [_project_payload(project) for project in projects]}


@router.post("/projects", response_model=ProjectResponse)
def create_project(
    payload: ProjectCreateRequest,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    name = payload.name.strip()
    if not name:
        raise HTTPException(status_code=422, detail="Project name is required.")
    repo = WorkbenchRepository(session)
    if repo.get_project_by_name(name) is not None:
        raise HTTPException(status_code=409, detail="Project already exists.")
    project = repo.create_project(name=name, description=payload.description)
    repo.create_audit_event(
        project_id=project.id,
        event_type="project.created",
        target_type="project",
        target_id=project.id,
        message=f"Project {name!r} was created.",
    )
    session.commit()
    return _project_payload(project)


@router.get("/projects/{project_id}", response_model=ProjectResponse)
def get_project(
    project_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    project = WorkbenchRepository(session).get_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    return _project_payload(project)


@router.get(
    "/projects/{project_id}/audit-events",
    response_model=dict[str, list[AuditEventResponse]],
)
def list_project_audit_events(
    project_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    limit: int = Query(default=100, ge=1, le=500),
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    if repo.get_project(project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    return {
        "items": [
            _audit_event_payload(event)
            for event in repo.list_project_audit_events(project_id, limit=limit)
        ]
    }


@router.get("/audit-events", response_model=dict[str, list[AuditEventResponse]])
def list_audit_events(
    session: Annotated[Session, Depends(get_db_session)],
    project_id: str | None = None,
    limit: int = Query(default=100, ge=1, le=500),
) -> dict[str, Any]:
    return {
        "items": [
            _audit_event_payload(event)
            for event in WorkbenchRepository(session).list_audit_events(
                project_id=project_id,
                limit=limit,
            )
        ]
    }


@router.get("/projects/{project_id}/assets")
def list_project_assets(
    project_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    if repo.get_project(project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    findings = repo.list_project_findings(project_id)
    finding_counts: dict[str, int] = {}
    for finding in findings:
        if finding.asset_id:
            finding_counts[finding.asset_id] = finding_counts.get(finding.asset_id, 0) + 1
    return {
        "items": [
            _asset_payload(asset, finding_count=finding_counts.get(asset.id, 0))
            for asset in repo.list_project_assets(project_id)
        ]
    }


@router.get("/assets/{asset_row_id}", response_model=AssetResponse)
def get_asset(
    asset_row_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    asset = WorkbenchRepository(session).get_asset(asset_row_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found.")
    return _asset_payload(asset, finding_count=len(asset.findings))


@router.patch("/assets/{asset_row_id}", response_model=AssetResponse)
def update_asset(
    asset_row_id: str,
    payload: AssetUpdateRequest,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    asset = repo.get_asset(asset_row_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found.")
    previous = _asset_audit_snapshot(asset)
    updated_fields = payload.model_fields_set
    updated = repo.update_asset(
        asset,
        asset_id=(
            _strip_or_none(payload.asset_id) or asset.asset_id
            if "asset_id" in updated_fields
            else asset.asset_id
        ),
        target_ref=(
            _strip_or_none(payload.target_ref)
            if "target_ref" in updated_fields
            else asset.target_ref
        ),
        owner=_strip_or_none(payload.owner) if "owner" in updated_fields else asset.owner,
        business_service=(
            _strip_or_none(payload.business_service)
            if "business_service" in updated_fields
            else asset.business_service
        ),
        environment=(
            _strip_or_none(payload.environment)
            if "environment" in updated_fields
            else asset.environment
        ),
        exposure=(
            _strip_or_none(payload.exposure) if "exposure" in updated_fields else asset.exposure
        ),
        criticality=(
            _strip_or_none(payload.criticality)
            if "criticality" in updated_fields
            else asset.criticality
        ),
    )
    repo.create_audit_event(
        project_id=updated.project_id,
        event_type="asset.updated",
        target_type="asset",
        target_id=updated.id,
        actor=updated.owner,
        message=f"Asset {updated.asset_id!r} was updated.",
        metadata_json={
            "previous": previous,
            "current": _asset_audit_snapshot(updated),
            "updated_fields": sorted(updated_fields),
        },
    )
    session.commit()
    return _asset_payload(updated, finding_count=len(updated.findings))


@router.get("/projects/{project_id}/waivers")
def list_project_waivers(
    project_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    if repo.get_project(project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    findings = repo.list_project_findings(project_id)
    return {
        "items": [
            _waiver_payload(
                waiver, matched_findings=_count_matching_waiver_findings(waiver, findings)
            )
            for waiver in repo.list_project_waivers(project_id)
        ]
    }


@router.post("/projects/{project_id}/waivers", response_model=WaiverResponse)
def create_project_waiver(
    project_id: str,
    payload: WaiverRequest,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    if repo.get_project(project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    values = _validated_waiver_values(payload, project_id=project_id, repo=repo)
    waiver = repo.create_waiver(project_id=project_id, **values)
    matched = _sync_project_waivers(repo, project_id)
    repo.create_audit_event(
        project_id=project_id,
        event_type="waiver.created",
        target_type="waiver",
        target_id=waiver.id,
        actor=waiver.owner,
        message="Waiver was created.",
        metadata_json={"matched_findings": matched.get(waiver.id, 0)},
    )
    session.commit()
    return _waiver_payload(waiver, matched_findings=matched.get(waiver.id, 0))


@router.patch("/waivers/{waiver_id}", response_model=WaiverResponse)
def update_project_waiver(
    waiver_id: str,
    payload: WaiverRequest,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    waiver = repo.get_waiver(waiver_id)
    if waiver is None:
        raise HTTPException(status_code=404, detail="Waiver not found.")
    values = _validated_waiver_values(payload, project_id=waiver.project_id, repo=repo)
    updated = repo.update_waiver(waiver, **values)
    matched = _sync_project_waivers(repo, updated.project_id)
    repo.create_audit_event(
        project_id=updated.project_id,
        event_type="waiver.updated",
        target_type="waiver",
        target_id=updated.id,
        actor=updated.owner,
        message="Waiver was updated.",
        metadata_json={"matched_findings": matched.get(updated.id, 0)},
    )
    session.commit()
    return _waiver_payload(updated, matched_findings=matched.get(updated.id, 0))


@router.delete("/waivers/{waiver_id}")
def delete_project_waiver(
    waiver_id: str,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    waiver = repo.get_waiver(waiver_id)
    if waiver is None:
        raise HTTPException(status_code=404, detail="Waiver not found.")
    project_id = waiver.project_id
    repo.delete_waiver(waiver)
    _sync_project_waivers(repo, project_id)
    repo.create_audit_event(
        project_id=project_id,
        event_type="waiver.deleted",
        target_type="waiver",
        target_id=waiver_id,
        message="Waiver was deleted.",
    )
    session.commit()
    return {"deleted": True}

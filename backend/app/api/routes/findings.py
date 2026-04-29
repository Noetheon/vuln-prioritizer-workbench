"""Finding API routes for the Workbench domain."""

from __future__ import annotations

import uuid
from typing import Literal

from fastapi import APIRouter, HTTPException, Query

from app.api.deps import CurrentUser, SessionDep
from app.api.routes.workbench_access import require_visible_project
from app.models import (
    AssetExposure,
    Finding,
    FindingExplanationPublic,
    FindingPriority,
    FindingPublic,
    FindingsPublic,
    FindingStatus,
)
from app.repositories import FindingRepository
from app.services import DecisionDataUnavailableError, build_finding_explanation_payload

router = APIRouter(tags=["findings"])

FindingsSort = Literal[
    "operational",
    "priority",
    "score",
    "cve",
    "status",
    "epss",
    "cvss",
    "kev",
    "last_seen",
]
FindingsSortDirection = Literal["asc", "desc"]


@router.get("/projects/{project_id}/findings/", response_model=FindingsPublic)
def read_project_findings(
    project_id: uuid.UUID,
    session: SessionDep,
    current_user: CurrentUser,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    sort: FindingsSort = Query(default="operational"),
    direction: FindingsSortDirection = Query(default="asc"),
    priority: FindingPriority | None = Query(default=None),
    status: FindingStatus | None = Query(default=None),
    kev: bool | None = Query(default=None),
    owner: str | None = Query(default=None, max_length=200),
    service: str | None = Query(default=None, max_length=200),
    owner_service: str | None = Query(default=None, max_length=200),
    exposure: AssetExposure | None = Query(default=None),
    epss_min: float | None = Query(default=None, ge=0, le=1),
    epss_max: float | None = Query(default=None, ge=0, le=1),
    cvss_min: float | None = Query(default=None, ge=0, le=10),
    cvss_max: float | None = Query(default=None, ge=0, le=10),
) -> FindingsPublic:
    """List a paginated page of findings for a visible project."""
    require_visible_project(session, current_user, project_id)
    findings, count = FindingRepository(session).list_project_findings_page(
        project_id,
        limit=limit,
        offset=offset,
        sort=sort,
        direction=direction,
        priority=priority,
        status=status,
        kev=kev,
        owner=owner,
        service=service,
        owner_service=owner_service,
        exposure=exposure,
        epss_min=epss_min,
        epss_max=epss_max,
        cvss_min=cvss_min,
        cvss_max=cvss_max,
    )
    return FindingsPublic(
        data=[_finding_public(finding) for finding in findings],
        count=count,
    )


@router.get("/findings/{finding_id}", response_model=FindingPublic)
def read_finding(
    finding_id: uuid.UUID,
    session: SessionDep,
    current_user: CurrentUser,
) -> FindingPublic:
    """Read one finding if its project is visible."""
    finding = FindingRepository(session).get_finding(finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    require_visible_project(session, current_user, finding.project_id)
    return _finding_public(finding)


def _finding_public(finding: Finding) -> FindingPublic:
    """Return a finding DTO with display context needed by the Workbench table."""
    return FindingPublic.model_validate(finding).model_copy(
        update={
            "component_name": finding.component.name if finding.component else None,
            "component_version": finding.component.version if finding.component else None,
            "component_purl": finding.component.purl if finding.component else None,
            "asset_name": finding.asset.name if finding.asset else None,
            "asset_key": finding.asset.asset_key if finding.asset else None,
            "owner": finding.asset.owner if finding.asset else None,
            "business_service": finding.asset.business_service if finding.asset else None,
            "exposure": finding.asset.exposure if finding.asset else None,
        }
    )


@router.get("/findings/{finding_id}/explain", response_model=FindingExplanationPublic)
def explain_finding(
    finding_id: uuid.UUID,
    session: SessionDep,
    current_user: CurrentUser,
) -> FindingExplanationPublic:
    """Read the persisted decision explanation for one visible finding."""
    finding = FindingRepository(session).get_finding(finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    require_visible_project(session, current_user, finding.project_id)
    try:
        return build_finding_explanation_payload(finding)
    except DecisionDataUnavailableError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

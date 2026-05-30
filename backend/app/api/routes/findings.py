"""Finding API routes for the Workbench domain."""

from __future__ import annotations

import uuid
from typing import Literal

from fastapi import APIRouter, HTTPException, Query

from app.api.deps import LocalActor, SessionDep
from app.api.routes.workbench_access import require_project
from app.models import (
    AssetExposure,
    FindingDetailPublic,
    FindingExplanationPublic,
    FindingPriority,
    FindingsPublic,
    FindingStatus,
)
from app.repositories import FindingPageQuery, FindingRepository
from app.services import DecisionDataUnavailableError, build_finding_explanation_payload
from app.services.finding_projection import (
    _finding_detail_public_with_attack_context,
    _finding_public,
)

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
    "component",
    "owner",
]
FindingsSortDirection = Literal["asc", "desc"]


@router.get("/projects/{project_id}/findings/", response_model=FindingsPublic)
def read_project_findings(
    project_id: uuid.UUID,
    session: SessionDep,
    local_actor: LocalActor,
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
    q: str | None = Query(default=None, max_length=200),
    asset_id: uuid.UUID | None = Query(default=None),
    exposure: AssetExposure | None = Query(default=None),
    epss_min: float | None = Query(default=None, ge=0, le=1),
    epss_max: float | None = Query(default=None, ge=0, le=1),
    cvss_min: float | None = Query(default=None, ge=0, le=10),
    cvss_max: float | None = Query(default=None, ge=0, le=10),
) -> FindingsPublic:
    """List a paginated page of findings for a visible project."""
    require_project(session, project_id)
    findings, count = FindingRepository(session).list_project_findings_query(
        FindingPageQuery(
            project_id=project_id,
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
            query=q,
            asset_id=asset_id,
            exposure=exposure,
            epss_min=epss_min,
            epss_max=epss_max,
            cvss_min=cvss_min,
            cvss_max=cvss_max,
        )
    )
    return FindingsPublic(
        data=[_finding_public(finding, session=session) for finding in findings],
        count=count,
    )


@router.get("/findings/{finding_id}", response_model=FindingDetailPublic)
def read_finding(
    finding_id: uuid.UUID,
    session: SessionDep,
    local_actor: LocalActor,
) -> FindingDetailPublic:
    """Read one finding if its project is visible."""
    finding = FindingRepository(session).get_finding(finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    require_project(session, finding.project_id)
    return _finding_detail_public_with_attack_context(session, finding)


@router.get("/findings/{finding_id}/explain", response_model=FindingExplanationPublic)
def explain_finding(
    finding_id: uuid.UUID,
    session: SessionDep,
    local_actor: LocalActor,
) -> FindingExplanationPublic:
    """Read the persisted decision explanation for one visible finding."""
    finding = FindingRepository(session).get_finding(finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    require_project(session, finding.project_id)
    try:
        return build_finding_explanation_payload(finding)
    except DecisionDataUnavailableError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

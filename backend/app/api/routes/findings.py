"""Finding API routes for the Workbench domain."""

from __future__ import annotations

import uuid
from typing import Literal

from fastapi import APIRouter, HTTPException, Query

from app.api.deps import CurrentUser, SessionDep
from app.api.routes.workbench_access import require_visible_project
from app.models import Finding, FindingPublic, FindingsPublic
from app.repositories import FindingRepository

router = APIRouter(tags=["findings"])

FindingsSort = Literal["operational", "priority", "cve", "status"]


@router.get("/projects/{project_id}/findings/", response_model=FindingsPublic)
def read_project_findings(
    project_id: uuid.UUID,
    session: SessionDep,
    current_user: CurrentUser,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    sort: FindingsSort = Query(default="operational"),
) -> FindingsPublic:
    """List a paginated page of findings for a visible project."""
    require_visible_project(session, current_user, project_id)
    findings, count = FindingRepository(session).list_project_findings_page(
        project_id,
        limit=limit,
        offset=offset,
        sort=sort,
    )
    return FindingsPublic(
        data=[FindingPublic.model_validate(finding) for finding in findings],
        count=count,
    )


@router.get("/findings/{finding_id}", response_model=FindingPublic)
def read_finding(
    finding_id: uuid.UUID,
    session: SessionDep,
    current_user: CurrentUser,
) -> Finding:
    """Read one finding if its project is visible."""
    finding = FindingRepository(session).get_finding(finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    require_visible_project(session, current_user, finding.project_id)
    return finding

"""Project routes for the template-aligned Workbench domain shell."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Query, Response

from app.api.deps import CurrentUser, SessionDep
from app.api.routes.workbench_access import require_visible_project
from app.models import (
    Project,
    ProjectAttackSummaryPublic,
    ProjectCreate,
    ProjectCvssOnlyComparisonPublic,
    ProjectDecisionSummaryPublic,
    ProjectGovernanceRollupsPublic,
    ProjectPublic,
    ProjectsPublic,
    ProjectUpdate,
)
from app.repositories import (
    FindingRepository,
    ProjectRepository,
    RunRepository,
    WaiverRepository,
)
from app.services import (
    build_cvss_only_comparison_payload,
    build_project_attack_summary_payload,
    build_project_governance_rollups_payload,
    build_project_summary_payload,
)

router = APIRouter(prefix="/projects", tags=["projects"])


@router.get("/", response_model=ProjectsPublic)
def read_projects(session: SessionDep, current_user: CurrentUser) -> ProjectsPublic:
    """List projects visible to the current user."""
    projects, count = ProjectRepository(session).list_visible_projects(current_user)
    return ProjectsPublic(
        data=[ProjectPublic.model_validate(project) for project in projects],
        count=count,
    )


@router.post("/", response_model=ProjectPublic)
def create_project(
    *,
    session: SessionDep,
    current_user: CurrentUser,
    project_in: ProjectCreate,
) -> Project:
    """Create a Project owned by the current user."""
    project = ProjectRepository(session).create_project(project_in, owner_id=current_user.id)
    session.commit()
    session.refresh(project)
    return project


@router.get("/{project_id}", response_model=ProjectPublic)
def read_project(project_id: uuid.UUID, session: SessionDep, current_user: CurrentUser) -> Project:
    """Read a single project if it belongs to the user or the user is superuser."""
    return require_visible_project(session, current_user, project_id)


@router.get("/{project_id}/summary", response_model=ProjectDecisionSummaryPublic)
def read_project_summary(
    project_id: uuid.UUID,
    session: SessionDep,
    current_user: CurrentUser,
) -> ProjectDecisionSummaryPublic:
    """Read a dashboard-oriented decision summary for one visible project."""
    require_visible_project(session, current_user, project_id)
    return build_project_summary_payload(
        project_id=project_id,
        findings=FindingRepository(session).list_project_findings(project_id),
        runs=RunRepository(session).list_analysis_runs(project_id),
    )


@router.get("/{project_id}/attack/summary", response_model=ProjectAttackSummaryPublic)
def read_project_attack_summary(
    project_id: uuid.UUID,
    session: SessionDep,
    current_user: CurrentUser,
    limit: int = Query(default=5, ge=1, le=20),
) -> ProjectAttackSummaryPublic:
    """Read top ATT&CK techniques, tactics, and confidence distribution."""
    require_visible_project(session, current_user, project_id)
    finding_repo = FindingRepository(session)
    return build_project_attack_summary_payload(
        project_id=project_id,
        findings=finding_repo.list_project_findings(project_id),
        attack_contexts=finding_repo.list_project_attack_contexts(project_id),
        top_limit=limit,
    )


@router.get("/{project_id}/governance/rollups/", response_model=ProjectGovernanceRollupsPublic)
def read_project_governance_rollups(
    project_id: uuid.UUID,
    session: SessionDep,
    current_user: CurrentUser,
    limit: int = Query(default=5, ge=1, le=20),
) -> ProjectGovernanceRollupsPublic:
    """Read owner, service, environment, and waiver-debt rollups."""
    require_visible_project(session, current_user, project_id)
    waiver_repository = WaiverRepository(session)
    return build_project_governance_rollups_payload(
        project_id=project_id,
        findings=FindingRepository(session).list_project_findings(project_id),
        waivers=waiver_repository.list_project_waivers(project_id),
        waiver_repository=waiver_repository,
        limit=limit,
    )


@router.get("/{project_id}/compare/cvss-only", response_model=ProjectCvssOnlyComparisonPublic)
def compare_project_cvss_only(
    project_id: uuid.UUID,
    session: SessionDep,
    current_user: CurrentUser,
    limit: int = Query(default=10, ge=0, le=100),
) -> ProjectCvssOnlyComparisonPublic:
    """Compare current enriched priorities with a CVSS-only baseline."""
    require_visible_project(session, current_user, project_id)
    return build_cvss_only_comparison_payload(
        project_id=project_id,
        findings=FindingRepository(session).list_project_findings(project_id),
        top_change_limit=limit,
    )


@router.patch("/{project_id}", response_model=ProjectPublic)
def update_project(
    *,
    project_id: uuid.UUID,
    session: SessionDep,
    current_user: CurrentUser,
    project_in: ProjectUpdate,
) -> Project:
    """Update a project if it belongs to the user or the user is superuser."""
    repository = ProjectRepository(session)
    project = require_visible_project(session, current_user, project_id)
    updated = repository.update_project(project, project_in)
    session.commit()
    session.refresh(updated)
    return updated


@router.delete("/{project_id}", status_code=204)
def delete_project(
    project_id: uuid.UUID, session: SessionDep, current_user: CurrentUser
) -> Response:
    """Delete a project if it belongs to the user or the user is superuser."""
    repository = ProjectRepository(session)
    project = require_visible_project(session, current_user, project_id)
    repository.delete_project(project)
    session.commit()
    return Response(status_code=204)

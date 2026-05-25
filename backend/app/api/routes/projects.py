"""Project routes for the Workbench domain shell."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, HTTPException, Query, Request, Response

from app.api.deps import LocalActor, SessionDep
from app.api.routes.workbench_access import require_project
from app.core.app_state import workbench_settings
from app.models import (
    Project,
    ProjectAttackSummaryPublic,
    ProjectCreate,
    ProjectCvssOnlyComparisonPublic,
    ProjectDashboardPublic,
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
    build_project_attack_summary_payload_from_rows,
    build_project_dashboard_payload_from_repositories,
    build_project_governance_rollups_payload_from_repositories,
    build_project_summary_payload_from_counts,
)
from app.services.artifact_cleanup import cleanup_project_artifacts
from app.services.audit import record_audit_event

router = APIRouter(prefix="/projects", tags=["projects"])


@router.get("/", response_model=ProjectsPublic)
def read_projects(
    session: SessionDep,
    local_actor: LocalActor,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> ProjectsPublic:
    """List local Workbench projects."""
    _ = local_actor
    projects, count = ProjectRepository(session).list_projects(limit=limit, offset=offset)
    return ProjectsPublic(
        data=[ProjectPublic.model_validate(project) for project in projects],
        count=count,
    )


@router.post("/", response_model=ProjectPublic)
def create_project(
    *,
    session: SessionDep,
    local_actor: LocalActor,
    project_in: ProjectCreate,
) -> Project:
    """Create a local Workbench project."""
    project = ProjectRepository(session).create_project(project_in)
    record_audit_event(
        session,
        action="project.create",
        resource_type="project",
        resource_id=project.id,
        actor=local_actor,
        project_id=project.id,
        detail={"name": project.name},
    )
    session.commit()
    session.refresh(project)
    return project


@router.get("/{project_id}", response_model=ProjectPublic)
def read_project(
    project_id: uuid.UUID,
    session: SessionDep,
    local_actor: LocalActor,
) -> Project:
    """Read a single local project."""
    return require_project(session, project_id)


@router.get("/{project_id}/summary", response_model=ProjectDecisionSummaryPublic)
def read_project_summary(
    project_id: uuid.UUID,
    session: SessionDep,
    local_actor: LocalActor,
) -> ProjectDecisionSummaryPublic:
    """Read a dashboard-oriented decision summary for one visible project."""
    require_project(session, project_id)
    finding_repository = FindingRepository(session)
    run_repository = RunRepository(session)
    return build_project_summary_payload_from_counts(
        project_id=project_id,
        summary_counts=finding_repository.project_finding_summary_counts(project_id),
        latest_run=run_repository.get_latest_analysis_run(project_id),
    )


@router.get("/{project_id}/dashboard", response_model=ProjectDashboardPublic)
def read_project_dashboard(
    project_id: uuid.UUID,
    session: SessionDep,
    local_actor: LocalActor,
) -> ProjectDashboardPublic:
    """Read the one-call aggregate payload for the project dashboard."""
    require_project(session, project_id)
    finding_repository = FindingRepository(session)
    run_repository = RunRepository(session)
    waiver_repository = WaiverRepository(session)
    return build_project_dashboard_payload_from_repositories(
        project_id=project_id,
        finding_repository=finding_repository,
        run_repository=run_repository,
        waiver_repository=waiver_repository,
    )


@router.get("/{project_id}/attack/summary", response_model=ProjectAttackSummaryPublic)
def read_project_attack_summary(
    project_id: uuid.UUID,
    session: SessionDep,
    local_actor: LocalActor,
    limit: int = Query(default=5, ge=1, le=20),
) -> ProjectAttackSummaryPublic:
    """Read top ATT&CK techniques, tactics, and confidence distribution."""
    require_project(session, project_id)
    finding_repo = FindingRepository(session)
    findings, attack_contexts = finding_repo.list_project_attack_summary_inputs(project_id)
    return build_project_attack_summary_payload_from_rows(
        project_id=project_id,
        findings=findings,
        attack_contexts=attack_contexts,
        top_limit=limit,
    )


@router.get("/{project_id}/governance/rollups/", response_model=ProjectGovernanceRollupsPublic)
def read_project_governance_rollups(
    project_id: uuid.UUID,
    session: SessionDep,
    local_actor: LocalActor,
    limit: int = Query(default=5, ge=1, le=20),
) -> ProjectGovernanceRollupsPublic:
    """Read owner, service, environment, and waiver-debt rollups."""
    require_project(session, project_id)
    finding_repository = FindingRepository(session)
    waiver_repository = WaiverRepository(session)
    return build_project_governance_rollups_payload_from_repositories(
        project_id=project_id,
        finding_repository=finding_repository,
        waiver_repository=waiver_repository,
        limit=limit,
    )


@router.get("/{project_id}/compare/cvss-only", response_model=ProjectCvssOnlyComparisonPublic)
def compare_project_cvss_only(
    project_id: uuid.UUID,
    request: Request,
    session: SessionDep,
    local_actor: LocalActor,
    limit: int = Query(default=10, ge=0, le=100),
    include_comparisons: bool = Query(default=False),
) -> ProjectCvssOnlyComparisonPublic:
    """Compare current enriched priorities with a CVSS-only baseline."""
    require_project(session, project_id)
    active_settings = workbench_settings(request)
    finding_repository = FindingRepository(session)
    finding_count = finding_repository.count_project_findings(project_id)
    if finding_count > active_settings.DECISION_API_MAX_FINDINGS:
        raise HTTPException(
            status_code=413,
            detail=(
                "Project contains too many findings for CVSS comparison. "
                "Use paginated finding APIs or increase DECISION_API_MAX_FINDINGS."
            ),
        )
    return build_cvss_only_comparison_payload(
        project_id=project_id,
        findings=finding_repository.list_project_findings(project_id),
        top_change_limit=limit,
        include_comparisons=include_comparisons,
    )


@router.patch("/{project_id}", response_model=ProjectPublic)
def update_project(
    *,
    project_id: uuid.UUID,
    session: SessionDep,
    local_actor: LocalActor,
    project_in: ProjectUpdate,
) -> Project:
    """Update a local project."""
    repository = ProjectRepository(session)
    project = require_project(session, project_id)
    updated = repository.update_project(project, project_in)
    record_audit_event(
        session,
        action="project.update",
        resource_type="project",
        resource_id=updated.id,
        actor=local_actor,
        project_id=updated.id,
        detail=project_in.model_dump(exclude_unset=True),
    )
    session.commit()
    session.refresh(updated)
    return updated


@router.delete("/{project_id}", status_code=204)
def delete_project(
    request: Request,
    project_id: uuid.UUID,
    session: SessionDep,
    local_actor: LocalActor,
) -> Response:
    """Delete a local project."""
    repository = ProjectRepository(session)
    project = require_project(session, project_id)
    cleanup_result = cleanup_project_artifacts(
        settings=workbench_settings(request),
        project_id=project.id,
    )
    record_audit_event(
        session,
        action="project.delete",
        resource_type="project",
        resource_id=project.id,
        actor=local_actor,
        detail={
            "name": project.name,
            "removed_artifact_paths": list(cleanup_result.removed_paths),
            "missing_artifact_paths": list(cleanup_result.missing_paths),
        },
    )
    repository.delete_project(project)
    session.commit()
    return Response(status_code=204)

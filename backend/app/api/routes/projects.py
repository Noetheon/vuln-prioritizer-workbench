"""Project routes for the template-aligned Workbench domain shell."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Response

from app.api.deps import CurrentUser, SessionDep
from app.api.routes.workbench_access import require_visible_project
from app.models import Project, ProjectCreate, ProjectPublic, ProjectsPublic, ProjectUpdate
from app.repositories import ProjectRepository

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

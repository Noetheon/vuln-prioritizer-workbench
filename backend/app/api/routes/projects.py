"""Project routes for the template-aligned Workbench domain shell."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, HTTPException

from app.api.deps import CurrentUser, SessionDep
from app.models import Project, ProjectCreate, ProjectPublic, ProjectsPublic
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
    repository = ProjectRepository(session)
    project = repository.get_project(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    if not current_user.is_superuser and project.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not enough permissions")
    return project

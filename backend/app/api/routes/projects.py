"""Project routes for the template-aligned Workbench domain shell."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, HTTPException
from sqlmodel import col, func, select

from app.api.deps import CurrentUser, SessionDep
from app.models import Project, ProjectCreate, ProjectPublic, ProjectsPublic

router = APIRouter(prefix="/projects", tags=["projects"])


@router.get("/", response_model=ProjectsPublic)
def read_projects(session: SessionDep, current_user: CurrentUser) -> ProjectsPublic:
    """List projects visible to the current user."""
    count_statement = select(func.count()).select_from(Project)
    statement = select(Project).order_by(col(Project.created_at).desc())
    if not current_user.is_superuser:
        count_statement = count_statement.where(Project.owner_id == current_user.id)
        statement = statement.where(Project.owner_id == current_user.id)

    count = session.exec(count_statement).one()
    projects = session.exec(statement).all()
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
    project = Project.model_validate(project_in, update={"owner_id": current_user.id})
    session.add(project)
    session.commit()
    session.refresh(project)
    return project


@router.get("/{project_id}", response_model=ProjectPublic)
def read_project(project_id: uuid.UUID, session: SessionDep, current_user: CurrentUser) -> Project:
    """Read a single project if it belongs to the user or the user is superuser."""
    project = session.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    if not current_user.is_superuser and project.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not enough permissions")
    return project

"""Shared access helpers for Workbench domain API routes."""

from __future__ import annotations

import uuid

from fastapi import HTTPException
from sqlmodel import Session

from app.models import Project, User
from app.repositories import ProjectRepository


def require_visible_project(session: Session, current_user: User, project_id: uuid.UUID) -> Project:
    """Return a project or raise a consistent 404/403 API error."""
    project = ProjectRepository(session).get_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")
    if not current_user.is_superuser and project.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not enough permissions")
    return project

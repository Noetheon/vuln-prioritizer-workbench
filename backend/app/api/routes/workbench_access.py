"""Shared access helpers for Workbench domain API routes."""

from __future__ import annotations

import uuid

from fastapi import HTTPException
from sqlmodel import Session

from app.models import Project
from app.repositories import ProjectRepository


def require_project(session: Session, project_id: uuid.UUID) -> Project:
    """Return a project for the local single-user Workbench or raise 404."""
    project = ProjectRepository(session).get_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")
    return project

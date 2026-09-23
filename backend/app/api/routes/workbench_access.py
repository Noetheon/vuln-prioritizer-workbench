"""Shared access helpers for Workbench domain API routes."""

from __future__ import annotations

import uuid
from typing import TypeVar

from fastapi import HTTPException
from sqlmodel import Session, SQLModel, select

from app.models import Finding, Project
from app.models.base import get_datetime_utc
from app.repositories import ProjectRepository
from app.services.decision_scope_lock import lock_project_decision_scope

_ProjectResource = TypeVar("_ProjectResource", bound=SQLModel)


def require_project(session: Session, project_id: uuid.UUID) -> Project:
    """Return a project for the local single-user Workbench or raise 404."""
    project = ProjectRepository(session).get_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")
    return project


def require_current_decisions(session: Session, project_id: uuid.UUID) -> Project:
    """Read-only freshness gate; the worker owns all daily decision mutations."""
    project = require_project(session, project_id)
    if project.waiver_evaluated_on != get_datetime_utc().date():
        has_findings = session.exec(
            select(Finding.id).where(Finding.project_id == project_id).limit(1)
        ).first()
        if has_findings is not None:
            raise HTTPException(
                status_code=503,
                headers={"Retry-After": "2", "Cache-Control": "no-store"},
                detail={
                    "code": "decision_refresh_pending",
                    "message": "Current decisions are awaiting today's governance update. "
                    "Retry shortly; if this persists, check the worker status.",
                    "evaluated_on": project.waiver_evaluated_on.isoformat()
                    if project.waiver_evaluated_on is not None
                    else None,
                },
            )
    return project


def lock_existing_project_resource(
    session: Session,
    *,
    model: type[_ProjectResource],
    resource_id: uuid.UUID,
    project_id: uuid.UUID,
    not_found_detail: str,
) -> _ProjectResource:
    """Lock a resource's project, then reject a concurrently deleted stale row."""
    require_project(session, project_id)
    lock_project_decision_scope(session, project_id)
    current = session.get(model, resource_id, populate_existing=True)
    if current is None or getattr(current, "project_id", None) != project_id:
        raise HTTPException(status_code=404, detail=not_found_detail)
    return current

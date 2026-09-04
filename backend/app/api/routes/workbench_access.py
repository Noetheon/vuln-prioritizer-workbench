"""Shared access helpers for Workbench domain API routes."""

from __future__ import annotations

import uuid
from typing import TypeVar

from fastapi import HTTPException
from sqlalchemy import or_, update
from sqlmodel import Session, SQLModel, col

from app.models import Project
from app.models.base import get_datetime_utc
from app.repositories import ProjectRepository
from app.services.audit import record_audit_event
from app.services.decision_scope_lock import (
    ProjectDecisionLockError,
    lock_project_decision_scope,
)

_ProjectResource = TypeVar("_ProjectResource", bound=SQLModel)


def require_project(session: Session, project_id: uuid.UUID) -> Project:
    """Return a project for the local single-user Workbench or raise 404."""
    project = ProjectRepository(session).get_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")
    _refresh_stale_project_waivers(session, project)
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


def _refresh_stale_project_waivers(session: Session, project: Project) -> None:
    """Refresh date-sensitive waiver decisions once per UTC calendar day."""
    evaluated_on = get_datetime_utc().date()
    if project.waiver_evaluated_on == evaluated_on:
        return

    # Claim this project's UTC-day refresh with one compare-and-set write. Two
    # requests may both have loaded yesterday's ORM state, but only the first
    # transaction whose database predicate still matches is allowed to rebuild
    # projections. The claim intentionally shares the refresh transaction so a
    # failed rebuild rolls the marker back as well.
    claim = session.connection().execute(
        update(Project)
        .where(
            col(Project.id) == project.id,
            or_(
                col(Project.waiver_evaluated_on).is_(None),
                col(Project.waiver_evaluated_on) != evaluated_on,
            ),
        )
        .values(waiver_evaluated_on=evaluated_on)
        .execution_options(synchronize_session=False)
    )
    if claim.rowcount != 1:
        current = session.get(Project, project.id, populate_existing=True)
        if current is None:
            raise ProjectDecisionLockError(f"Project {project.id} does not exist.")
        return

    # Import lazily to keep the shared route dependency free of repository cycles.
    from app.repositories.waivers import WaiverRepository

    try:
        changed_finding_ids: set[uuid.UUID] = set()
        WaiverRepository(session).sync_project_waivers(
            project.id,
            changed_finding_ids=changed_finding_ids,
        )
        project.waiver_evaluated_on = evaluated_on
        session.add(project)
        if changed_finding_ids:
            record_audit_event(
                session,
                action="waiver.lifecycle_refresh",
                resource_type="project",
                resource_id=project.id,
                project_id=project.id,
                detail={
                    "evaluated_on": evaluated_on.isoformat(),
                    "changed_finding_count": len(changed_finding_ids),
                    "changed_finding_ids": sorted(str(item) for item in changed_finding_ids),
                },
            )
        session.commit()
        session.refresh(project)
    except Exception:
        session.rollback()
        raise

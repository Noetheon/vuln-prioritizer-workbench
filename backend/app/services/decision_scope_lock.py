"""Transaction-scoped serialization for mutable project decision state."""

from __future__ import annotations

import uuid

from sqlalchemy import update
from sqlmodel import Session, col, select

from app.models import Project


class ProjectDecisionLockError(RuntimeError):
    """Raised when a decision mutation cannot lock its project row."""


def lock_project_decision_scope(session: Session, project_id: uuid.UUID) -> None:
    """Serialize decision-source and projection mutations for one project."""
    bind = session.get_bind()
    if bind.dialect.name != "sqlite":
        locked_id = session.exec(
            select(Project.id).where(col(Project.id) == project_id).with_for_update()
        ).first()
        if locked_id is None:
            raise ProjectDecisionLockError(f"Project {project_id} does not exist.")
        return

    # SQLite has no SELECT FOR UPDATE. A no-op row UPDATE acquires its writer
    # lock inside this same transaction, so another process cannot compute and
    # commit a projection from a concurrent stale snapshot.
    result = session.connection().execute(
        update(Project)
        .where(col(Project.id) == project_id)
        .values(updated_at=col(Project.updated_at))
    )
    if result.rowcount != 1:
        raise ProjectDecisionLockError(f"Project {project_id} does not exist.")

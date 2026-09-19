"""Transaction-scoped serialization for mutable project decision state."""

from __future__ import annotations

import uuid

from sqlalchemy import update
from sqlmodel import Session, col, select

from app.models import Project


class ProjectDecisionLockError(RuntimeError):
    """Raised when a decision mutation cannot lock its project row."""


class ProjectDecisionConflict(ProjectDecisionLockError):
    """Raised when inputs changed while a decision was being computed."""


def project_decision_revision(session: Session, project_id: uuid.UUID) -> int:
    """Read the database revision rather than a cached Project object."""
    revision = session.exec(
        select(Project.decision_revision).where(col(Project.id) == project_id)
    ).first()
    if revision is None:
        raise ProjectDecisionLockError(f"Project {project_id} does not exist.")
    return revision


def lock_project_decision_scope(
    session: Session, project_id: uuid.UUID, *, expected_revision: int | None = None
) -> None:
    """Serialize decision-source and projection mutations for one project."""
    # An atomic UPDATE acquires the row/writer lock on both supported databases.
    # Every mutation advances this token in the same transaction; rollback also
    # rolls back the token, while stale computations cannot publish over a winner.
    statement = (
        update(Project)
        .where(col(Project.id) == project_id)
        .values(decision_revision=col(Project.decision_revision) + 1)
        .execution_options(synchronize_session=False)
    )
    if expected_revision is not None:
        statement = statement.where(col(Project.decision_revision) == expected_revision)
    result = session.connection().execute(statement)
    if result.rowcount != 1:
        if expected_revision is not None:
            raise ProjectDecisionConflict("Project decisions changed; start a new evaluation.")
        raise ProjectDecisionLockError(f"Project {project_id} does not exist.")

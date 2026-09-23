"""Worker-owned UTC-day governance maintenance with atomic publication fences."""

from __future__ import annotations

import logging
import threading
import uuid

from sqlalchemy import or_, update
from sqlalchemy.engine import Engine
from sqlmodel import Session, col, select

from app.models import Project
from app.models.base import get_datetime_utc
from app.services.audit import record_audit_event
from app.services.decision_projection_sync import DecisionProjectionService
from app.services.decision_scope_lock import ProjectDecisionLockError

logger = logging.getLogger(__name__)


def refresh_project_decisions(session: Session, project: Project) -> bool:
    """Claim, refresh and commit one UTC day; rollback the entire claim on failure."""
    evaluated_on = get_datetime_utc().date()
    if project.waiver_evaluated_on == evaluated_on:
        return False
    claim = session.connection().execute(
        update(Project)
        .where(
            col(Project.id) == project.id,
            or_(
                col(Project.waiver_evaluated_on).is_(None),
                col(Project.waiver_evaluated_on) != evaluated_on,
            ),
        )
        .values(
            waiver_evaluated_on=evaluated_on,
            decision_revision=col(Project.decision_revision) + 1,
        )
        .execution_options(synchronize_session=False)
    )
    if claim.rowcount != 1:
        if session.get(Project, project.id, populate_existing=True) is None:
            raise ProjectDecisionLockError(f"Project {project.id} does not exist.")
        return False
    try:
        changed_finding_ids: set[uuid.UUID] = set()
        DecisionProjectionService(session).sync_project_waivers(
            project.id,
            changed_finding_ids=changed_finding_ids,
            revision_cause="waiver_expiry",
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
        return True
    except Exception:
        session.rollback()
        raise


def maintain_due_project_decisions(
    engine: Engine, *, stop_event: threading.Event | None = None
) -> tuple[int, int]:
    """Maintain each due project independently; a failed project cannot block others."""
    if stop_event is not None and stop_event.is_set():
        return 0, 0
    today = get_datetime_utc().date()
    with Session(engine) as session:
        project_ids = session.exec(
            select(Project.id)
            .where(
                or_(
                    col(Project.waiver_evaluated_on).is_(None),
                    col(Project.waiver_evaluated_on) != today,
                )
            )
            .order_by(col(Project.id))
        ).all()
    completed = failed = 0
    for project_id in project_ids:
        if stop_event is not None and stop_event.is_set():
            break
        try:
            with Session(engine) as session:
                project = session.get(Project, project_id)
                if project is not None:
                    completed += int(refresh_project_decisions(session, project))
        except Exception:
            # The unadvanced date is the durable retry condition. Current-read
            # endpoints remain unavailable, rather than displaying stale acceptance.
            logger.exception("Daily decision refresh failed for project %s", project_id)
            failed += 1
    return completed, failed

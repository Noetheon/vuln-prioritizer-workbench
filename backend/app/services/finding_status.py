"""Manual workflow status transitions for findings."""

from __future__ import annotations

from typing import Any

from sqlmodel import Session

from app.core.local_actor import LocalWorkbenchActor
from app.models import Finding, FindingStatus
from app.models.base import get_datetime_utc
from app.repositories import FindingCurrentProjectionRepository
from app.services.audit import record_audit_event

# Statuses an analyst may set by hand. Terminal governance states stay owned
# by their sources: waivers (accepted), VEX (suppressed), and imports (fixed).
WORKFLOW_STATUSES = frozenset(
    {
        FindingStatus.OPEN,
        FindingStatus.IN_REVIEW,
        FindingStatus.REMEDIATING,
    }
)


class FindingStatusTransitionError(ValueError):
    """Raised when a manual finding status transition is not allowed."""


def update_finding_workflow_status(
    session: Session,
    *,
    finding: Finding,
    status: FindingStatus,
    local_actor: LocalWorkbenchActor,
) -> Finding:
    """Apply a manual workflow status and update only materialized current state."""
    if status not in WORKFLOW_STATUSES:
        raise FindingStatusTransitionError(
            f"Status '{status.value}' is governance-managed and cannot be set manually."
        )
    current_status = FindingStatus(finding.status)
    if current_status not in WORKFLOW_STATUSES:
        raise FindingStatusTransitionError(
            f"Finding is in governance-managed status '{current_status.value}'; "
            "resolve the waiver or VEX statement instead."
        )

    previous_status = current_status
    finding.status = status
    finding.updated_at = get_datetime_utc()
    session.add(finding)
    _sync_current_projection_status(session, finding)
    record_audit_event(
        session,
        action="finding.status",
        resource_type="finding",
        resource_id=finding.id,
        status="success",
        actor=local_actor,
        project_id=finding.project_id,
        detail={"from": previous_status.value, "to": status.value},
    )
    session.flush()
    return finding


def _sync_current_projection_status(session: Session, finding: Finding) -> None:
    """Mirror the manual status into mutable current state, never run history."""
    status_value = FindingStatus(finding.status).value

    def update(payload: dict[str, Any]) -> dict[str, Any]:
        payload["status"] = status_value
        return payload

    FindingCurrentProjectionRepository(session).mutate_current_payload(finding.id, update)

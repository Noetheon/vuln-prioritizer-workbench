"""Manual workflow status transitions for findings."""

from __future__ import annotations

import uuid
from collections.abc import Sequence

from sqlmodel import Session, col, select

from app.core.local_actor import LocalWorkbenchActor
from app.models import (
    CLOSED_WORKFLOW_STATUSES,
    Finding,
    FindingBulkStatusSkipPublic,
    FindingBulkStatusUpdatePublic,
    FindingLifecycleSource,
    FindingStatus,
)
from app.services.audit import record_audit_event
from app.services.decision_projection_sync_fast import sync_unchanged_project_ranks
from app.services.finding_lifecycle import record_lifecycle_event, set_current_status

# Statuses an analyst may set by hand. Terminal governance states stay owned
# by their sources: waivers (accepted), VEX (suppressed), and VEX-fixed (fixed).
WORKFLOW_STATUSES = frozenset(
    {
        FindingStatus.OPEN,
        FindingStatus.IN_REVIEW,
        FindingStatus.REMEDIATING,
        FindingStatus.RESOLVED,
        FindingStatus.FALSE_POSITIVE,
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
    reason: str | None = None,
) -> Finding:
    """Apply a manual workflow status, record why, and reorder the current queue."""
    changed = _apply_manual_status(
        session,
        finding=finding,
        status=status,
        local_actor=local_actor,
        reason=reason,
    )
    if changed:
        _sync_queue(session, finding.project_id)
    session.flush()
    return finding


def update_findings_workflow_status(
    session: Session,
    *,
    project_id: uuid.UUID,
    finding_ids: Sequence[uuid.UUID],
    status: FindingStatus,
    local_actor: LocalWorkbenchActor,
    reason: str | None = None,
) -> FindingBulkStatusUpdatePublic:
    """Apply one manual status to many findings; report the ones left unchanged."""
    _validate_target(status, reason)
    requested = list(dict.fromkeys(finding_ids))
    findings = {
        finding.id: finding
        for finding in session.exec(
            select(Finding).where(
                col(Finding.project_id) == project_id,
                col(Finding.id).in_(requested),
            )
        ).all()
    }
    result = FindingBulkStatusUpdatePublic(status=status)
    for finding_id in requested:
        finding = findings.get(finding_id)
        if finding is None:
            result.skipped.append(
                FindingBulkStatusSkipPublic(
                    finding_id=finding_id,
                    detail="Finding not found in this project.",
                )
            )
            continue
        try:
            changed = _apply_manual_status(
                session,
                finding=finding,
                status=status,
                local_actor=local_actor,
                reason=reason,
            )
        except FindingStatusTransitionError as exc:
            result.skipped.append(
                FindingBulkStatusSkipPublic(finding_id=finding_id, detail=str(exc))
            )
            continue
        if changed:
            result.updated_ids.append(finding_id)
        else:
            result.skipped.append(
                FindingBulkStatusSkipPublic(
                    finding_id=finding_id,
                    detail=f"Finding already has status '{status.value}'.",
                )
            )
    result.updated_count = len(result.updated_ids)
    if result.updated_ids:
        _sync_queue(session, project_id)
    session.flush()
    return result


def _apply_manual_status(
    session: Session,
    *,
    finding: Finding,
    status: FindingStatus,
    local_actor: LocalWorkbenchActor,
    reason: str | None,
) -> bool:
    _validate_target(status, reason)
    current_status = FindingStatus(finding.status)
    if current_status not in WORKFLOW_STATUSES:
        raise FindingStatusTransitionError(
            f"Finding is in governance-managed status '{current_status.value}'; "
            "resolve the waiver or VEX statement instead."
        )
    if current_status == status:
        return False
    cleaned_reason = _clean_reason(reason)
    set_current_status(session, finding, status)
    record_lifecycle_event(
        session,
        finding=finding,
        from_status=current_status,
        to_status=status,
        source=FindingLifecycleSource.MANUAL,
        reason=cleaned_reason,
        actor=local_actor.email,
    )
    record_audit_event(
        session,
        action="finding.status",
        resource_type="finding",
        resource_id=finding.id,
        status="success",
        actor=local_actor,
        project_id=finding.project_id,
        detail={
            "from": current_status.value,
            "to": status.value,
            "reason_recorded": cleaned_reason is not None,
        },
    )
    return True


def _validate_target(status: FindingStatus, reason: str | None) -> None:
    if status not in WORKFLOW_STATUSES:
        raise FindingStatusTransitionError(
            f"Status '{status.value}' is governance-managed and cannot be set manually."
        )
    if status in CLOSED_WORKFLOW_STATUSES and _clean_reason(reason) is None:
        raise FindingStatusTransitionError(
            f"A reason is required to mark a finding as '{status.value}'."
        )


def _clean_reason(reason: str | None) -> str | None:
    cleaned = (reason or "").strip()
    return cleaned or None


def _sync_queue(session: Session, project_id: uuid.UUID) -> None:
    """Move closed findings behind open work without re-evaluating any decision."""
    session.flush()
    sync_unchanged_project_ranks(session, project_id, require_complete=False)

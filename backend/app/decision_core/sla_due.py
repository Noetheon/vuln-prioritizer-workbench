"""SLA due dates: a finding's first sighting plus its recorded SLA target."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, TypeGuard

from app.models.enums import ACTIONABLE_FINDING_STATUSES, FindingSlaState, FindingStatus

# The last quarter of an SLA window counts as due soon.
DUE_SOON_FRACTION = 0.25


@dataclass(frozen=True, slots=True)
class SlaDue:
    """When open work is due and where it stands at a given time."""

    due_at: datetime
    state: FindingSlaState


def sla_target_hours(sla: Mapping[str, Any] | None) -> int | None:
    """Return the recorded SLA window in hours, preferring hours over days."""
    if not sla:
        return None
    hours = sla.get("target_hours")
    if _positive_int(hours):
        return hours
    days = sla.get("target_days")
    if _positive_int(days):
        return days * 24
    return None


def sla_due(
    *,
    first_seen_at: datetime,
    sla: Mapping[str, Any] | None,
    status: FindingStatus | str,
    now: datetime,
) -> SlaDue | None:
    """
    Return the due date of open work, or None for closed or governed findings.

    The clock starts when the Workbench first saw the finding, and the window
    is the SLA recorded with its current decision. A priority escalation keeps
    the original start, so escalated work can become overdue at once.
    """
    try:
        if FindingStatus(status) not in ACTIONABLE_FINDING_STATUSES:
            return None
    except ValueError:
        return None
    hours = sla_target_hours(sla)
    if hours is None:
        return None
    window = timedelta(hours=hours)
    due_at = as_utc(first_seen_at) + window
    current = as_utc(now)
    if current >= due_at:
        state = FindingSlaState.OVERDUE
    elif current >= due_at - window * DUE_SOON_FRACTION:
        state = FindingSlaState.DUE_SOON
    else:
        state = FindingSlaState.ON_TRACK
    return SlaDue(due_at=due_at, state=state)


def first_seen_bounds(
    state: FindingSlaState,
    *,
    hours: int,
    now: datetime,
) -> tuple[datetime | None, datetime | None]:
    """
    Return the (exclusive lower, inclusive upper) first-seen bounds of a state.

    Matches :func:`sla_due` for one SLA window so queries can filter by state.
    """
    window = timedelta(hours=hours)
    current = as_utc(now)
    overdue_from = current - window
    due_soon_from = current - window * (1 - DUE_SOON_FRACTION)
    if state == FindingSlaState.OVERDUE:
        return None, overdue_from
    if state == FindingSlaState.DUE_SOON:
        return overdue_from, due_soon_from
    return due_soon_from, None


def as_utc(value: datetime) -> datetime:
    """Treat stored naive timestamps as UTC."""
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _positive_int(value: Any) -> TypeGuard[int]:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0

"""Per-project priority policy: read, validate against the engine rules, and save."""

from __future__ import annotations

import uuid

from sqlmodel import Session

from app.core.local_actor import LocalWorkbenchActor
from app.domain.engine.models import PriorityPolicy, SlaHoursPolicy
from app.domain.engine.services.decision_guidance import SLA_BY_PRIORITY
from app.models import (
    ProjectPolicy,
    ProjectPolicyFields,
    ProjectPolicyPublic,
    SlaHoursPublic,
)
from app.models.base import get_datetime_utc
from app.services.audit import record_audit_event


def default_sla_hours() -> SlaHoursPolicy:
    """Return the engine's default response targets as a policy."""
    return SlaHoursPolicy(
        critical=_default_hours("Critical"),
        high=_default_hours("High"),
        medium=_default_hours("Medium"),
        low=_default_hours("Low"),
    )


def current_priority_policy(session: Session, project_id: uuid.UUID) -> PriorityPolicy:
    """Return the policy new evaluations of this project use."""
    row = session.get(ProjectPolicy, project_id)
    if row is None or not row.policy_json:
        return PriorityPolicy()
    return PriorityPolicy.model_validate(row.policy_json)


def project_policy_public(session: Session, project_id: uuid.UUID) -> ProjectPolicyPublic:
    """Return the effective policy with its version and the defaults."""
    row = session.get(ProjectPolicy, project_id)
    policy = current_priority_policy(session, project_id)
    return ProjectPolicyPublic(
        **policy_fields(policy).model_dump(),
        project_id=project_id,
        version=row.version if row is not None else 0,
        is_default=policy == PriorityPolicy(),
        updated_at=row.updated_at if row is not None else None,
        updated_by=row.updated_by if row is not None else None,
        defaults=policy_fields(PriorityPolicy()),
    )


def policy_fields(policy: PriorityPolicy) -> ProjectPolicyFields:
    """Express an engine policy with explicit SLA hours for every priority."""
    sla = policy.sla_hours or default_sla_hours()
    return ProjectPolicyFields(
        critical_epss_threshold=policy.critical_epss_threshold,
        critical_cvss_threshold=policy.critical_cvss_threshold,
        high_epss_threshold=policy.high_epss_threshold,
        high_cvss_threshold=policy.high_cvss_threshold,
        medium_epss_threshold=policy.medium_epss_threshold,
        medium_cvss_threshold=policy.medium_cvss_threshold,
        sla_hours=SlaHoursPublic(**sla.model_dump()),
    )


def engine_policy(fields: ProjectPolicyFields) -> PriorityPolicy:
    """
    Validate submitted fields with the engine's own rules.

    Default SLA hours are stored as "no override", so a project that only
    changes thresholds keeps recording the default SLA table.
    """
    sla = SlaHoursPolicy(**fields.sla_hours.model_dump())
    return PriorityPolicy(
        critical_epss_threshold=fields.critical_epss_threshold,
        critical_cvss_threshold=fields.critical_cvss_threshold,
        high_epss_threshold=fields.high_epss_threshold,
        high_cvss_threshold=fields.high_cvss_threshold,
        medium_epss_threshold=fields.medium_epss_threshold,
        medium_cvss_threshold=fields.medium_cvss_threshold,
        sla_hours=None if sla == default_sla_hours() else sla,
    )


def save_project_policy(
    session: Session,
    project_id: uuid.UUID,
    fields: ProjectPolicyFields,
    *,
    actor: LocalWorkbenchActor,
    reason: str | None = None,
) -> bool:
    """Store a changed policy with a new version; return whether anything changed."""
    policy = engine_policy(fields)
    previous = current_priority_policy(session, project_id)
    if policy == previous:
        return False
    row = session.get(ProjectPolicy, project_id) or ProjectPolicy(project_id=project_id, version=0)
    row.version += 1
    row.policy_json = policy.model_dump(mode="json")
    row.updated_at = get_datetime_utc()
    row.updated_by = actor.email
    session.add(row)
    record_audit_event(
        session,
        action="project.policy",
        resource_type="project",
        resource_id=project_id,
        actor=actor,
        project_id=project_id,
        detail={
            "version": row.version,
            "from": previous.model_dump(mode="json"),
            "to": row.policy_json,
            "reason_recorded": bool(reason and reason.strip()),
        },
    )
    session.flush()
    return True


def _default_hours(priority: str) -> int:
    hours = SLA_BY_PRIORITY[priority].target_hours
    assert hours is not None
    return hours

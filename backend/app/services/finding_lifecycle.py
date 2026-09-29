"""
Finding lifecycle: analyst closure, rescan reconciliation, and status history.

Status changes are current state. They never rewrite immutable decision evidence;
every transition appends a ``finding_lifecycle_event`` with its cause.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Collection, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func
from sqlmodel import Session, col, select

from app.domain.asset_identity import normalize_asset_identity_value, normalize_asset_target_kind
from app.models import (
    ACTIONABLE_FINDING_STATUSES,
    Finding,
    FindingCurrentProjection,
    FindingLifecycleEvent,
    FindingLifecycleEventPublic,
    FindingLifecycleSource,
    FindingOccurrence,
    FindingStatus,
)
from app.models.base import get_datetime_utc
from app.models.occurrence_identity import occurrence_identity_expressions
from app.repositories import FindingCurrentProjectionRepository

TargetKey = tuple[str, str]
CoverageKey = tuple[str, TargetKey]


@dataclass(frozen=True)
class ImportReconciliation:
    """Findings closed or reopened because of what one import did or did not observe."""

    resolved_ids: tuple[uuid.UUID, ...] = ()
    reopened_ids: tuple[uuid.UUID, ...] = ()

    @property
    def changed(self) -> bool:
        """Return whether any finding changed status."""
        return bool(self.resolved_ids or self.reopened_ids)


def scope_target_key(
    target_kind: str | None,
    target_ref: str | None,
    asset_id: str | None = None,
) -> TargetKey | None:
    """Normalize a finding scope target exactly like finding-scope-v2 identity."""
    reference = _normalized_value(target_ref) or _normalized_value(asset_id)
    if reference is None:
        return None
    kind = normalize_asset_target_kind(target_kind or "generic") or "generic"
    return kind, reference


def import_coverage(
    observations: Iterable[tuple[str | None, str | None, str | None, str | None]],
) -> set[CoverageKey]:
    """Return the (source format, target) pairs an import actually examined."""
    coverage: set[CoverageKey] = set()
    for source, target_kind, target_ref, asset_id in observations:
        target = scope_target_key(target_kind, target_ref, asset_id)
        if source and target is not None:
            coverage.add((source.strip().casefold(), target))
    return coverage


def set_current_status(
    session: Session,
    finding: Finding,
    status: FindingStatus,
) -> None:
    """Write a status to the finding row and its materialized current decision only."""
    finding.status = status
    finding.updated_at = get_datetime_utc()
    session.add(finding)
    status_value = status.value

    def update(payload: dict[str, Any]) -> dict[str, Any]:
        payload["status"] = status_value
        return payload

    FindingCurrentProjectionRepository(session).mutate_current_payload(finding.id, update)


def record_lifecycle_event(
    session: Session,
    *,
    finding: Finding,
    from_status: FindingStatus | str,
    to_status: FindingStatus | str,
    source: FindingLifecycleSource,
    reason: str | None = None,
    analysis_run_id: uuid.UUID | None = None,
    actor: str | None = None,
) -> FindingLifecycleEvent:
    """Append one immutable status-history row."""
    event = FindingLifecycleEvent(
        project_id=finding.project_id,
        finding_id=finding.id,
        analysis_run_id=analysis_run_id,
        from_status=FindingStatus(from_status).value,
        to_status=FindingStatus(to_status).value,
        source=source.value,
        reason=reason,
        actor=actor,
    )
    session.add(event)
    return event


def list_lifecycle_events(
    session: Session,
    finding_id: uuid.UUID,
    *,
    limit: int = 100,
    offset: int = 0,
) -> tuple[list[FindingLifecycleEventPublic], int]:
    """Return newest-first status history for one finding."""
    count = int(
        session.exec(
            select(func.count())
            .select_from(FindingLifecycleEvent)
            .where(col(FindingLifecycleEvent.finding_id) == finding_id)
        ).one()
    )
    rows = session.exec(
        select(FindingLifecycleEvent)
        .where(col(FindingLifecycleEvent.finding_id) == finding_id)
        .order_by(col(FindingLifecycleEvent.created_at).desc(), col(FindingLifecycleEvent.id))
        .offset(offset)
        .limit(limit)
    ).all()
    events = [FindingLifecycleEventPublic.model_validate(row, from_attributes=True) for row in rows]
    return events, count


def resolved_finding_ids(session: Session, project_id: uuid.UUID) -> set[uuid.UUID]:
    """Return findings currently resolved, captured before an import may reopen them."""
    return set(
        session.exec(
            select(Finding.id).where(
                col(Finding.project_id) == project_id,
                col(Finding.status) == FindingStatus.RESOLVED.value,
            )
        ).all()
    )


def resolved_after_observation(
    session: Session,
    finding_ids: Collection[uuid.UUID],
    observed_at: datetime | None,
) -> set[uuid.UUID]:
    """
    Return resolved findings closed at or after an import's observation time.

    Re-assessing an older observation, such as an SBOM rescan, must not reopen
    what newer evidence or an analyst already closed.
    """
    if observed_at is None or not finding_ids:
        return set()
    observation = _naive_utc(observed_at)
    rows = session.exec(
        select(FindingLifecycleEvent.finding_id, func.max(FindingLifecycleEvent.created_at))
        .where(
            col(FindingLifecycleEvent.finding_id).in_(list(finding_ids)),
            col(FindingLifecycleEvent.to_status) == FindingStatus.RESOLVED.value,
        )
        .group_by(col(FindingLifecycleEvent.finding_id))
    ).all()
    return {
        finding_id
        for finding_id, resolved_at in rows
        if resolved_at is not None and _naive_utc(resolved_at) >= observation
    }


def reconcile_import_observations(
    session: Session,
    *,
    project_id: uuid.UUID,
    run_id: uuid.UUID,
    coverage: Collection[CoverageKey],
    previously_resolved: Collection[uuid.UUID],
    run_label: str,
    actor: str | None,
    resolve_missing: bool = True,
    observed_at: datetime | None = None,
) -> ImportReconciliation:
    """
    Resolve findings a rescan no longer reports and record reobserved ones.

    A finding is resolved only when this run examined one of its targets with a
    source format that previously reported it, and did not report it again.
    Findings from other scanners, CVE-only lists, other targets, closed or
    governed findings are left untouched. An import with an explicit, older
    observation time only resolves findings last seen before that observation.
    Reopening is applied during persistence; this step records why it happened.
    """
    observed = set(
        session.exec(
            select(FindingOccurrence.finding_id)
            .where(col(FindingOccurrence.analysis_run_id) == run_id)
            .distinct()
        ).all()
    )
    reopened = tuple(
        sorted(
            (
                finding
                for finding in _findings_by_id(session, observed & set(previously_resolved))
                if FindingStatus(finding.status) == FindingStatus.OPEN
            ),
            key=lambda item: str(item.id),
        )
    )
    for finding in reopened:
        record_lifecycle_event(
            session,
            finding=finding,
            from_status=FindingStatus.RESOLVED,
            to_status=FindingStatus.OPEN,
            source=FindingLifecycleSource.IMPORT_REOBSERVED,
            reason=f"Reported again by {run_label}.",
            analysis_run_id=run_id,
            actor=actor,
        )

    resolved: list[Finding] = []
    if resolve_missing and coverage:
        candidates = _unobserved_candidates(session, project_id, observed, coverage)
        if observed_at is not None:
            observation = _naive_utc(observed_at)
            candidates = [
                (finding, target)
                for finding, target in candidates
                if _naive_utc(finding.last_seen_at) < observation
            ]
        for finding, target in candidates:
            previous = FindingStatus(finding.status)
            set_current_status(session, finding, FindingStatus.RESOLVED)
            record_lifecycle_event(
                session,
                finding=finding,
                from_status=previous,
                to_status=FindingStatus.RESOLVED,
                source=FindingLifecycleSource.IMPORT_NOT_OBSERVED,
                reason=f"Not reported by {run_label} for {target[0]} {target[1]}.",
                analysis_run_id=run_id,
                actor=actor,
            )
            resolved.append(finding)
    session.flush()
    return ImportReconciliation(
        resolved_ids=tuple(item.id for item in resolved),
        reopened_ids=tuple(item.id for item in reopened),
    )


def _unobserved_candidates(
    session: Session,
    project_id: uuid.UUID,
    observed: set[uuid.UUID],
    coverage: Collection[CoverageKey],
) -> list[tuple[Finding, TargetKey]]:
    coverage_set = set(coverage)
    # Distinct identity facts come from the covering expression index; the
    # immutable occurrence JSON is never loaded.
    columns = (
        col(FindingOccurrence.finding_id),
        col(FindingOccurrence.source),
        *occurrence_identity_expressions(col(FindingOccurrence.evidence_json)),
    )
    rows: list[Any] = list(
        session.exec(
            select(*columns)
            .select_from(FindingOccurrence)
            .join(Finding, col(Finding.id) == col(FindingOccurrence.finding_id))
            .where(
                col(Finding.project_id) == project_id,
                col(Finding.status).in_([status.value for status in ACTIONABLE_FINDING_STATUSES]),
            )
            .distinct()
        ).all()
    )
    matched: dict[uuid.UUID, TargetKey] = {}
    for finding_id, source, asset_id, target_kind, target_ref in rows:
        if finding_id in observed or finding_id in matched or not source:
            continue
        target = scope_target_key(
            _json_text(target_kind), _json_text(target_ref), _json_text(asset_id)
        )
        if target is not None and (source.strip().casefold(), target) in coverage_set:
            matched[finding_id] = target
    findings = _findings_by_id(session, set(matched))
    return sorted(
        ((finding, matched[finding.id]) for finding in findings),
        key=lambda item: str(item[0].id),
    )


def _findings_by_id(session: Session, ids: set[uuid.UUID]) -> list[Finding]:
    if not ids:
        return []
    return list(session.exec(select(Finding).where(col(Finding.id).in_(ids))).all())


def closed_status_findings_exist(session: Session, project_id: uuid.UUID) -> bool:
    """Return whether the current queue must move analyst-closed findings last."""
    return (
        session.exec(
            select(FindingCurrentProjection.finding_id)
            .where(
                col(FindingCurrentProjection.project_id) == project_id,
                col(FindingCurrentProjection.status).in_(
                    [FindingStatus.RESOLVED.value, FindingStatus.FALSE_POSITIVE.value]
                ),
            )
            .limit(1)
        ).first()
        is not None
    )


def _naive_utc(value: datetime) -> datetime:
    """Compare stored naive UTC timestamps with aware ones safely."""
    if value.tzinfo is None:
        return value
    return value.astimezone(UTC).replace(tzinfo=None)


def _normalized_value(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = normalize_asset_identity_value(value)
    return normalized or None


def _json_text(value: object) -> str | None:
    """Decode a JSON-extracted scalar rendered as text on SQLite and PostgreSQL."""
    if value is None:
        return None
    text = str(value)
    try:
        decoded = json.loads(text)
    except ValueError:
        return text
    return decoded if isinstance(decoded, str) else None

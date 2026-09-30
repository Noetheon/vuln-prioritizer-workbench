"""Absolute risk KPIs of a project's open work (issue #674)."""

from __future__ import annotations

import uuid
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import case, func
from sqlmodel import Session, col, select

from app.decision_core.readmodels import DecisionFindingView
from app.decision_core.sla_due import as_utc, sla_due, sla_target_hours
from app.models import (
    AnalysisRun,
    AnalysisRunRiskSnapshot,
    Finding,
    FindingCurrentProjection,
    FindingLifecycleEvent,
    ProjectRiskKpisPublic,
)
from app.models.base import get_datetime_utc
from app.models.enums import FindingSlaState, FindingStatus

ACTIONABLE_STATUSES = frozenset(
    {
        FindingStatus.OPEN.value,
        FindingStatus.IN_REVIEW.value,
        FindingStatus.REMEDIATING.value,
    }
)
# Closures that count as remediation for MTTR and SLA compliance.
REMEDIATED_STATUSES = frozenset({FindingStatus.RESOLVED.value, FindingStatus.FIXED.value})
CLOSURE_WINDOW_DAYS = 90
RUN_KPI_METRIC = "open-risk-kpis.v1"


def is_open_work(view: DecisionFindingView) -> bool:
    """Open work that carries risk: not accepted, not suppressed by VEX."""
    return (
        str(view.status) in ACTIONABLE_STATUSES
        and not bool(view.suppressed_by_vex)
        and not bool(view.waived)
    )


def build_project_risk_kpis(
    views: Sequence[DecisionFindingView],
    *,
    closed_at: Mapping[uuid.UUID, datetime],
    now: datetime,
    closure_window_days: int = CLOSURE_WINDOW_DAYS,
) -> ProjectRiskKpisPublic:
    """
    Count open work and closure performance from current decisions.

    ``closed_at`` maps findings to when they were last resolved or fixed.
    """
    open_views = [view for view in views if is_open_work(view)]
    open_scores = [_score(view) for view in open_views]
    overdue = due_soon = 0
    for view in open_views:
        due = sla_due(
            first_seen_at=view.finding.first_seen_at,
            sla=_sla(view),
            status=view.status,
            now=now,
        )
        if due is None:
            continue
        if due.state == FindingSlaState.OVERDUE:
            overdue += 1
        elif due.state == FindingSlaState.DUE_SOON:
            due_soon += 1
    accepted = [
        view
        for view in views
        if (str(view.status) == FindingStatus.ACCEPTED.value or bool(view.waived))
        and not bool(view.suppressed_by_vex)
    ]

    window_start = as_utc(now) - timedelta(days=closure_window_days)
    durations: list[float] = []
    with_sla = within_sla = 0
    for view in views:
        if str(view.status) not in REMEDIATED_STATUSES:
            continue
        closed = closed_at.get(view.finding.id)
        if closed is None or as_utc(closed) < window_start:
            continue
        opened = as_utc(view.finding.first_seen_at)
        durations.append(max((as_utc(closed) - opened).total_seconds(), 0.0) / 86400)
        hours = sla_target_hours(_sla(view))
        if hours is not None:
            with_sla += 1
            if as_utc(closed) <= opened + timedelta(hours=hours):
                within_sla += 1

    by_priority: dict[str, int] = {}
    for view in open_views:
        key = _priority(view)
        by_priority[key] = by_priority.get(key, 0) + 1
    return ProjectRiskKpisPublic(
        open_findings=len(open_views),
        open_by_priority=by_priority,
        open_critical=sum(_priority(view) == "critical" for view in open_views),
        open_high=sum(_priority(view) == "high" for view in open_views),
        open_kev=sum(bool(view.in_kev) for view in open_views),
        overdue=overdue,
        due_soon=due_soon,
        open_risk=_round(sum(open_scores)),
        mean_open_score=_round(sum(open_scores) / len(open_scores)) if open_scores else 0.0,
        accepted_findings=len(accepted),
        accepted_risk=_round(sum(_score(view) for view in accepted)),
        closure_window_days=closure_window_days,
        closed_findings=len(durations),
        mttr_days=_round(sum(durations) / len(durations)) if durations else None,
        closed_with_sla=with_sla,
        closed_within_sla=within_sla,
        sla_compliance_rate=round(within_sla / with_sla, 4) if with_sla else None,
    )


def latest_closure_times(session: Session, project_id: uuid.UUID) -> dict[uuid.UUID, datetime]:
    """Return when each finding was last resolved or fixed."""
    rows = session.exec(
        select(
            FindingLifecycleEvent.finding_id,
            func.max(FindingLifecycleEvent.created_at),
        )
        .where(
            FindingLifecycleEvent.project_id == project_id,
            col(FindingLifecycleEvent.to_status).in_(sorted(REMEDIATED_STATUSES)),
        )
        .group_by(col(FindingLifecycleEvent.finding_id))
    ).all()
    return {finding_id: closed for finding_id, closed in rows if closed is not None}


def project_risk_snapshot(session: Session, project_id: uuid.UUID) -> dict[str, Any]:
    """Absolute open-risk figures from materialized current columns, stored per run."""
    status = func.coalesce(FindingCurrentProjection.status, Finding.status)
    open_work = (
        Finding.project_id == project_id,
        status.in_(sorted(ACTIONABLE_STATUSES)),
        func.coalesce(FindingCurrentProjection.suppressed_by_vex, False).is_(False),
        func.coalesce(FindingCurrentProjection.waived, False).is_(False),
    )
    priority = func.lower(func.coalesce(FindingCurrentProjection.priority, "medium"))
    in_kev = func.coalesce(FindingCurrentProjection.in_kev, False).is_(True)
    row = session.exec(
        select(
            func.count(col(Finding.id)),
            func.coalesce(func.sum(func.coalesce(FindingCurrentProjection.risk_score, 0.0)), 0.0),
            func.coalesce(func.sum(case((priority == "critical", 1), else_=0)), 0),
            func.coalesce(func.sum(case((in_kev, 1), else_=0)), 0),
        )
        .select_from(Finding)
        .outerjoin(
            FindingCurrentProjection,
            col(FindingCurrentProjection.finding_id) == col(Finding.id),
        )
        .where(*open_work)
    ).one()
    count, risk, critical, kev = row
    return {
        "metric": RUN_KPI_METRIC,
        "open_findings": int(count or 0),
        "open_risk": _round(float(risk or 0.0)),
        "open_critical": int(critical or 0),
        "open_kev": int(kev or 0),
    }


def record_run_risk_snapshot(session: Session, run: AnalysisRun) -> None:
    """Store the project's open-risk figures as of this run's completion."""
    snapshot = project_risk_snapshot(session, run.project_id)
    existing = session.get(AnalysisRunRiskSnapshot, run.id)
    if existing is None:
        session.add(
            AnalysisRunRiskSnapshot(
                analysis_run_id=run.id,
                project_id=run.project_id,
                snapshot_json=snapshot,
            )
        )
    else:
        existing.snapshot_json = snapshot
        existing.created_at = get_datetime_utc()
        session.add(existing)
    session.flush()


def run_risk_snapshots(
    session: Session, run_ids: Sequence[uuid.UUID]
) -> dict[uuid.UUID, dict[str, Any]]:
    """Return the recorded open-risk figures of these runs; older runs have none."""
    if not run_ids:
        return {}
    rows = session.exec(
        select(AnalysisRunRiskSnapshot).where(
            col(AnalysisRunRiskSnapshot.analysis_run_id).in_(list(run_ids))
        )
    ).all()
    return {row.analysis_run_id: dict(row.snapshot_json) for row in rows}


def _sla(view: DecisionFindingView) -> dict[str, Any] | None:
    sla = view.read_summary.get("sla")
    return sla if isinstance(sla, dict) else None


def _priority(view: DecisionFindingView) -> str:
    return str(view.priority_label or view.priority).lower()


def _score(view: DecisionFindingView) -> float:
    return float(view.risk_score or 0.0)


def _round(value: float) -> float:
    return round(value, 1)

"""SQL-backed finding governance rollup query helpers."""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import case, or_
from sqlmodel import Session, col, func, select

from app.models import Asset, Finding, FindingPriority, FindingStatus, GovernanceRollupPublic
from app.repositories.finding_summary_query import OPEN_WORK_STATUSES

PRIORITY_LABELS = ("Critical", "High", "Medium", "Low")
STATUS_LABELS = tuple(status.value for status in FindingStatus)
UNKNOWN_LABEL = "Unassigned"


def project_governance_rollups(
    session: Session,
    project_id: uuid.UUID,
    *,
    dimension: str,
    limit: int,
) -> list[GovernanceRollupPublic]:
    """Return SQL-backed governance rollups for one project dimension."""
    label_expr = _governance_label_expression(dimension)
    waiver_status = Finding.explanation_json["waiver_status"].as_string()
    status = col(Finding.status)
    priority = col(Finding.priority)
    waived = col(Finding.waived)
    in_kev = col(Finding.in_kev)
    attack_mapped = col(Finding.attack_mapped)
    suppressed_by_vex = col(Finding.suppressed_by_vex)
    under_investigation = col(Finding.under_investigation)
    risk_score = col(Finding.risk_score)
    columns: list[Any] = [
        label_expr,
        func.count(),
        func.sum(_case_int(status.in_(OPEN_WORK_STATUSES))),
        func.sum(
            _case_int(
                or_(
                    status == FindingStatus.ACCEPTED,
                    waived.is_(True),
                )
            )
        ),
        func.sum(_case_int(status == FindingStatus.FIXED)),
        func.sum(_case_int(status == FindingStatus.SUPPRESSED)),
        func.sum(_case_int(priority == FindingPriority.CRITICAL)),
        func.sum(_case_int(priority == FindingPriority.HIGH)),
        func.sum(_case_int(in_kev.is_(True))),
        func.sum(_case_int(attack_mapped.is_(True))),
        func.sum(_case_int(suppressed_by_vex.is_(True))),
        func.sum(_case_int(under_investigation.is_(True))),
        func.sum(_case_int(waived.is_(True))),
        func.sum(_case_int(waiver_status == "expired")),
        func.sum(_case_int(waiver_status == "review_due")),
        func.coalesce(func.sum(risk_score), 0.0),
        func.max(risk_score),
        *[
            func.sum(_case_int(priority == finding_priority))
            for finding_priority in (
                FindingPriority.CRITICAL,
                FindingPriority.HIGH,
                FindingPriority.MEDIUM,
                FindingPriority.LOW,
            )
        ],
        *[func.sum(_case_int(status == finding_status)) for finding_status in FindingStatus],
    ]
    statement = (
        select(*columns)
        .select_from(Finding)
        .outerjoin(Asset, col(Finding.asset_id) == col(Asset.id))
        .where(Finding.project_id == project_id)
        .group_by(label_expr)
    )
    rollups = [
        _governance_rollup_from_row(
            row,
            dimension=dimension,
            top_cves=top_cves_for_governance_label(
                session,
                project_id,
                dimension=dimension,
                label=str(row[0]),
            ),
        )
        for row in session.exec(statement).all()
    ]
    rollups.sort(
        key=lambda item: (
            -item.risk_score_total,
            -item.critical_count,
            -item.high_count,
            -item.finding_count,
            item.label.casefold(),
        )
    )
    return rollups[:limit]


def top_cves_for_governance_label(
    session: Session,
    project_id: uuid.UUID,
    *,
    dimension: str,
    label: str,
) -> list[str]:
    """Return top CVE ids for one governance rollup label."""
    label_expr = _governance_label_expression(dimension)
    statement = (
        select(Finding.cve_id)
        .select_from(Finding)
        .outerjoin(Asset, col(Finding.asset_id) == col(Asset.id))
        .where(Finding.project_id == project_id, label_expr == label)
        .order_by(col(Finding.operational_rank), col(Finding.priority_rank), Finding.cve_id)
        .limit(5)
    )
    return list(session.exec(statement).all())


def _case_int(condition: Any) -> Any:
    return case((condition, 1), else_=0)


def _governance_label_expression(dimension: str) -> Any:
    if dimension == "owner":
        return func.coalesce(func.nullif(Asset.owner, ""), UNKNOWN_LABEL)
    if dimension == "service":
        return func.coalesce(func.nullif(Asset.business_service, ""), UNKNOWN_LABEL)
    if dimension == "asset":
        return func.coalesce(
            func.nullif(Asset.asset_key, ""),
            func.nullif(Asset.name, ""),
            UNKNOWN_LABEL,
        )
    if dimension == "environment":
        return func.coalesce(func.nullif(Asset.environment, ""), "unknown")
    raise ValueError(f"Unknown governance dimension: {dimension}")


def _governance_rollup_from_row(
    row: Any,
    *,
    dimension: str,
    top_cves: list[str],
) -> GovernanceRollupPublic:
    priority_start = 17
    status_start = priority_start + len(PRIORITY_LABELS)
    priority_counts = {
        label: _row_int(row, priority_start + index) for index, label in enumerate(PRIORITY_LABELS)
    }
    status_counts = {
        status: _row_int(row, status_start + index) for index, status in enumerate(STATUS_LABELS)
    }
    return GovernanceRollupPublic(
        dimension=dimension,
        label=str(row[0]),
        finding_count=_row_int(row, 1),
        open_count=_row_int(row, 2),
        accepted_count=_row_int(row, 3),
        fixed_count=_row_int(row, 4),
        suppressed_count=_row_int(row, 5),
        critical_count=_row_int(row, 6),
        high_count=_row_int(row, 7),
        kev_count=_row_int(row, 8),
        attack_mapped_count=_row_int(row, 9),
        suppressed_by_vex_count=_row_int(row, 10),
        under_investigation_count=_row_int(row, 11),
        waived_count=_row_int(row, 12),
        expired_waiver_count=_row_int(row, 13),
        review_due_waiver_count=_row_int(row, 14),
        risk_score_total=round(float(row[15] or 0.0), 3),
        risk_score_max=round(float(row[16]), 3) if row[16] is not None else None,
        highest_priority=_highest_priority(priority_counts),
        priority_counts=priority_counts,
        status_counts=status_counts,
        top_cves=top_cves,
    )


def _row_int(row: Any, index: int) -> int:
    return int(row[index] or 0)


def _highest_priority(priority_counts: dict[str, int]) -> str | None:
    for priority in PRIORITY_LABELS:
        if priority_counts.get(priority, 0):
            return priority
    return None

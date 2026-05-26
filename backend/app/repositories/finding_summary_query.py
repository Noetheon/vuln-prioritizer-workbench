"""SQL-backed finding summary query helpers."""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import case, or_
from sqlmodel import Session, col, func, select

from app.models import Asset, AssetExposure, Finding, FindingPriority, FindingStatus

OPEN_WORK_STATUSES = (
    FindingStatus.OPEN,
    FindingStatus.IN_REVIEW,
    FindingStatus.REMEDIATING,
)


def count_project_findings(session: Session, project_id: uuid.UUID) -> int:
    """Return the project finding count without materializing finding rows."""
    statement = select(func.count()).select_from(Finding).where(Finding.project_id == project_id)
    return int(session.exec(statement).one())


def count_project_findings_where(
    session: Session,
    project_id: uuid.UUID,
    *criteria: Any,
) -> int:
    """Count project findings matching additional SQL criteria."""
    statement = (
        select(func.count()).select_from(Finding).where(Finding.project_id == project_id, *criteria)
    )
    return int(session.exec(statement).one())


def project_finding_summary_counts(session: Session, project_id: uuid.UUID) -> dict[str, Any]:
    """Return dashboard summary counts with bounded aggregate queries."""
    priority_counts = {
        str(priority): int(count)
        for priority, count in session.exec(
            select(Finding.priority, func.count())
            .where(Finding.project_id == project_id)
            .group_by(Finding.priority)
        ).all()
    }
    status_counts = {
        str(status): int(count)
        for status, count in session.exec(
            select(Finding.status, func.count())
            .where(Finding.project_id == project_id)
            .group_by(Finding.status)
        ).all()
    }
    return {
        "finding_count": count_project_findings(session, project_id),
        "open_finding_count": count_project_findings_where(
            session,
            project_id,
            col(Finding.status).in_(OPEN_WORK_STATUSES),
        ),
        "counts_by_priority": priority_counts,
        "counts_by_status": status_counts,
        "kev_hits": count_project_findings_where(
            session,
            project_id,
            col(Finding.in_kev).is_(True),
        ),
        "epss_hits": count_project_findings_where(
            session,
            project_id,
            col(Finding.epss).is_not(None),
        ),
        "cvss_known_count": count_project_findings_where(
            session,
            project_id,
            col(Finding.cvss_base_score).is_not(None),
        ),
    }


def project_dashboard_signal_counts(session: Session, project_id: uuid.UUID) -> dict[str, Any]:
    """Return dashboard signal counts without materializing project findings."""
    epss = col(Finding.epss)
    priority = col(Finding.priority)
    exposure = col(Asset.exposure)
    columns: list[Any] = [
        func.sum(_case_int(epss >= 0.7)),
        func.sum(_case_int((epss >= 0) & (epss <= 0.25))),
        func.sum(_case_int((epss >= 0.25) & (epss <= 0.5))),
        func.sum(_case_int((epss >= 0.5) & (epss <= 0.7))),
        func.sum(
            _case_int(
                (priority == FindingPriority.CRITICAL) & (exposure == AssetExposure.INTERNET_FACING)
            )
        ),
    ]
    epss_bucket_rows = session.exec(
        select(*columns)
        .select_from(Finding)
        .outerjoin(Asset, col(Finding.asset_id) == col(Asset.id))
        .where(Finding.project_id == project_id)
    ).one()
    high_epss, low, medium, high, internet_facing_criticals = epss_bucket_rows
    return {
        "high_epss": int(high_epss or 0),
        "internet_facing_criticals": int(internet_facing_criticals or 0),
        "epss_buckets": {
            "low": int(low or 0),
            "medium": int(medium or 0),
            "high": int(high or 0),
            "critical": int(high_epss or 0),
        },
    }


def project_waiver_finding_counts(session: Session, project_id: uuid.UUID) -> dict[str, int]:
    """Return accepted-risk finding counts for governance debt."""
    waiver_status = Finding.explanation_json["waiver_status"].as_string()
    status = col(Finding.status)
    waived = col(Finding.waived)
    columns: list[Any] = [
        func.sum(
            _case_int(
                or_(
                    status == FindingStatus.ACCEPTED,
                    waived.is_(True),
                )
            )
        ),
        func.sum(_case_int(waiver_status == "expired")),
        func.sum(_case_int(waiver_status == "review_due")),
    ]
    accepted, expired, review_due = session.exec(
        select(*columns).select_from(Finding).where(Finding.project_id == project_id)
    ).one()
    return {
        "accepted_finding_count": int(accepted or 0),
        "expired_finding_count": int(expired or 0),
        "review_due_finding_count": int(review_due or 0),
    }


def _case_int(condition: Any) -> Any:
    return case((condition, 1), else_=0)

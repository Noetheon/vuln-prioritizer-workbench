"""Evidence-backed finding query helpers."""

from __future__ import annotations

import uuid
from typing import Any, cast

from sqlalchemy.orm import QueryableAttribute, selectinload
from sqlmodel import Session, col, func, select

from app.decision_core.readmodels import DecisionFindingView, project_finding_decision_views
from app.models import (
    Asset,
    AttackSummaryContextRow,
    AttackSummaryFindingRow,
    Component,
    Finding,
    FindingPriority,
    FindingStatus,
)
from app.repositories.finding_attack_query import (
    list_project_attack_summary_contexts as _list_project_attack_summary_contexts,
)
from app.repositories.finding_page_query import FindingPageQuery
from app.repositories.findings import FindingRepository


def list_project_attack_summary_inputs(
    session: Session,
    project_id: uuid.UUID,
) -> tuple[list[AttackSummaryFindingRow], list[AttackSummaryContextRow]]:
    """Return evidence-backed rows needed for the ATT&CK dashboard summary."""
    findings = FindingRepository(session).list_project_findings(project_id)
    finding_rows = [
        AttackSummaryFindingRow(id=view.finding.id, risk_score=view.risk_score)
        for view in project_finding_decision_views(session, findings)
    ]
    context_rows = _list_project_attack_summary_contexts(session, project_id)
    return finding_rows, context_rows


def list_project_findings_page(
    session: Session,
    project_id: uuid.UUID,
    *,
    limit: int = 100,
    offset: int = 0,
    sort: str = "operational",
    direction: str = "asc",
    priority: FindingPriority | str | None = None,
    status: FindingStatus | str | None = None,
    kev: bool | None = None,
    owner: str | None = None,
    service: str | None = None,
    owner_service: str | None = None,
    query: str | None = None,
    asset_id: uuid.UUID | None = None,
    exposure: str | None = None,
    epss_min: float | None = None,
    epss_max: float | None = None,
    cvss_min: float | None = None,
    cvss_max: float | None = None,
) -> tuple[list[Finding], int]:
    """Return a filtered, sorted, paginated project finding page."""
    return list_project_findings_query(
        session,
        FindingPageQuery(
            project_id=project_id,
            limit=limit,
            offset=offset,
            sort=sort,
            direction=direction,
            priority=priority,
            status=status,
            kev=kev,
            owner=owner,
            service=service,
            owner_service=owner_service,
            query=query,
            asset_id=asset_id,
            exposure=exposure,
            epss_min=epss_min,
            epss_max=epss_max,
            cvss_min=cvss_min,
            cvss_max=cvss_max,
        ),
    )


def list_project_findings_query(
    session: Session,
    query: FindingPageQuery,
) -> tuple[list[Finding], int]:
    """Return a filtered, sorted, paginated project finding page."""
    asset_relationship = cast(QueryableAttribute[Any], Finding.asset)
    component_relationship = cast(QueryableAttribute[Any], Finding.component)
    database_page = _database_cve_page_if_unfiltered(
        session,
        query,
        asset_relationship=asset_relationship,
        component_relationship=component_relationship,
    )
    if database_page is not None:
        return database_page

    statement = (
        select(Finding)
        .outerjoin(Asset, col(Finding.asset_id) == col(Asset.id))
        .outerjoin(Component, col(Finding.component_id) == col(Component.id))
        .options(
            selectinload(asset_relationship),
            selectinload(component_relationship),
        )
        .where(Finding.project_id == query.project_id)
        .order_by(Finding.cve_id, col(Finding.id))
    )
    findings = list(session.exec(statement).all())
    views = [
        view
        for view in project_finding_decision_views(session, findings)
        if _matches_finding_page_query(view, query)
    ]
    views.sort(key=lambda view: _finding_page_sort_key(view, query))
    if query.direction == "desc":
        views.reverse()
    count = len(views)
    page = views[query.offset : query.offset + query.limit]
    return [view.finding for view in page], count


def _database_cve_page_if_unfiltered(
    session: Session,
    query: FindingPageQuery,
    *,
    asset_relationship: QueryableAttribute[Any],
    component_relationship: QueryableAttribute[Any],
) -> tuple[list[Finding], int] | None:
    if not _can_use_database_cve_page(query):
        return None
    count = int(
        session.exec(
            select(func.count()).select_from(Finding).where(Finding.project_id == query.project_id)
        ).one()
    )
    order_by: tuple[Any, ...] = (col(Finding.cve_id), col(Finding.id))
    if query.direction == "desc":
        order_by = tuple(column.desc() for column in order_by)
    statement = (
        select(Finding)
        .options(
            selectinload(asset_relationship),
            selectinload(component_relationship),
        )
        .where(Finding.project_id == query.project_id)
        .order_by(*order_by)
        .offset(query.offset)
        .limit(query.limit)
    )
    return list(session.exec(statement).all()), count


def _can_use_database_cve_page(query: FindingPageQuery) -> bool:
    return (
        query.sort == "cve"
        and query.priority is None
        and query.status is None
        and query.kev is None
        and query.owner is None
        and query.service is None
        and query.owner_service is None
        and query.query is None
        and query.asset_id is None
        and query.exposure is None
        and query.epss_min is None
        and query.epss_max is None
        and query.cvss_min is None
        and query.cvss_max is None
    )


def _matches_finding_page_query(
    view: DecisionFindingView,
    query: FindingPageQuery,
) -> bool:
    finding = view.finding
    asset = finding.asset
    component = finding.component
    if query.priority is not None and view.priority != FindingPriority(query.priority):
        return False
    if query.status is not None and view.status != FindingStatus(query.status):
        return False
    if query.kev is not None and view.in_kev != query.kev:
        return False
    if query.asset_id is not None and finding.asset_id != query.asset_id:
        return False
    if query.exposure is not None and (asset is None or asset.exposure != query.exposure):
        return False
    if query.epss_min is not None and (view.epss is None or view.epss < query.epss_min):
        return False
    if query.epss_max is not None and (view.epss is None or view.epss > query.epss_max):
        return False
    if query.cvss_min is not None and (
        view.cvss_base_score is None or view.cvss_base_score < query.cvss_min
    ):
        return False
    if query.cvss_max is not None and (
        view.cvss_base_score is None or view.cvss_base_score > query.cvss_max
    ):
        return False
    if not _contains(asset.owner if asset else None, query.owner):
        return False
    if not _contains(asset.business_service if asset else None, query.service):
        return False
    if query.owner_service and not (
        _contains(asset.owner if asset else None, query.owner_service)
        or _contains(asset.business_service if asset else None, query.owner_service)
    ):
        return False
    if query.query and not any(
        _contains(value, query.query)
        for value in (
            view.cve_id,
            view.recommended_action,
            view.rationale,
            component.name if component else None,
            component.version if component else None,
            component.purl if component else None,
            component.ecosystem if component else None,
            asset.asset_key if asset else None,
            asset.name if asset else None,
            asset.target_ref if asset else None,
            asset.owner if asset else None,
            asset.business_service if asset else None,
        )
    ):
        return False
    return True


def _contains(value: object, needle: str | None) -> bool:
    if not needle or not needle.strip():
        return True
    return needle.strip().casefold() in str(value or "").casefold()


def _finding_page_sort_key(view: DecisionFindingView, query: FindingPageQuery) -> tuple[Any, ...]:
    finding = view.finding
    asset = finding.asset
    component = finding.component
    stable_tie = _finding_page_stable_tie_key(view)
    if query.sort == "operational":
        return (view.operational_rank or 999_999, view.priority_rank, *stable_tie)
    if query.sort == "priority":
        return (view.priority_rank, *stable_tie)
    if query.sort == "score":
        return (_none_last_number(view.risk_score), view.priority_rank, *stable_tie)
    if query.sort == "cve":
        return stable_tie
    if query.sort == "status":
        return (view.status.value, *stable_tie)
    if query.sort == "epss":
        return (_none_last_number(view.epss), view.priority_rank, *stable_tie)
    if query.sort == "cvss":
        return (_none_last_number(view.cvss_base_score), view.priority_rank, *stable_tie)
    if query.sort == "kev":
        return (1 if view.in_kev else 0, view.priority_rank, *stable_tie)
    if query.sort == "last_seen":
        return (finding.last_seen_at, view.priority_rank, *stable_tie)
    if query.sort == "component":
        return (
            str(component.name if component else ""),
            str(component.version if component else ""),
            str(asset.business_service if asset else ""),
            str(asset.asset_key if asset else ""),
            view.cve_id,
        )
    if query.sort == "owner":
        return (
            str(asset.owner if asset else ""),
            str(asset.business_service if asset else ""),
            str(asset.asset_key if asset else ""),
            view.cve_id,
        )
    raise ValueError(f"Unsupported findings sort field: {query.sort}.")


def _finding_page_stable_tie_key(view: DecisionFindingView) -> tuple[str, ...]:
    finding = view.finding
    asset = finding.asset
    component = finding.component
    return (
        str(view.cve_id or "").casefold(),
        str(component.name if component else "").casefold(),
        str(component.version if component else "").casefold(),
        str(asset.business_service if asset else "").casefold(),
        str(asset.owner if asset else "").casefold(),
        str(asset.asset_key if asset else "").casefold(),
        str(finding.id),
    )


def _none_last_number(value: float | int | None) -> tuple[int, float]:
    return (1, 0.0) if value is None else (0, float(value))

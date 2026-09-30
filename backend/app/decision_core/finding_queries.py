"""Evidence-backed finding query helpers."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, cast

from sqlalchemy import and_, case, false, or_
from sqlalchemy.orm import QueryableAttribute, selectinload
from sqlmodel import Session, col, func, select

from app.decision_core.readmodels import project_finding_decision_views
from app.decision_core.sla_due import first_seen_bounds
from app.models import (
    ACTIONABLE_FINDING_STATUSES,
    Asset,
    AttackSummaryContextRow,
    AttackSummaryFindingRow,
    Component,
    Finding,
    FindingCurrentProjection,
    FindingPriority,
    FindingSlaState,
    FindingsSummaryPublic,
    FindingStatus,
)
from app.models.base import get_datetime_utc
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
    data_gap: bool | None = None,
    sla_state: FindingSlaState | str | None = None,
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
            data_gap=data_gap,
            sla_state=sla_state,
        ),
    )


def list_project_findings_query(
    session: Session,
    query: FindingPageQuery,
) -> tuple[list[Finding], int]:
    """Return a filtered, sorted, paginated project finding page."""
    asset_relationship = cast(QueryableAttribute[Any], Finding.asset)
    component_relationship = cast(QueryableAttribute[Any], Finding.component)
    filters = _database_finding_filters(query)
    if query.sla_state is not None:
        filters.append(
            _sla_state_filter(
                FindingSlaState(query.sla_state),
                sla_hours=_project_sla_hours(session, query.project_id),
                now=get_datetime_utc(),
            )
        )
    count = int(
        session.exec(
            select(func.count())
            .select_from(Finding)
            .outerjoin(Asset, col(Finding.asset_id) == col(Asset.id))
            .outerjoin(Component, col(Finding.component_id) == col(Component.id))
            .outerjoin(
                FindingCurrentProjection,
                col(FindingCurrentProjection.finding_id) == col(Finding.id),
            )
            .where(*filters)
        ).one()
    )
    order_by = _database_finding_order(query)
    statement = (
        select(Finding)
        .outerjoin(Asset, col(Finding.asset_id) == col(Asset.id))
        .outerjoin(Component, col(Finding.component_id) == col(Component.id))
        .outerjoin(
            FindingCurrentProjection,
            col(FindingCurrentProjection.finding_id) == col(Finding.id),
        )
        .options(
            selectinload(asset_relationship),
            selectinload(component_relationship),
        )
        .where(*filters)
        .order_by(*order_by)
        .offset(query.offset)
        .limit(query.limit)
    )
    return list(session.exec(statement).all()), count


def project_findings_summary(
    session: Session,
    query: FindingPageQuery,
) -> FindingsSummaryPublic:
    """Count what a filtered finding list holds across all of its pages."""
    now = get_datetime_utc()
    sla_hours = _project_sla_hours(session, query.project_id)
    filters = _database_finding_filters(query)
    if query.sla_state is not None:
        filters.append(
            _sla_state_filter(FindingSlaState(query.sla_state), sla_hours=sla_hours, now=now)
        )
    priority = func.lower(func.coalesce(FindingCurrentProjection.priority, "medium"))
    in_kev = func.coalesce(FindingCurrentProjection.in_kev, False).is_(True)
    overdue = _sla_state_filter(FindingSlaState.OVERDUE, sla_hours=sla_hours, now=now)
    by_priority = session.exec(
        _summary_select(priority, func.count()).where(*filters).group_by(priority)
    ).all()
    kev, open_work, overdue_count = session.exec(
        _summary_select(
            _count_where(in_kev), _count_where(_actionable_status_filter()), _count_where(overdue)
        ).where(*filters)
    ).one()
    return FindingsSummaryPublic(
        by_priority={str(label): int(count) for label, count in by_priority if count},
        kev=int(kev or 0),
        open_work=int(open_work or 0),
        overdue=int(overdue_count or 0),
    )


def _count_where(condition: Any) -> Any:
    return func.coalesce(func.sum(case((condition, 1), else_=0)), 0)


def _summary_select(*columns: Any) -> Any:
    return (
        select(*columns)
        .select_from(Finding)
        .outerjoin(Asset, col(Finding.asset_id) == col(Asset.id))
        .outerjoin(Component, col(Finding.component_id) == col(Component.id))
        .outerjoin(
            FindingCurrentProjection,
            col(FindingCurrentProjection.finding_id) == col(Finding.id),
        )
    )


def _database_finding_filters(query: FindingPageQuery) -> list[Any]:
    filters: list[Any] = [Finding.project_id == query.project_id]
    if query.priority is not None:
        filters.append(
            func.coalesce(FindingCurrentProjection.priority, "medium")
            == FindingPriority(query.priority).value
        )
    if query.status is not None:
        filters.append(
            func.coalesce(FindingCurrentProjection.status, Finding.status)
            == FindingStatus(query.status).value
        )
    if query.open_work is not None:
        open_work = _actionable_status_filter()
        filters.append(open_work if query.open_work else ~open_work)
    if query.kev is not None:
        filters.append(func.coalesce(FindingCurrentProjection.in_kev, False) == query.kev)
    if query.asset_id is not None:
        filters.append(Finding.asset_id == query.asset_id)
    if query.exposure is not None:
        filters.append(Asset.exposure == str(query.exposure))
    if query.epss_min is not None:
        filters.append(col(FindingCurrentProjection.epss) >= query.epss_min)
    if query.epss_max is not None:
        filters.append(col(FindingCurrentProjection.epss) <= query.epss_max)
    if query.cvss_min is not None:
        filters.append(col(FindingCurrentProjection.cvss_base_score) >= query.cvss_min)
    if query.cvss_max is not None:
        filters.append(col(FindingCurrentProjection.cvss_base_score) <= query.cvss_max)
    if query.data_gap is not None:
        missing_provider_signal = or_(
            col(FindingCurrentProjection.cvss_base_score).is_(None),
            col(FindingCurrentProjection.epss).is_(None),
        )
        filters.append(missing_provider_signal if query.data_gap else ~missing_provider_signal)
    if query.owner and query.owner.strip():
        filters.append(_database_contains(Asset.owner, query.owner))
    if query.service and query.service.strip():
        filters.append(_database_contains(Asset.business_service, query.service))
    if query.owner_service and query.owner_service.strip():
        filters.append(
            or_(
                _database_contains(Asset.owner, query.owner_service),
                _database_contains(Asset.business_service, query.owner_service),
            )
        )
    if query.query and query.query.strip():
        component_name = _database_component_field(
            FindingCurrentProjection.component_name,
            Component.name,
        )
        component_version = _database_component_field(
            FindingCurrentProjection.component_version,
            Component.version,
        )
        component_purl = _database_component_field(
            FindingCurrentProjection.component_purl,
            Component.purl,
        )
        component_package_type = _database_component_field(
            FindingCurrentProjection.component_package_type,
            Component.package_type,
        )
        component_ecosystem = _database_component_field(
            FindingCurrentProjection.component_ecosystem,
            Component.ecosystem,
        )
        filters.append(
            or_(
                _database_contains(FindingCurrentProjection.cve_id, query.query),
                _database_contains(Finding.cve_id, query.query),
                _database_contains(FindingCurrentProjection.recommended_action, query.query),
                _database_contains(FindingCurrentProjection.rationale, query.query),
                _database_contains(component_name, query.query),
                _database_contains(component_version, query.query),
                _database_contains(component_purl, query.query),
                _database_contains(component_package_type, query.query),
                _database_contains(component_ecosystem, query.query),
                _database_contains(Asset.asset_key, query.query),
                _database_contains(Asset.name, query.query),
                _database_contains(Asset.target_ref, query.query),
                _database_contains(Asset.owner, query.query),
                _database_contains(Asset.business_service, query.query),
            )
        )
    return filters


def _sla_hours_expression() -> Any:
    """Recorded SLA window in hours, read from the materialized decision summary."""
    summary = col(FindingCurrentProjection.read_summary_json)
    return func.coalesce(
        summary[("sla", "target_hours")].as_integer(),
        summary[("sla", "target_days")].as_integer() * 24,
    )


def _actionable_status_filter() -> Any:
    return func.coalesce(FindingCurrentProjection.status, Finding.status).in_(
        [status.value for status in ACTIONABLE_FINDING_STATUSES]
    )


def _project_sla_hours(session: Session, project_id: uuid.UUID) -> list[int]:
    """Return the distinct SLA windows of a project's open work."""
    hours = _sla_hours_expression()
    values = session.exec(
        select(hours)
        .select_from(FindingCurrentProjection)
        .join(Finding, col(Finding.id) == col(FindingCurrentProjection.finding_id))
        .where(
            col(FindingCurrentProjection.project_id) == project_id,
            _actionable_status_filter(),
        )
        .distinct()
    ).all()
    return sorted({int(value) for value in values if isinstance(value, int) and value > 0})


def _sla_state_filter(
    state: FindingSlaState,
    *,
    sla_hours: list[int],
    now: datetime,
) -> Any:
    """Match open work whose first sighting puts it in ``state`` for its SLA window."""
    hours_expression = _sla_hours_expression()
    windows = []
    for hours in sla_hours:
        lower, upper = first_seen_bounds(state, hours=hours, now=now)
        conditions = [hours_expression == hours]
        if lower is not None:
            conditions.append(col(Finding.first_seen_at) > lower)
        if upper is not None:
            conditions.append(col(Finding.first_seen_at) <= upper)
        windows.append(and_(*conditions))
    if not windows:
        return false()
    return and_(_actionable_status_filter(), or_(*windows))


def _database_finding_order(query: FindingPageQuery) -> tuple[Any, ...]:
    priority_rank = func.coalesce(FindingCurrentProjection.priority_rank, 99)
    stable_tie = _database_stable_tie_order()
    if query.sort == "operational":
        operational_rank = func.coalesce(
            func.nullif(FindingCurrentProjection.operational_rank, 0),
            999_999,
        )
        return _database_direction((operational_rank, priority_rank, *stable_tie), query.direction)
    if query.sort == "priority":
        # Within one priority band, open work comes before closed or accepted
        # findings, and the highest score comes first, whatever the direction.
        return (
            *_database_direction((priority_rank,), query.direction),
            _database_open_work_first(),
            *_database_none_last_number_order(FindingCurrentProjection.risk_score, "desc"),
            *_database_direction(stable_tie, "asc"),
        )
    if query.sort == "score":
        return (
            *_database_none_last_number_order(
                FindingCurrentProjection.risk_score,
                query.direction,
            ),
            *_database_direction((priority_rank, *stable_tie), query.direction),
        )
    if query.sort == "cve":
        return _database_direction(stable_tie, query.direction)
    if query.sort == "status":
        return _database_direction(
            (func.coalesce(FindingCurrentProjection.status, Finding.status), *stable_tie),
            query.direction,
        )
    if query.sort == "epss":
        return (
            *_database_none_last_number_order(FindingCurrentProjection.epss, query.direction),
            *_database_direction((priority_rank, *stable_tie), query.direction),
        )
    if query.sort == "cvss":
        return (
            *_database_none_last_number_order(
                FindingCurrentProjection.cvss_base_score,
                query.direction,
            ),
            *_database_direction((priority_rank, *stable_tie), query.direction),
        )
    if query.sort == "kev":
        return _database_direction(
            (
                func.coalesce(FindingCurrentProjection.in_kev, False),
                priority_rank,
                *stable_tie,
            ),
            query.direction,
        )
    if query.sort == "last_seen":
        return _database_direction(
            (Finding.last_seen_at, priority_rank, *stable_tie),
            query.direction,
        )
    if query.sort == "component":
        component_name, component_version = _database_component_sort_fields()
        return _database_direction(
            (
                func.lower(func.coalesce(component_name, "")),
                func.lower(func.coalesce(component_version, "")),
                func.lower(func.coalesce(Asset.business_service, "")),
                func.lower(func.coalesce(Asset.asset_key, "")),
                func.lower(func.coalesce(FindingCurrentProjection.cve_id, Finding.cve_id)),
                Finding.id,
            ),
            query.direction,
        )
    if query.sort == "owner":
        return _database_direction(
            (
                func.lower(func.coalesce(Asset.owner, "")),
                func.lower(func.coalesce(Asset.business_service, "")),
                func.lower(func.coalesce(Asset.asset_key, "")),
                func.lower(func.coalesce(FindingCurrentProjection.cve_id, Finding.cve_id)),
                Finding.id,
            ),
            query.direction,
        )
    raise ValueError(f"Unsupported findings sort field: {query.sort}.")


def _database_stable_tie_order() -> tuple[Any, ...]:
    component_name, component_version = _database_component_sort_fields()
    return (
        func.lower(func.coalesce(FindingCurrentProjection.cve_id, Finding.cve_id, "")),
        func.lower(func.coalesce(component_name, "")),
        func.lower(func.coalesce(component_version, "")),
        func.lower(func.coalesce(Asset.business_service, "")),
        func.lower(func.coalesce(Asset.owner, "")),
        func.lower(func.coalesce(Asset.asset_key, "")),
        Finding.id,
    )


def _database_component_sort_fields() -> tuple[Any, Any]:
    return (
        _database_component_field(FindingCurrentProjection.component_name, Component.name),
        _database_component_field(FindingCurrentProjection.component_version, Component.version),
    )


def _database_component_field(projection_column: Any, legacy_column: Any) -> Any:
    """Use evidence-bound fields whenever a current projection row exists."""
    return case(
        (
            col(FindingCurrentProjection.finding_id).is_not(None),
            col(projection_column),
        ),
        else_=col(legacy_column),
    )


def _database_open_work_first() -> Any:
    status = func.coalesce(FindingCurrentProjection.status, Finding.status)
    open_statuses = [value.value for value in ACTIONABLE_FINDING_STATUSES]
    return case((status.in_(open_statuses), 0), else_=1).asc()


def _database_direction(expressions: tuple[Any, ...], direction: str) -> tuple[Any, ...]:
    if direction == "desc":
        return tuple(expression.desc() for expression in expressions)
    return tuple(expression.asc() for expression in expressions)


def _database_none_last_number_order(column: Any, direction: str) -> tuple[Any, Any]:
    value = col(column)
    null_rank = case((value.is_(None), 1), else_=0).asc()
    ordered_value = value.desc() if direction == "desc" else value.asc()
    return (null_rank, ordered_value)


def _database_contains(column: Any, needle: str) -> Any:
    escaped = needle.strip().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return column.ilike(f"%{escaped}%", escape="\\")

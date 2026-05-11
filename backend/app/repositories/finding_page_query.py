"""Finding page query helpers for Workbench repository calls."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any

from sqlalchemy import or_
from sqlmodel import col

from app.models import (
    Asset,
    Component,
    Finding,
    FindingPriority,
    FindingStatus,
)


@dataclass(frozen=True, slots=True)
class FindingPageQuery:
    """Internal query object for filtered Workbench finding pages."""

    project_id: uuid.UUID
    limit: int = 100
    offset: int = 0
    sort: str = "operational"
    direction: str = "asc"
    priority: FindingPriority | str | None = None
    status: FindingStatus | str | None = None
    kev: bool | None = None
    owner: str | None = None
    service: str | None = None
    owner_service: str | None = None
    asset_id: uuid.UUID | None = None
    exposure: str | None = None
    epss_min: float | None = None
    epss_max: float | None = None
    cvss_min: float | None = None
    cvss_max: float | None = None


def finding_page_filters(query: FindingPageQuery) -> list[Any]:
    return [
        Finding.project_id == query.project_id,
        *_finding_state_filters(query),
        *_finding_asset_text_filters(query),
        *_finding_asset_filters(query),
        *_finding_score_filters(query),
    ]


def _finding_state_filters(query: FindingPageQuery) -> list[Any]:
    filters: list[Any] = []
    if query.priority is not None:
        filters.append(Finding.priority == FindingPriority(query.priority))
    if query.status is not None:
        filters.append(Finding.status == FindingStatus(query.status))
    if query.kev is not None:
        filters.append(Finding.in_kev == query.kev)
    return filters


def _finding_asset_text_filters(query: FindingPageQuery) -> list[Any]:
    filters: list[Any] = []
    if query.owner and query.owner.strip():
        filters.append(col(Asset.owner).ilike(f"%{query.owner.strip()}%"))
    if query.service and query.service.strip():
        filters.append(col(Asset.business_service).ilike(f"%{query.service.strip()}%"))
    if query.owner_service and query.owner_service.strip():
        pattern = f"%{query.owner_service.strip()}%"
        filters.append(
            or_(
                col(Asset.owner).ilike(pattern),
                col(Asset.business_service).ilike(pattern),
            )
        )
    return filters


def _finding_asset_filters(query: FindingPageQuery) -> list[Any]:
    filters: list[Any] = []
    if query.asset_id is not None:
        filters.append(Finding.asset_id == query.asset_id)
    if query.exposure is not None:
        filters.append(Asset.exposure == query.exposure)
    return filters


def _finding_score_filters(query: FindingPageQuery) -> list[Any]:
    filters: list[Any] = []
    if query.epss_min is not None:
        filters.append(col(Finding.epss) >= query.epss_min)
    if query.epss_max is not None:
        filters.append(col(Finding.epss) <= query.epss_max)
    if query.cvss_min is not None:
        filters.append(col(Finding.cvss_base_score) >= query.cvss_min)
    if query.cvss_max is not None:
        filters.append(col(Finding.cvss_base_score) <= query.cvss_max)
    return filters


def finding_page_order_by(query: FindingPageQuery) -> list[Any]:
    order_fields = _finding_page_order_fields()
    if query.sort not in order_fields:
        raise ValueError(f"Unsupported findings sort field: {query.sort}.")
    if query.direction not in {"asc", "desc"}:
        raise ValueError(f"Unsupported findings sort direction: {query.direction}.")

    order_by = [
        field.desc() if query.direction == "desc" else field.asc()
        for field in order_fields[query.sort]
    ]
    order_by.append(col(Finding.cve_id).asc())
    order_by.append(col(Finding.id).asc())
    return order_by


def _finding_page_order_fields() -> dict[str, tuple[Any, ...]]:
    return {
        "operational": (col(Finding.operational_rank), col(Finding.priority_rank)),
        "priority": (col(Finding.priority_rank), col(Finding.cve_id)),
        "score": (col(Finding.risk_score), col(Finding.priority_rank)),
        "cve": (col(Finding.cve_id),),
        "status": (col(Finding.status), col(Finding.cve_id)),
        "epss": (col(Finding.epss), col(Finding.priority_rank)),
        "cvss": (col(Finding.cvss_base_score), col(Finding.priority_rank)),
        "kev": (col(Finding.in_kev), col(Finding.priority_rank)),
        "last_seen": (col(Finding.last_seen_at), col(Finding.priority_rank)),
        "component": (
            col(Component.name),
            col(Component.version),
            col(Asset.business_service),
            col(Asset.asset_key),
        ),
        "owner": (col(Asset.owner), col(Asset.business_service), col(Asset.asset_key)),
    }

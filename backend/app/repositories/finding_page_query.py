"""Finding page query helpers for Workbench repository calls."""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from app.models import (
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
    query: str | None = None
    asset_id: uuid.UUID | None = None
    exposure: str | None = None
    epss_min: float | None = None
    epss_max: float | None = None
    cvss_min: float | None = None
    cvss_max: float | None = None

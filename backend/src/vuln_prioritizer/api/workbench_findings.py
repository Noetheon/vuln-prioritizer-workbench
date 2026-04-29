"""Finding filtering and sorting helpers for Workbench routes."""

from __future__ import annotations

from typing import Any

from fastapi import HTTPException


def _filter_findings(
    findings: list[Any],
    *,
    priority: str | None,
    status: str | None,
    q: str | None,
    kev: bool | None,
    owner: str | None,
    service: str | None,
    min_epss: float | None,
    min_cvss: float | None,
) -> list[Any]:
    query = q.lower().strip() if q else None
    owner_query = owner.lower().strip() if owner else None
    service_query = service.lower().strip() if service else None
    return [
        finding
        for finding in findings
        if (priority is None or finding.priority == priority)
        and (status is None or finding.status == status)
        and (kev is None or finding.in_kev is kev)
        and (min_epss is None or (finding.epss is not None and finding.epss >= min_epss))
        and (
            min_cvss is None
            or (finding.cvss_base_score is not None and finding.cvss_base_score >= min_cvss)
        )
        and _finding_matches_query(finding, query)
        and _finding_matches_owner(finding, owner_query)
        and _finding_matches_service(finding, service_query)
    ]


def _sort_findings(findings: list[Any], *, sort: str) -> list[Any]:
    if sort == "operational":
        return sorted(findings, key=lambda item: (item.operational_rank, item.cve_id))
    if sort == "priority":
        return sorted(findings, key=lambda item: (item.priority_rank, item.operational_rank))
    if sort == "epss":
        return sorted(findings, key=lambda item: (-(item.epss or -1), item.operational_rank))
    if sort == "cvss":
        return sorted(
            findings,
            key=lambda item: (-(item.cvss_base_score or -1), item.operational_rank),
        )
    if sort == "cve":
        return sorted(findings, key=lambda item: item.cve_id)
    if sort == "last_seen":
        return sorted(findings, key=lambda item: item.last_seen_at, reverse=True)
    raise HTTPException(status_code=422, detail=f"Unsupported findings sort: {sort}.")


def _finding_matches_query(finding: Any, query: str | None) -> bool:
    if query is None:
        return True
    values = [
        finding.cve_id,
        finding.component.name if finding.component else None,
        finding.component.version if finding.component else None,
        finding.asset.asset_id if finding.asset else None,
        finding.asset.business_service if finding.asset else None,
        finding.asset.owner if finding.asset else None,
    ]
    return any(query in str(value).lower() for value in values if value)


def _finding_matches_owner(finding: Any, owner: str | None) -> bool:
    if owner is None:
        return True
    return finding.asset is not None and owner in (finding.asset.owner or "").lower()


def _finding_matches_service(finding: Any, service: str | None) -> bool:
    if service is None:
        return True
    return finding.asset is not None and service in (finding.asset.business_service or "").lower()

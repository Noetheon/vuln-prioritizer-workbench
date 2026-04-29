"""Finding API routes for the Workbench domain."""

from __future__ import annotations

import uuid
from typing import Literal

from fastapi import APIRouter, HTTPException, Query

from app.api.deps import CurrentUser, SessionDep
from app.api.routes.workbench_access import require_visible_project
from app.models import (
    AssetExposure,
    Finding,
    FindingDetailPublic,
    FindingExplanationPublic,
    FindingOccurrence,
    FindingOccurrencePublic,
    FindingPriority,
    FindingPublic,
    FindingsPublic,
    FindingStatus,
)
from app.repositories import FindingRepository
from app.services import DecisionDataUnavailableError, build_finding_explanation_payload

router = APIRouter(tags=["findings"])

FindingsSort = Literal[
    "operational",
    "priority",
    "score",
    "cve",
    "status",
    "epss",
    "cvss",
    "kev",
    "last_seen",
]
FindingsSortDirection = Literal["asc", "desc"]


@router.get("/projects/{project_id}/findings/", response_model=FindingsPublic)
def read_project_findings(
    project_id: uuid.UUID,
    session: SessionDep,
    current_user: CurrentUser,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    sort: FindingsSort = Query(default="operational"),
    direction: FindingsSortDirection = Query(default="asc"),
    priority: FindingPriority | None = Query(default=None),
    status: FindingStatus | None = Query(default=None),
    kev: bool | None = Query(default=None),
    owner: str | None = Query(default=None, max_length=200),
    service: str | None = Query(default=None, max_length=200),
    owner_service: str | None = Query(default=None, max_length=200),
    asset_id: uuid.UUID | None = Query(default=None),
    exposure: AssetExposure | None = Query(default=None),
    epss_min: float | None = Query(default=None, ge=0, le=1),
    epss_max: float | None = Query(default=None, ge=0, le=1),
    cvss_min: float | None = Query(default=None, ge=0, le=10),
    cvss_max: float | None = Query(default=None, ge=0, le=10),
) -> FindingsPublic:
    """List a paginated page of findings for a visible project."""
    require_visible_project(session, current_user, project_id)
    findings, count = FindingRepository(session).list_project_findings_page(
        project_id,
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
        asset_id=asset_id,
        exposure=exposure,
        epss_min=epss_min,
        epss_max=epss_max,
        cvss_min=cvss_min,
        cvss_max=cvss_max,
    )
    return FindingsPublic(
        data=[_finding_public(finding) for finding in findings],
        count=count,
    )


@router.get("/findings/{finding_id}", response_model=FindingDetailPublic)
def read_finding(
    finding_id: uuid.UUID,
    session: SessionDep,
    current_user: CurrentUser,
) -> FindingDetailPublic:
    """Read one finding if its project is visible."""
    finding = FindingRepository(session).get_finding(finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    require_visible_project(session, current_user, finding.project_id)
    return _finding_detail_public(finding)


def _finding_public(finding: Finding) -> FindingPublic:
    """Return a finding DTO with display context needed by the Workbench table."""
    return FindingPublic.model_validate(finding).model_copy(
        update={
            "component_name": finding.component.name if finding.component else None,
            "component_version": finding.component.version if finding.component else None,
            "component_purl": finding.component.purl if finding.component else None,
            "asset_name": finding.asset.name if finding.asset else None,
            "asset_key": finding.asset.asset_key if finding.asset else None,
            "asset_target_ref": finding.asset.target_ref if finding.asset else None,
            "asset_environment": finding.asset.environment if finding.asset else None,
            "asset_criticality": finding.asset.criticality if finding.asset else None,
            "owner": finding.asset.owner if finding.asset else None,
            "business_service": finding.asset.business_service if finding.asset else None,
            "exposure": finding.asset.exposure if finding.asset else None,
        }
    )


def _finding_detail_public(finding: Finding) -> FindingDetailPublic:
    """Return a finding detail DTO with source occurrence rows."""
    return FindingDetailPublic.model_validate(_finding_public(finding)).model_copy(
        update={
            "occurrences": [
                _finding_occurrence_public(occurrence, finding)
                for occurrence in finding.occurrences
            ],
        }
    )


def _finding_occurrence_public(
    occurrence: FindingOccurrence,
    finding: Finding,
) -> FindingOccurrencePublic:
    """Return a conservative occurrence DTO from persisted columns and raw evidence."""
    evidence = occurrence.evidence_json or {}
    return FindingOccurrencePublic(
        id=occurrence.id,
        analysis_run_id=occurrence.analysis_run_id,
        source=occurrence.source,
        scanner=occurrence.scanner or _string_evidence(evidence, "scanner"),
        raw_reference=occurrence.raw_reference,
        fix_version=occurrence.fix_version,
        source_format=(
            _string_evidence(evidence, "source_format")
            or _string_evidence(evidence, "input_type")
            or occurrence.source
        ),
        source_id=_string_evidence(evidence, "source_id"),
        source_record_id=_string_evidence(evidence, "source_record_id") or occurrence.raw_reference,
        component_name=(
            _string_evidence(evidence, "component_name")
            or _string_evidence(evidence, "component")
            or (finding.component.name if finding.component else None)
        ),
        component_version=(
            _string_evidence(evidence, "component_version")
            or _string_evidence(evidence, "version")
            or (finding.component.version if finding.component else None)
        ),
        purl=_string_evidence(evidence, "purl")
        or (finding.component.purl if finding.component else None),
        fix_versions=_string_list_evidence(evidence, "fix_versions")
        or ([occurrence.fix_version] if occurrence.fix_version else None),
        target_kind=_string_evidence(evidence, "target_kind"),
        target_ref=_string_evidence(evidence, "target_ref"),
        asset_ref=(
            _string_evidence(evidence, "asset_ref")
            or _string_evidence(evidence, "asset_id")
            or (finding.asset.asset_key if finding.asset else None)
        ),
        asset_owner=(
            _string_evidence(evidence, "asset_owner")
            or _string_evidence(evidence, "owner")
            or (finding.asset.owner if finding.asset else None)
        ),
        asset_business_service=(
            _string_evidence(evidence, "asset_business_service")
            or _string_evidence(evidence, "business_service")
            or (finding.asset.business_service if finding.asset else None)
        ),
        asset_exposure=(
            _string_evidence(evidence, "asset_exposure")
            or _string_evidence(evidence, "exposure")
            or (finding.asset.exposure if finding.asset else None)
        ),
        raw_severity=_string_evidence(evidence, "raw_severity")
        or _string_evidence(evidence, "severity"),
        created_at=getattr(occurrence, "created_at", None),
    )


def _string_evidence(evidence: dict[str, object], key: str) -> str | None:
    value = evidence.get(key)
    if isinstance(value, str):
        stripped = value.strip()
        return stripped or None
    return None


def _string_list_evidence(evidence: dict[str, object], key: str) -> list[str] | None:
    value = evidence.get(key)
    if isinstance(value, list):
        items = [item.strip() for item in value if isinstance(item, str) and item.strip()]
        return items or None
    if isinstance(value, str):
        stripped = value.strip()
        return [stripped] if stripped else None
    return None


@router.get("/findings/{finding_id}/explain", response_model=FindingExplanationPublic)
def explain_finding(
    finding_id: uuid.UUID,
    session: SessionDep,
    current_user: CurrentUser,
) -> FindingExplanationPublic:
    """Read the persisted decision explanation for one visible finding."""
    finding = FindingRepository(session).get_finding(finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    require_visible_project(session, current_user, finding.project_id)
    try:
        return build_finding_explanation_payload(finding)
    except DecisionDataUnavailableError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

"""Finding API routes for the Workbench domain."""

from __future__ import annotations

import uuid
from typing import Literal

from fastapi import APIRouter, HTTPException, Query
from sqlmodel import Session, col, select

from app.api.deps import CurrentUser, SessionDep
from app.api.routes.workbench_access import require_visible_project
from app.models import (
    AssetExposure,
    Finding,
    FindingAttackContext,
    FindingAttackContextDetailPublic,
    FindingAttackMappingDetailPublic,
    FindingAttackTechniqueDetailPublic,
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
    return _finding_detail_public_with_attack_context(session, finding)


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


def _finding_detail_public_with_attack_context(
    session: Session,
    finding: Finding,
) -> FindingDetailPublic:
    detail = _finding_detail_public(finding)
    context = _latest_finding_attack_context(session, finding.id)
    return detail.model_copy(
        update={
            "attack_context": _finding_attack_context_detail_public(context, finding),
        }
    )


def _latest_finding_attack_context(
    session: Session,
    finding_id: uuid.UUID,
) -> FindingAttackContext | None:
    statement = (
        select(FindingAttackContext)
        .where(FindingAttackContext.finding_id == finding_id)
        .order_by(col(FindingAttackContext.created_at).desc())
    )
    return session.exec(statement).first()


def _finding_attack_context_detail_public(
    context: FindingAttackContext | None,
    finding: Finding,
) -> FindingAttackContextDetailPublic | None:
    if context is not None:
        mappings = _attack_mapping_rows(
            context.mappings_json,
            source=context.source,
            review_status=context.review_status,
            context_rationale=context.rationale,
            defensive_note=context.defensive_note,
        )
        techniques = _attack_technique_rows(
            mappings,
            context.technique_ids_json,
            source=context.source,
            review_status=context.review_status,
            defensive_note=context.defensive_note,
        )
        confidence = _attack_context_confidence(mappings)
        return FindingAttackContextDetailPublic(
            mapped=context.mapped,
            source=context.source,
            review_status=context.review_status,
            defensive_note=context.defensive_note,
            rationale=context.rationale,
            confidence=confidence,
            low_confidence=confidence == "low",
            attack_relevance="Mapped" if context.mapped else "Unmapped",
            technique_ids=list(context.technique_ids_json),
            tactics=_attack_context_tactics(mappings, techniques, context.tactic_ids_json),
            mappings=mappings,
            techniques=techniques,
        )

    raw_context = _object_record(finding.explanation_json.get("attack_context"))
    if not raw_context or (
        raw_context.get("mapped") is not True and raw_context.get("source") in {None, "none", ""}
    ):
        return None
    mappings = _attack_mapping_rows(
        _array_records(raw_context.get("mappings")),
        source=_string_value(raw_context.get("source")) or "none",
        review_status="reviewed" if raw_context.get("mapped") is True else "unreviewed",
        context_rationale=_string_value(raw_context.get("rationale")),
        defensive_note=_default_attack_defensive_note(raw_context.get("mapped") is True),
    )
    techniques = _attack_technique_rows(
        mappings,
        _attack_context_technique_ids(_array_records(raw_context.get("techniques"))),
        source=_string_value(raw_context.get("source")) or "none",
        review_status="reviewed" if raw_context.get("mapped") is True else "unreviewed",
        defensive_note=_default_attack_defensive_note(raw_context.get("mapped") is True),
    )
    confidence = _string_value(raw_context.get("confidence")) or _attack_context_confidence(
        mappings
    )
    return FindingAttackContextDetailPublic(
        mapped=raw_context.get("mapped") is True,
        source=_string_value(raw_context.get("source")) or "none",
        review_status="reviewed" if raw_context.get("mapped") is True else "unreviewed",
        defensive_note=_default_attack_defensive_note(raw_context.get("mapped") is True),
        rationale=_string_value(raw_context.get("rationale")),
        confidence=confidence,
        low_confidence=confidence == "low" or raw_context.get("low_confidence") is True,
        attack_relevance=_string_value(raw_context.get("attack_relevance")) or "Unmapped",
        technique_ids=[row.technique_id for row in techniques],
        tactics=_attack_context_tactics(mappings, techniques, []),
        mappings=mappings,
        techniques=techniques,
    )


def _attack_mapping_rows(
    mappings_json: list[dict[str, object]],
    *,
    source: str,
    review_status: str,
    context_rationale: str | None,
    defensive_note: str,
) -> list[FindingAttackMappingDetailPublic]:
    rows: list[FindingAttackMappingDetailPublic] = []
    for mapping in mappings_json:
        technique = _object_record(mapping.get("technique"))
        technique_id = (
            _string_value(mapping.get("attack_object_id"))
            or _string_value(mapping.get("technique_id"))
            or _string_value(technique.get("attack_object_id"))
        )
        if technique_id is None:
            continue
        confidence = _attack_confidence_label(mapping.get("confidence"))
        rows.append(
            FindingAttackMappingDetailPublic(
                technique_id=technique_id,
                technique_name=(
                    _string_value(mapping.get("attack_object_name"))
                    or _string_value(mapping.get("technique_name"))
                    or _string_value(technique.get("name"))
                ),
                tactics=_string_list_value(mapping.get("tactics"))
                or _string_list_value(technique.get("tactics")),
                source=_string_value(mapping.get("source")) or source,
                confidence=confidence,
                review_status=_string_value(mapping.get("review_status")) or review_status,
                mapping_type=_string_value(mapping.get("mapping_type")),
                rationale=(
                    _string_value(mapping.get("rationale"))
                    or context_rationale
                    or "Reviewed ATT&CK mapping for defensive triage."
                ),
                defensive_note=_string_value(mapping.get("defensive_note")) or defensive_note,
                references=_string_list_value(mapping.get("references")),
            )
        )
    return rows


def _attack_technique_rows(
    mappings: list[FindingAttackMappingDetailPublic],
    technique_ids: list[str],
    *,
    source: str,
    review_status: str,
    defensive_note: str,
) -> list[FindingAttackTechniqueDetailPublic]:
    rows: list[FindingAttackTechniqueDetailPublic] = []
    seen: set[str] = set()
    for mapping in mappings:
        if mapping.technique_id in seen:
            continue
        seen.add(mapping.technique_id)
        rows.append(
            FindingAttackTechniqueDetailPublic(
                technique_id=mapping.technique_id,
                name=mapping.technique_name,
                tactics=mapping.tactics,
                source=mapping.source or source,
                confidence=mapping.confidence,
                review_status=mapping.review_status or review_status,
                rationale=mapping.rationale,
                defensive_note=mapping.defensive_note or defensive_note,
            )
        )
    for technique_id in technique_ids:
        if technique_id not in seen:
            rows.append(
                FindingAttackTechniqueDetailPublic(
                    technique_id=technique_id,
                    source=source,
                    review_status=review_status,
                    defensive_note=defensive_note,
                )
            )
    return rows


def _attack_context_technique_ids(records: list[dict[str, object]]) -> list[str]:
    values: list[str] = []
    for item in records:
        candidate = _string_value(item.get("attack_object_id")) or _string_value(
            item.get("technique_id")
        )
        if candidate:
            values.append(candidate)
    return values


def _attack_context_confidence(mappings: list[FindingAttackMappingDetailPublic]) -> str | None:
    confidence_order = {"low": 0, "medium": 1, "high": 2}
    labels = [mapping.confidence for mapping in mappings if mapping.confidence in confidence_order]
    if not labels:
        return None
    return min(labels, key=lambda item: confidence_order[item])


def _attack_confidence_label(value: object) -> str | None:
    if isinstance(value, str):
        normalized = value.strip().lower()
        return normalized if normalized in {"low", "medium", "high"} else None
    if isinstance(value, int | float):
        if value >= 0.75:
            return "high"
        if value >= 0.4:
            return "medium"
        return "low"
    return None


def _attack_context_tactics(
    mappings: list[FindingAttackMappingDetailPublic],
    techniques: list[FindingAttackTechniqueDetailPublic],
    context_tactics: list[str],
) -> list[str]:
    tactics: list[str] = []
    for value in context_tactics:
        if value and value not in tactics:
            tactics.append(value)
    for mapping in mappings:
        for tactic in mapping.tactics:
            if tactic and tactic not in tactics:
                tactics.append(tactic)
    for technique in techniques:
        for tactic in technique.tactics:
            if tactic and tactic not in tactics:
                tactics.append(tactic)
    return tactics


def _default_attack_defensive_note(mapped: bool) -> str:
    if mapped:
        return (
            "Use this ATT&CK context only for defensive triage, detection coverage, "
            "and mitigation review."
        )
    return "No approved ATT&CK mapping is stored for this finding."


def _object_record(value: object) -> dict[str, object]:
    return value if isinstance(value, dict) else {}


def _array_records(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _string_value(value: object) -> str | None:
    if isinstance(value, str):
        stripped = value.strip()
        return stripped or None
    return None


def _string_list_value(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item.strip() for item in value if isinstance(item, str) and item.strip()]


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

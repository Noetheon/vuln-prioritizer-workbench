"""Finding DTO projection helpers."""

from __future__ import annotations

import uuid

from sqlmodel import Session, col, select

from app.decision_core.contracts import FindingDecisionEvidenceV2, OccurrenceEvidenceV2
from app.decision_core.readmodels import (
    DecisionFindingView,
    latest_finding_decision_view,
)
from app.domain.engine.security_redaction import redact_value
from app.models import (
    Finding,
    FindingAttackContext,
    FindingAttackContextDetailPublic,
    FindingAttackMappingDetailPublic,
    FindingAttackTechniqueDetailPublic,
    FindingDetailPublic,
    FindingOccurrence,
    FindingOccurrencePublic,
    FindingPublic,
)


def _finding_public(
    finding: Finding,
    *,
    session: Session | None = None,
) -> FindingPublic:
    """Return a finding DTO with display context needed by the Workbench table."""
    view = latest_finding_decision_view(finding, session=session)
    return _finding_public_from_view(view)


def _finding_public_from_view(view: DecisionFindingView) -> FindingPublic:
    """Return a finding DTO from an already-batched current decision view."""
    return FindingPublic.model_validate(view.finding).model_copy(update=view.public_update())


def _latest_decision_evidence(
    finding: Finding,
    *,
    session: Session | None = None,
) -> FindingDecisionEvidenceV2 | None:
    return latest_finding_decision_view(finding, session=session).evidence


def _redacted_finding_json(value: dict[str, object] | None) -> dict[str, object]:
    redacted, _paths = redact_value(value or {})
    return redacted if isinstance(redacted, dict) else {}


def _finding_detail_public(finding: Finding) -> FindingDetailPublic:
    """Return a finding detail DTO with source occurrence rows."""
    view = latest_finding_decision_view(finding)
    evidence_occurrences = _evidence_occurrences_public(view)
    return FindingDetailPublic.model_validate(_finding_public(finding)).model_copy(
        update={
            "occurrences": evidence_occurrences
            if evidence_occurrences is not None
            else [
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

    evidence = latest_finding_decision_view(finding).evidence
    if evidence is None or (
        evidence.attack.mapped is not True and evidence.attack.source in {None, "none", ""}
    ):
        return None
    raw_context = evidence.attack.to_jsonable()
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
    evidence = _redacted_finding_json(occurrence.evidence_json)
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
            or (finding.component.name if finding.component else None)
        ),
        component_version=(
            _string_evidence(evidence, "component_version")
            or (finding.component.version if finding.component else None)
        ),
        purl=_string_evidence(evidence, "purl")
        or (finding.component.purl if finding.component else None),
        fix_versions=_string_list_evidence(evidence, "fix_versions")
        or ([occurrence.fix_version] if occurrence.fix_version else None),
        target_kind=_string_evidence(evidence, "target_kind"),
        target_ref=_string_evidence(evidence, "target_ref")
        or (finding.asset.target_ref if finding.asset else None),
        asset_id=_string_evidence(evidence, "asset_id"),
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
        raw_severity=_string_evidence(evidence, "raw_severity"),
        vex_status=_string_evidence(evidence, "vex_status"),
        vex_justification=_string_evidence(evidence, "vex_justification"),
        vex_action_statement=_string_evidence(evidence, "vex_action_statement"),
        vex_match_type=_string_evidence(evidence, "vex_match_type"),
        vex_source_format=_string_evidence(evidence, "vex_source_format"),
        vex_source_record_id=_string_evidence(evidence, "vex_source_record_id"),
        vex_source_path=_string_evidence(evidence, "vex_source_path"),
        vex_candidate_count=_int_evidence(evidence, "vex_candidate_count"),
        created_at=getattr(occurrence, "created_at", None),
    )


def _evidence_occurrences_public(
    view: DecisionFindingView,
) -> list[FindingOccurrencePublic] | None:
    evidence = view.evidence
    if evidence is None or not evidence.occurrences:
        return None
    rows: list[FindingOccurrencePublic] = []
    for occurrence in evidence.occurrences:
        row = _evidence_occurrence_public(occurrence, finding=view.finding)
        if row is None:
            return None
        rows.append(row)
    return rows


def _evidence_occurrence_public(
    occurrence: OccurrenceEvidenceV2,
    *,
    finding: Finding,
) -> FindingOccurrencePublic | None:
    if occurrence.occurrence_id is None:
        return None
    try:
        occurrence_id = uuid.UUID(occurrence.occurrence_id)
        analysis_run_id = uuid.UUID(occurrence.analysis_run_id)
    except ValueError:
        return None
    import_evidence = occurrence.import_evidence
    return FindingOccurrencePublic(
        id=occurrence_id,
        analysis_run_id=analysis_run_id,
        source=occurrence.source,
        scanner=occurrence.scanner,
        raw_reference=occurrence.raw_reference,
        fix_version=occurrence.fix_version,
        source_format=occurrence.source_format or occurrence.source,
        source_id=occurrence.source_id,
        source_record_id=occurrence.source_record_id or occurrence.raw_reference,
        component_name=occurrence.component_name,
        component_version=occurrence.component_version,
        purl=occurrence.purl,
        fix_versions=occurrence.fix_versions,
        target_kind=occurrence.target_kind,
        target_ref=occurrence.target_ref or (finding.asset.target_ref if finding.asset else None),
        asset_id=occurrence.asset_id,
        asset_owner=occurrence.asset_owner
        or _string_evidence(import_evidence, "asset_owner")
        or _string_evidence(import_evidence, "owner")
        or (finding.asset.owner if finding.asset else None),
        asset_business_service=occurrence.asset_business_service
        or _string_evidence(import_evidence, "asset_business_service")
        or _string_evidence(import_evidence, "business_service")
        or (finding.asset.business_service if finding.asset else None),
        asset_exposure=occurrence.asset_exposure
        or _string_evidence(import_evidence, "asset_exposure")
        or _string_evidence(import_evidence, "exposure")
        or (finding.asset.exposure if finding.asset else None),
        raw_severity=occurrence.raw_severity,
        vex_status=occurrence.vex_status,
        vex_justification=occurrence.vex_justification,
        vex_action_statement=occurrence.vex_action_statement,
        vex_match_type=occurrence.vex_match_type,
        vex_source_format=occurrence.vex_source_format,
        vex_source_record_id=occurrence.vex_source_record_id,
        vex_source_path=occurrence.vex_source_path,
        vex_candidate_count=occurrence.vex_candidate_count,
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


def _int_evidence(evidence: dict[str, object], key: str) -> int:
    value = evidence.get(key)
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            return 0
    return 0


__all__ = [
    "_finding_public",
    "_finding_public_from_view",
    "_redacted_finding_json",
    "_finding_detail_public",
    "_finding_detail_public_with_attack_context",
    "_latest_finding_attack_context",
    "_finding_attack_context_detail_public",
    "_attack_mapping_rows",
    "_attack_technique_rows",
    "_attack_context_technique_ids",
    "_attack_context_confidence",
    "_attack_confidence_label",
    "_attack_context_tactics",
    "_default_attack_defensive_note",
    "_object_record",
    "_array_records",
    "_string_value",
    "_string_list_value",
    "_finding_occurrence_public",
    "_string_evidence",
    "_string_list_evidence",
    "_int_evidence",
]

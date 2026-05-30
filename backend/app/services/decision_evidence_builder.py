"""
Adapter builders for Decision/Evidence v2 payload boundaries.

Successful Workbench imports build product evidence through
``app.services.decision_kernel``. This module remains for typed diagnostics,
finding-level adapter helpers, and historical payload-boundary tests.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from typing import Any

from app.contracts.decision_evidence import (
    AttackEvidenceV2,
    FindingDecisionEvidenceV2,
    GovernanceEvidenceV2,
    OccurrenceEvidenceV2,
    PriorityEvidenceV2,
    ProviderEvidenceV2,
    RemediationEvidenceV2,
    RunDiagnosticsV2,
    RunFailureV2,
    RunParseErrorV2,
)


def build_run_diagnostics(payload: Mapping[str, Any] | None) -> RunDiagnosticsV2:
    """Build typed diagnostics from terminal workflow failure payloads."""
    raw = _dict_value(payload)
    return RunDiagnosticsV2(
        stage=_str_value(raw.get("stage")),
        message=_str_value(raw.get("message")),
        error_type=_str_value(raw.get("error_type")),
        parse_errors=[
            RunParseErrorV2.model_validate(item) for item in _dict_list(raw.get("parse_errors"))
        ],
        analysis_error=_failure(raw.get("analysis_error")),
        asset_context_error=_failure(raw.get("asset_context_error")),
        vex_error=_failure(raw.get("vex_error")),
        warnings=_string_list(raw.get("warnings")),
    )


def finding_decision_evidence_from_payload(payload: Mapping[str, Any]) -> FindingDecisionEvidenceV2:
    """Validate one persisted finding evidence payload."""
    return FindingDecisionEvidenceV2.model_validate(dict(payload))


def build_finding_decision_evidence(
    *,
    project_id: uuid.UUID,
    run_id: uuid.UUID,
    finding_id: uuid.UUID,
    cve_id: str,
    dedup_key: str,
    status: str,
    priority: str,
    priority_rank: int,
    risk_score: float | None,
    operational_rank: int,
    in_kev: bool,
    epss: float | None,
    cvss_base_score: float | None,
    attack_mapped: bool,
    suppressed_by_vex: bool,
    under_investigation: bool,
    waived: bool,
    rationale: str | None,
    recommended_action: str | None,
    decision_payload: Mapping[str, Any],
    data_quality_payload: Mapping[str, Any],
    provider_payload: Mapping[str, Any],
    occurrence_scope: Mapping[str, Any],
    occurrence_evidence: list[OccurrenceEvidenceV2],
) -> FindingDecisionEvidenceV2:
    """Build finding-level evidence from scoring and persistence decisions."""
    decision = _dict_value(decision_payload)
    guidance = _dict_value(decision.get("decision_guidance"))
    provenance = _dict_value(decision.get("provenance"))
    return FindingDecisionEvidenceV2(
        finding_id=str(finding_id),
        analysis_run_id=str(run_id),
        project_id=str(project_id),
        cve_id=cve_id,
        dedup_key=dedup_key,
        status=status,
        priority=priority,
        priority_rank=priority_rank,
        risk_score=risk_score,
        operational_rank=operational_rank,
        in_kev=in_kev,
        epss=epss,
        cvss_base_score=cvss_base_score,
        attack_mapped=attack_mapped,
        suppressed_by_vex=suppressed_by_vex,
        under_investigation=under_investigation,
        waived=waived,
        rationale=rationale,
        recommended_action=recommended_action,
        occurrence_scope=_dict_value(occurrence_scope),
        priority_evidence=PriorityEvidenceV2(
            priority_label=_str_value(decision.get("priority_label")) or priority.title(),
            priority_rank=priority_rank,
            priority_state=_str_value(decision.get("priority_state")),
            operational_score=_float_value(decision.get("operational_score")),
            operational_score_reasons=_string_list(decision.get("operational_score_reasons")),
            explanation=_dict_value(decision.get("explanation")),
            rationale=rationale,
            data_quality_confidence=_str_value(decision.get("data_quality_confidence"))
            or _str_value(_dict_value(data_quality_payload).get("confidence")),
            data_quality_flags=_dict_list(decision.get("data_quality_flags"))
            or _dict_list(_dict_value(data_quality_payload).get("flags")),
            raw=decision,
        ),
        provider=ProviderEvidenceV2(
            provider_snapshot_hash=_str_value(provenance.get("provider_snapshot_hash")),
            provider_evidence=_dict_value(provider_payload),
        ),
        governance=GovernanceEvidenceV2(
            suppressed_by_vex=suppressed_by_vex,
            under_investigation=under_investigation,
            waived=waived,
            vex_statuses={
                key: _int_value(value)
                for key, value in _dict_value(provenance.get("vex_statuses")).items()
            },
            waiver=_dict_value(decision.get("waiver")),
            data_quality=_dict_value(data_quality_payload),
        ),
        attack=AttackEvidenceV2(
            mapped=attack_mapped,
            source=_str_value(_dict_value(decision.get("attack_context")).get("source")) or "none",
            review_status=_str_value(
                _dict_value(decision.get("attack_context")).get("review_status")
            )
            or "unreviewed",
            defensive_note=_str_value(
                _dict_value(decision.get("attack_context")).get("defensive_note")
            ),
            rationale=_str_value(_dict_value(decision.get("attack_context")).get("rationale")),
            confidence=_str_value(_dict_value(decision.get("attack_context")).get("confidence")),
            technique_ids=[str(item) for item in _list_value(decision.get("attack_techniques"))],
            mappings=_dict_list(_dict_value(decision.get("attack_context")).get("mappings")),
        ),
        remediation=RemediationEvidenceV2(
            recommended_action=recommended_action,
            decision_statement=_decision_text(guidance, "decision_statement"),
            recommendation=_decision_text(guidance, "recommendation"),
            recommendation_label=_decision_text(guidance, "recommendation_label"),
            business_impact=_decision_text(guidance, "business_impact"),
            sla=_dict_value(guidance.get("sla")),
            raw=guidance,
        ),
        occurrences=occurrence_evidence,
    )


def build_occurrence_evidence(
    *,
    analysis_run_id: uuid.UUID,
    occurrence_id: uuid.UUID | None = None,
    source: str | None,
    scanner: str | None = None,
    raw_reference: str | None,
    fix_version: str | None,
    raw_evidence: Mapping[str, Any],
    dedup: Mapping[str, Any],
) -> OccurrenceEvidenceV2:
    """Build occurrence evidence from persisted/imported occurrence state."""
    raw = _dict_value(raw_evidence)
    return OccurrenceEvidenceV2(
        occurrence_id=str(occurrence_id) if occurrence_id is not None else None,
        analysis_run_id=str(analysis_run_id),
        source=source,
        scanner=scanner,
        raw_reference=raw_reference,
        fix_version=fix_version,
        source_format=_str_value(raw.get("source_format")),
        source_id=_str_value(raw.get("source_id")),
        source_record_id=_str_value(raw.get("source_record_id")),
        component_name=_str_value(raw.get("component")),
        component_version=_str_value(raw.get("version")),
        purl=_str_value(raw.get("purl")),
        fix_versions=[str(item) for item in _list_value(raw.get("fix_versions"))] or None,
        target_kind=_str_value(raw.get("target_kind")),
        target_ref=_str_value(raw.get("target_ref")),
        asset_ref=_str_value(raw.get("asset_ref")),
        asset_owner=_str_value(raw.get("owner")),
        asset_business_service=_str_value(raw.get("business_service")),
        asset_exposure=_str_value(raw.get("exposure")),
        raw_severity=_str_value(raw.get("severity")),
        vex_status=_str_value(raw.get("vex_status")),
        vex_justification=_str_value(raw.get("vex_justification")),
        vex_action_statement=_str_value(raw.get("vex_action_statement")),
        vex_match_type=_str_value(raw.get("vex_match_type")),
        vex_source_format=_str_value(raw.get("vex_source_format")),
        vex_source_record_id=_str_value(raw.get("vex_source_record_id")),
        vex_source_path=_str_value(raw.get("vex_source_path")),
        vex_candidate_count=_int_value(raw.get("vex_candidate_count")),
        import_evidence=raw,
        dedup=_dict_value(dedup),
    )


def workflow_ref_payload(
    *,
    analysis_evidence_id: uuid.UUID,
    artifact_refs: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Return the compact workflow result payload for a terminal import."""
    return {
        "schema_version": "workflow-result-ref.v2",
        "analysis_evidence_id": str(analysis_evidence_id),
        "artifact_refs": artifact_refs or [],
    }


def _failure(value: Any) -> RunFailureV2 | None:
    payload = _dict_value(value)
    return RunFailureV2.model_validate(payload) if payload else None


def _dict_value(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}


def _dict_list(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [dict(item) for item in value if isinstance(item, Mapping)]


def _list_value(value: Any) -> list[Any]:
    return list(value) if isinstance(value, list) else []


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str) and item]


def _str_value(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _int_value(value: Any) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str) and value.isdecimal():
        return int(value)
    return 0


def _float_value(value: Any) -> float | None:
    if isinstance(value, bool):
        return float(value)
    if isinstance(value, int | float):
        return float(value)
    return None


def _decision_text(decision_guidance: Mapping[str, Any], key: str) -> str | None:
    value = decision_guidance.get(key)
    if isinstance(value, str) and value.strip():
        return value
    if isinstance(value, Mapping):
        for candidate in ("text", "summary", "statement", "label"):
            candidate_value = value.get(candidate)
            if isinstance(candidate_value, str) and candidate_value.strip():
                return candidate_value
    return None

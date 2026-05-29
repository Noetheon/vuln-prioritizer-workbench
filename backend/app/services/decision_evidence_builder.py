"""Build Decision/Evidence Kernel v2 contracts from import execution state."""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from typing import Any

from app.contracts.decision_evidence import (
    AnalysisEvidenceUploadsV2,
    AnalysisEvidenceV2,
    AttackEvidenceV2,
    EvidenceUploadRef,
    FindingDecisionEvidenceV2,
    GovernanceEvidenceV2,
    OccurrenceEvidenceV2,
    PriorityEvidenceV2,
    ProviderEvidenceV2,
    RemediationEvidenceV2,
    RunCountsV2,
    RunDiagnosticsV2,
    RunFailureV2,
    RunParseErrorV2,
)
from app.models import AnalysisRun
from app.services.analysis import WorkbenchAnalysisResult

PRIORITY_LABELS = ("Critical", "High", "Medium", "Low")


def build_analysis_evidence(
    *,
    project_id: uuid.UUID,
    run: AnalysisRun,
    analysis_result: WorkbenchAnalysisResult,
    run_payload: Mapping[str, Any],
    finding_evidence: list[FindingDecisionEvidenceV2],
    diagnostics: RunDiagnosticsV2 | None = None,
) -> AnalysisEvidenceV2:
    """Build and validate the run-wide evidence contract."""
    payload = _dict_value(run_payload)
    counts = RunCountsV2(
        created_findings=_int_value(payload.get("created_findings")),
        updated_findings=_int_value(payload.get("updated_findings")),
        ignored_lines=_int_value(payload.get("ignored_lines")),
        rows_read=_int_value(payload.get("rows_read")),
        occurrence_count=_int_value(payload.get("occurrence_count")),
        finding_count=_int_value(payload.get("finding_count")),
        counts_by_priority=_priority_counts(payload.get("counts_by_priority")),
        kev_hits=_int_value(payload.get("kev_hits")),
        epss_hits=_int_value(payload.get("epss_hits")),
        nvd_hits=_int_value(payload.get("nvd_hits")),
        suppressed_by_vex=_int_value(payload.get("suppressed_by_vex")),
        under_investigation_count=_int_value(payload.get("under_investigation_count")),
        vex_conflict_count=_int_value(payload.get("vex_conflict_count")),
        attack_mapped_cves=_int_value(payload.get("attack_mapped_cves")),
    )
    provider = ProviderEvidenceV2(
        provider_snapshot_id=str(analysis_result.provider_snapshot_id)
        if analysis_result.provider_snapshot_id is not None
        else None,
        provider_snapshot_hash=analysis_result.provider_snapshot_hash,
        provider_snapshot_file=_str_value(payload.get("provider_snapshot_file")),
        locked_provider_data=bool(payload.get("locked_provider_data")),
        provider_degraded=bool(payload.get("provider_degraded")),
        provider_data_quality_flags=_dict_value(payload.get("provider_data_quality_flags")),
        kev_hits=counts.kev_hits,
        epss_hits=counts.epss_hits,
        nvd_hits=counts.nvd_hits,
    )
    return AnalysisEvidenceV2(
        analysis_run_id=str(run.id),
        project_id=str(project_id),
        input_type=run.input_type,
        filename=run.filename,
        status=str(run.status),
        input_sha256=_str_value(payload.get("input_sha256")),
        counts=counts,
        uploads=AnalysisEvidenceUploadsV2(
            input=_upload_ref(payload.get("input_upload")),
            asset_context=_upload_ref(payload.get("asset_context_upload")),
            vex=_upload_ref(payload.get("vex_upload")),
        ),
        provider=provider,
        warnings=_string_list(payload.get("warnings")),
        parse_errors=[
            RunParseErrorV2.model_validate(item) for item in _dict_list(payload.get("parse_errors"))
        ],
        analysis_service=_dict_value(payload.get("analysis_service")),
        analysis_semantics=_dict_value(payload.get("analysis_semantics")),
        asset_context=_dict_or_none(payload.get("asset_context")),
        vex=_dict_or_none(payload.get("vex")),
        dedup_summary=_dict_or_none(payload.get("dedup_summary")),
        attack=AttackEvidenceV2(
            mapped=counts.attack_mapped_cves > 0,
            source=_str_value(payload.get("attack_source")) or "none",
            technique_ids=_finding_technique_ids(finding_evidence),
        ),
        diagnostics=diagnostics,
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


def _upload_ref(value: Any) -> EvidenceUploadRef | None:
    payload = _dict_value(value)
    return EvidenceUploadRef.model_validate(payload) if payload else None


def _failure(value: Any) -> RunFailureV2 | None:
    payload = _dict_value(value)
    return RunFailureV2.model_validate(payload) if payload else None


def _priority_counts(value: Any) -> dict[str, int]:
    raw = _dict_value(value)
    return {label: _int_value(raw.get(label)) for label in PRIORITY_LABELS}


def _finding_technique_ids(items: list[FindingDecisionEvidenceV2]) -> list[str]:
    technique_ids: list[str] = []
    for item in items:
        for technique_id in item.attack.technique_ids:
            if technique_id not in technique_ids:
                technique_ids.append(technique_id)
    return technique_ids


def _dict_value(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}


def _dict_or_none(value: Any) -> dict[str, Any] | None:
    payload = _dict_value(value)
    return payload or None


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

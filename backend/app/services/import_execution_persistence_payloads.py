"""Decision payload, status, and evidence helpers for Workbench imports."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from app.domain.engine.models import PrioritizedFinding
from app.domain.import_asset_context import string_evidence as _string_evidence
from app.importers.contracts import NormalizedOccurrence
from app.models import FindingPriority, FindingStatus
from app.services.analysis import WorkbenchAnalysisError, WorkbenchAnalysisResult


def _analysis_semantics_summary(
    *,
    occurrences: list[NormalizedOccurrence],
    finding_count: int,
) -> dict[str, Any]:
    return {
        "analysis_decision_scope": "cve_baseline_with_occurrence_overlays",
        "persistence_scope": "asset_component_occurrence",
        "occurrence_overlay_fields": [
            "asset_context",
            "component_identity",
            "source_identity",
            "vex_status",
        ],
        "finding_dedup_key_version": "vpw019-v1",
        "cve_count": len({occurrence.cve_id for occurrence in occurrences}),
        "occurrence_count": len(occurrences),
        "finding_count": finding_count,
        "same_cve_can_create_distinct_asset_findings": True,
    }


def _decision_payload_for_occurrence(
    decision: PrioritizedFinding,
    occurrence: NormalizedOccurrence,
    *,
    compact: bool = False,
    base_payload: dict[str, Any] | None = None,
    occurrence_scope: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if base_payload is not None:
        payload = deepcopy(base_payload)
    else:
        payload = _compact_decision_payload(decision) if compact else decision.model_dump()
    occurrence_scope = occurrence_scope or _occurrence_scope_payload(occurrence)
    payload["occurrence_scope"] = occurrence_scope
    payload["suppressed_by_vex"] = _suppressed_by_vex_for_occurrence(decision, occurrence)
    payload["priority_state"] = _priority_state_for_occurrence(
        decision,
        occurrence,
        base_priority_state=payload.get("priority_state"),
    )
    provenance = payload.get("provenance")
    if isinstance(provenance, dict):
        provenance["occurrence_scope"] = occurrence_scope
        vex_status = _occurrence_vex_status(occurrence)
        provenance["vex_statuses"] = {vex_status: 1} if vex_status else {}
    return payload


def _analysis_evidence_for_occurrence(
    analysis_result: WorkbenchAnalysisResult,
    decision: PrioritizedFinding,
    occurrence: NormalizedOccurrence,
    *,
    priority_state: str | None = None,
    occurrence_scope: dict[str, Any] | None = None,
) -> dict[str, Any]:
    occurrence_scope = occurrence_scope or _occurrence_scope_payload(occurrence)
    return {
        "decision_scope": "cve_baseline_with_occurrence_overlays",
        "priority_state": priority_state
        or _priority_state_for_occurrence(
            decision,
            occurrence,
            base_priority_state=decision.priority_state,
        ),
        "operational_score": decision.operational_score,
        "provider_snapshot_id": str(analysis_result.provider_snapshot_id)
        if analysis_result.provider_snapshot_id is not None
        else None,
        "provider_snapshot_hash": analysis_result.provider_snapshot_hash,
        "occurrence_scope": occurrence_scope,
        "occurrence_vex_status": _occurrence_vex_status(occurrence),
    }


def _priority_state_for_occurrence(
    decision: PrioritizedFinding,
    occurrence: NormalizedOccurrence,
    *,
    base_priority_state: str | None,
) -> str | None:
    status = _finding_status_for_occurrence(decision, occurrence)
    if status in {FindingStatus.FIXED, FindingStatus.SUPPRESSED}:
        return status.value.title()
    if decision.suppressed_by_vex and _occurrence_vex_status(occurrence) is None:
        return "Open"
    return base_priority_state


def _occurrence_scope_payload(occurrence: NormalizedOccurrence) -> dict[str, Any]:
    return {
        "source": occurrence.source,
        "source_id": _string_evidence(occurrence.raw_evidence, "source_id"),
        "source_record_id": _string_evidence(occurrence.raw_evidence, "source_record_id"),
        "component_name": occurrence.component_name,
        "component_version": occurrence.component_version,
        "purl": _string_evidence(occurrence.raw_evidence, "purl"),
        "target_ref": occurrence.target_ref
        or _string_evidence(occurrence.raw_evidence, "target_ref"),
        "asset_owner": _string_evidence(occurrence.raw_evidence, "owner"),
        "asset_business_service": _string_evidence(
            occurrence.raw_evidence,
            "business_service",
        ),
        "asset_exposure": _string_evidence(occurrence.raw_evidence, "exposure"),
        "asset_environment": _string_evidence(occurrence.raw_evidence, "environment"),
        "asset_criticality": _string_evidence(occurrence.raw_evidence, "criticality"),
        "vex_status": _occurrence_vex_status(occurrence),
        "vex_match_type": _string_evidence(occurrence.raw_evidence, "vex_match_type"),
        "vex_source_path": _string_evidence(occurrence.raw_evidence, "vex_source_path"),
    }


def _compact_decision_payload(decision: PrioritizedFinding) -> dict[str, Any]:
    """Return the explain/score fields needed for large bulk imports without provider bloat."""
    explanation = _jsonable_model(getattr(decision, "explanation", None)) or {}
    guidance = _jsonable_model(getattr(decision, "decision_guidance", None)) or {}
    provenance = _jsonable_model(getattr(decision, "provenance", None)) or {}
    payload: dict[str, Any] = {
        "cve_id": decision.cve_id,
        "priority_label": decision.priority_label,
        "priority_rank": decision.priority_rank,
        "priority_state": decision.priority_state,
        "operational_score": decision.operational_score,
        "operational_score_reasons": list(decision.operational_score_reasons),
        "recommended_action": decision.recommended_action,
        "rationale": decision.rationale,
        "explanation": {
            "summary": explanation.get("summary"),
            "reasons": explanation.get("reasons", []),
        },
        "decision_guidance": {
            "decision_statement": guidance.get("decision_statement"),
            "recommended_next_steps": guidance.get("recommended_next_steps", []),
        },
        "provenance": {
            "vex_statuses": provenance.get("vex_statuses", {}),
            "provider_snapshot_hash": provenance.get("provider_snapshot_hash"),
        },
        "data_quality_flags": [_jsonable_model(item) for item in decision.data_quality_flags],
        "data_quality_confidence": decision.data_quality_confidence,
    }
    if decision.provider_evidence is not None:
        payload["provider_evidence"] = {
            "nvd": {
                "cvss_score": decision.cvss_base_score,
                "cvss_vector": _decision_cvss_vector(decision),
                "published": _decision_published(decision),
                "last_modified": _decision_modified(decision),
                "cwes": _decision_cwes(decision),
            },
            "epss": {"score": decision.epss},
            "kev": {"known_exploited": decision.in_kev},
        }
    return {key: value for key, value in payload.items() if value is not None}


def _jsonable_model(value: Any) -> Any:
    if value is None:
        return None
    if hasattr(value, "model_dump"):
        return value.model_dump()
    if isinstance(value, list):
        return [_jsonable_model(item) for item in value]
    if isinstance(value, tuple):
        return [_jsonable_model(item) for item in value]
    return value


def _decision_for_occurrence(
    analysis_result: WorkbenchAnalysisResult,
    occurrence: NormalizedOccurrence,
) -> PrioritizedFinding:
    decision = analysis_result.findings_by_cve.get(occurrence.cve_id)
    if decision is None:
        raise WorkbenchAnalysisError(f"Decision analysis did not produce {occurrence.cve_id}.")
    return decision


def _decision_priority(decision: PrioritizedFinding) -> FindingPriority:
    return FindingPriority(decision.priority_label.lower())


def _decision_status(decision: PrioritizedFinding) -> FindingStatus:
    if decision.priority_state == "Fixed":
        return FindingStatus.FIXED
    if decision.suppressed_by_vex:
        return FindingStatus.SUPPRESSED
    if decision.waived:
        return FindingStatus.ACCEPTED
    return FindingStatus.OPEN


def _finding_status_for_occurrence(
    decision: PrioritizedFinding,
    occurrence: NormalizedOccurrence,
) -> FindingStatus:
    vex_status = _occurrence_vex_status(occurrence)
    if vex_status == "fixed":
        return FindingStatus.FIXED
    if vex_status == "not_affected":
        return FindingStatus.SUPPRESSED
    if vex_status is None and decision.suppressed_by_vex:
        return FindingStatus.OPEN
    return _decision_status(decision)


def _suppressed_by_vex_for_occurrence(
    decision: PrioritizedFinding,
    occurrence: NormalizedOccurrence,
) -> bool:
    vex_status = _occurrence_vex_status(occurrence)
    if vex_status in {"fixed", "not_affected"}:
        return True
    if vex_status is None:
        return False
    return decision.suppressed_by_vex


def _occurrence_vex_status(occurrence: NormalizedOccurrence) -> str | None:
    return _string_evidence(occurrence.raw_evidence, "vex_status")


def _decision_provider_json(decision: PrioritizedFinding) -> dict[str, Any]:
    return decision.provider_evidence.model_dump() if decision.provider_evidence else {}


def _decision_cvss_vector(decision: PrioritizedFinding) -> str | None:
    if decision.provider_evidence is None:
        return None
    return decision.provider_evidence.nvd.cvss_vector


def _decision_cwe(decision: PrioritizedFinding) -> str | None:
    if decision.provider_evidence is None or not decision.provider_evidence.nvd.cwes:
        return None
    return ", ".join(decision.provider_evidence.nvd.cwes)


def _decision_cwes(decision: PrioritizedFinding) -> list[str]:
    if decision.provider_evidence is None:
        return []
    return list(decision.provider_evidence.nvd.cwes)


def _decision_published(decision: PrioritizedFinding) -> str | None:
    if decision.provider_evidence is None:
        return None
    return decision.provider_evidence.nvd.published


def _decision_modified(decision: PrioritizedFinding) -> str | None:
    if decision.provider_evidence is None:
        return None
    return decision.provider_evidence.nvd.last_modified


def _decision_data_quality_json(decision: PrioritizedFinding) -> dict[str, Any]:
    return {
        "flags": [item.model_dump() for item in decision.data_quality_flags],
        "confidence": decision.data_quality_confidence,
    }

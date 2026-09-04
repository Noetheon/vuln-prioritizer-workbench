"""Decision payload, status, and evidence helpers for Workbench imports."""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any

from app.decision_core.identity import FINDING_SCOPE_KEY_VERSION
from app.domain.asset_identity import normalize_asset_identity_value
from app.domain.engine.models import PrioritizedFinding
from app.domain.engine.services.contextualization import aggregate_provenance
from app.domain.import_asset_context import (
    asset_criticality_from_evidence,
    asset_environment_from_evidence,
    asset_exposure_from_evidence,
    input_occurrence_from_workbench_occurrence,
)
from app.domain.import_asset_context import string_evidence as _string_evidence
from app.importers.contracts import NormalizedOccurrence
from app.models import FindingPriority, FindingStatus
from app.services.analysis import WorkbenchAnalysisError, WorkbenchAnalysisResult

_UNANIMOUS_OCCURRENCE_SCOPE_FIELDS = (
    "source",
    "source_id",
    "source_record_id",
    "vex_status",
    "vex_match_type",
    "vex_source_path",
)


def _scoped_operational_score_for_occurrence(
    decision: PrioritizedFinding,
    occurrence: NormalizedOccurrence,
) -> tuple[int, list[str]]:
    """Return the final scope score without re-evaluating decision semantics."""
    _ = occurrence
    return decision.operational_score, list(decision.operational_score_reasons)


def _analysis_semantics_summary(
    *,
    occurrences: list[NormalizedOccurrence],
    finding_count: int,
    analysis_result: WorkbenchAnalysisResult | None = None,
) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "analysis_decision_scope": "finding_scope_first",
        "persistence_scope": "decision_graph_materialization",
        "occurrence_overlay_fields": [],
        "finding_dedup_key_version": FINDING_SCOPE_KEY_VERSION,
        "cve_count": len({occurrence.cve_id for occurrence in occurrences}),
        "occurrence_count": len(occurrences),
        "finding_count": finding_count,
        "same_cve_can_create_distinct_asset_findings": True,
    }
    if analysis_result is not None and analysis_result.decision_graph is not None:
        graph = analysis_result.decision_graph
        summary.update(
            {
                "decision_graph_schema_version": graph.schema_version,
                "normalized_input_sha256": graph.fingerprint.normalized_input_sha256,
                "policy_sha256": graph.fingerprint.policy_sha256,
                "shared_facts_sha256": graph.fingerprint.shared_facts_sha256,
                "replay_sha256": graph.fingerprint.replay_sha256,
            }
        )
    return summary


def _decision_payload_for_occurrence(
    decision: PrioritizedFinding,
    occurrence: NormalizedOccurrence,
    *,
    compact: bool = False,
    base_payload: dict[str, Any] | None = None,
    occurrence_scope: dict[str, Any] | None = None,
    scoped_score: tuple[int, list[str]] | None = None,
) -> dict[str, Any]:
    # Kept as accepted compatibility arguments for older internal callers. The
    # decision graph has already evaluated the final scope, so persistence must
    # never change its score, VEX state, remediation, or explanation.
    _ = occurrence, compact, base_payload, occurrence_scope, scoped_score
    return _canonical_decision_payload(decision)


def _analysis_evidence_for_occurrence(
    analysis_result: WorkbenchAnalysisResult,
    decision: PrioritizedFinding,
    occurrence: NormalizedOccurrence,
    *,
    priority_state: str | None = None,
    occurrence_scope: dict[str, Any] | None = None,
    operational_score: int | None = None,
) -> dict[str, Any]:
    occurrence_scope = occurrence_scope or _occurrence_scope_payload(occurrence)
    return {
        "decision_scope": "finding_scope_first",
        "priority_state": priority_state or decision.priority_state,
        "operational_score": (
            operational_score if operational_score is not None else decision.operational_score
        ),
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
    _ = occurrence
    return base_priority_state if base_priority_state is not None else decision.priority_state


def _occurrence_scope_payload(occurrence: NormalizedOccurrence) -> dict[str, Any]:
    raw_exposure = _string_evidence(occurrence.raw_evidence, "asset_exposure") or _string_evidence(
        occurrence.raw_evidence, "exposure"
    )
    raw_environment = _string_evidence(
        occurrence.raw_evidence, "asset_environment"
    ) or _string_evidence(occurrence.raw_evidence, "environment")
    raw_criticality = _string_evidence(
        occurrence.raw_evidence, "asset_criticality"
    ) or _string_evidence(occurrence.raw_evidence, "criticality")
    return {
        "source": occurrence.source,
        "source_id": _string_evidence(occurrence.raw_evidence, "source_id"),
        "source_record_id": _string_evidence(occurrence.raw_evidence, "source_record_id"),
        "component_name": occurrence.component_name,
        "component_version": occurrence.component_version,
        "purl": _string_evidence(occurrence.raw_evidence, "purl"),
        "package_type": _string_evidence(occurrence.raw_evidence, "package_type"),
        "target_kind": occurrence.target_kind,
        "target_ref": occurrence.target_ref,
        "asset_id": occurrence.asset_id,
        "asset_owner": _string_evidence(occurrence.raw_evidence, "owner"),
        "asset_business_service": _string_evidence(
            occurrence.raw_evidence,
            "business_service",
        ),
        "asset_exposure": (
            asset_exposure_from_evidence({"asset_exposure": raw_exposure}).value
            if raw_exposure
            else None
        ),
        "asset_environment": (
            asset_environment_from_evidence({"asset_environment": raw_environment}).value
            if raw_environment
            else None
        ),
        "asset_criticality": (
            asset_criticality_from_evidence({"asset_criticality": raw_criticality}).value
            if raw_criticality
            else None
        ),
        "vex_status": _occurrence_vex_status(occurrence),
        "vex_match_type": _string_evidence(occurrence.raw_evidence, "vex_match_type"),
        "vex_source_path": _string_evidence(occurrence.raw_evidence, "vex_source_path"),
    }


def _scope_projection_payload(
    decision: PrioritizedFinding,
    occurrences: Sequence[NormalizedOccurrence],
) -> dict[str, Any]:
    """Project one deterministic scope summary while retaining row evidence separately."""
    if not occurrences:
        raise ValueError("A finding scope projection requires at least one occurrence.")
    representative_index = min(
        range(len(occurrences)),
        key=lambda index: _stable_occurrence_sort_key(occurrences[index]),
    )
    scope_payloads = [_occurrence_scope_payload(occurrence) for occurrence in occurrences]
    payload = dict(scope_payloads[representative_index])
    for field_name in _UNANIMOUS_OCCURRENCE_SCOPE_FIELDS:
        payload[field_name] = _unanimous_scope_string(scope_payloads, field_name)
    payload["asset_id"] = _singular_present_asset_id(scope_payloads)
    core_occurrences = [
        input_occurrence_from_workbench_occurrence(occurrence) for occurrence in occurrences
    ]
    provenance = aggregate_provenance([decision.cve_id], core_occurrences)[decision.cve_id]
    payload.update(
        {
            "asset_owner": _canonical_scope_value(provenance.asset_owners),
            "asset_business_service": _canonical_scope_value(provenance.asset_business_services),
            "asset_exposure": _canonical_asset_exposure(provenance.highest_asset_exposure),
            "asset_environment": _canonical_asset_environment(provenance.asset_environments),
            "asset_criticality": _canonical_asset_criticality(provenance.highest_asset_criticality),
        }
    )
    return payload


def _unanimous_scope_string(
    scope_payloads: Sequence[dict[str, Any]],
    field_name: str,
) -> str | None:
    """Return a singular scope value only when every occurrence agrees exactly."""
    first_value = scope_payloads[0].get(field_name)
    if not isinstance(first_value, str):
        return None
    if any(payload.get(field_name) != first_value for payload in scope_payloads[1:]):
        return None
    return first_value


def _singular_present_asset_id(scope_payloads: Sequence[dict[str, Any]]) -> str | None:
    """Retain one explicit asset ID even when sibling evidence omits it."""
    values = {
        normalized
        for payload in scope_payloads
        if isinstance((value := payload.get("asset_id")), str)
        and (normalized := normalize_asset_identity_value(value))
    }
    return next(iter(values)) if len(values) == 1 else None


def _asset_projection_payload(
    occurrences: Sequence[NormalizedOccurrence],
) -> dict[str, Any]:
    """Aggregate one relational asset row independently of upload ordering."""
    if not occurrences:
        raise ValueError("An asset projection requires at least one occurrence.")
    core_occurrences = [
        input_occurrence_from_workbench_occurrence(occurrence) for occurrence in occurrences
    ]
    cve_ids = sorted({occurrence.cve_id for occurrence in core_occurrences})
    provenance_by_cve = aggregate_provenance(cve_ids, core_occurrences)
    provenances = list(provenance_by_cve.values())
    criticalities = [
        provenance.highest_asset_criticality
        for provenance in provenances
        if provenance.highest_asset_criticality
    ]
    exposures = [
        provenance.highest_asset_exposure
        for provenance in provenances
        if provenance.highest_asset_exposure
    ]
    environments = [
        environment for provenance in provenances for environment in provenance.asset_environments
    ]
    owners = [owner for provenance in provenances for owner in provenance.asset_owners]
    services = [
        service for provenance in provenances for service in provenance.asset_business_services
    ]
    target_refs = [
        occurrence.target_ref for occurrence in core_occurrences if occurrence.target_ref
    ]
    return {
        "target_ref": _canonical_scope_value(target_refs),
        "owner": _canonical_scope_value(owners),
        "business_service": _canonical_scope_value(services),
        "environment": _canonical_asset_environment(environments) or "unknown",
        "exposure": _highest_canonical_value(
            exposures,
            order={"internal": 1, "dmz": 2, "internet-facing": 3},
            canonicalizer=_canonical_asset_exposure,
        )
        or "unknown",
        "criticality": _highest_canonical_value(
            criticalities,
            order={"low": 1, "medium": 2, "high": 3, "critical": 4},
            canonicalizer=_canonical_asset_criticality,
        )
        or "unknown",
    }


def _stable_occurrence_sort_key(occurrence: NormalizedOccurrence) -> str:
    core_occurrence = input_occurrence_from_workbench_occurrence(occurrence)
    return json.dumps(
        core_occurrence.model_dump(mode="json"),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _canonical_scope_value(values: Sequence[str]) -> str | None:
    normalized = {value.strip() for value in values if value.strip()}
    return min(normalized, key=lambda value: (value.casefold(), value)) if normalized else None


def _canonical_vulnerability_source_id(
    occurrences: Sequence[NormalizedOccurrence],
) -> str | None:
    """Project a singular alias only when all observations agree on it."""
    source_ids = {
        _string_evidence(occurrence.raw_evidence, "source_id")
        or _string_evidence(occurrence.raw_evidence, "vulnerability_id")
        or occurrence.cve_id
        for occurrence in occurrences
    }
    return next(iter(source_ids)) if len(source_ids) == 1 else None


def _canonical_asset_criticality(value: str | None) -> str | None:
    if value is None:
        return None
    return asset_criticality_from_evidence({"asset_criticality": value}).value


def _canonical_asset_exposure(value: str | None) -> str | None:
    if value is None:
        return None
    return asset_exposure_from_evidence({"asset_exposure": value}).value


def _canonical_asset_environment(values: Sequence[str]) -> str | None:
    return _highest_canonical_value(
        values,
        order={"development": 1, "test": 2, "staging": 3, "production": 4},
        canonicalizer=lambda value: (
            asset_environment_from_evidence({"asset_environment": value}).value
        ),
    )


def _highest_canonical_value(
    values: Sequence[str],
    *,
    order: dict[str, int],
    canonicalizer: Any,
) -> str | None:
    canonical_values = {canonicalizer(value) for value in values}
    canonical_values.discard("unknown")
    if not canonical_values:
        return None
    return max(canonical_values, key=lambda value: (order.get(value, 0), value))


def _canonical_decision_payload(decision: PrioritizedFinding) -> dict[str, Any]:
    """Return one canonical semantic payload for normal and bulk persistence."""
    payload = decision.model_dump(mode="json", exclude={"provider_evidence"})
    provenance = payload.get("provenance")
    if isinstance(provenance, dict):
        # Occurrences have their own typed evidence collection. Keeping them in
        # the decision payload as well would duplicate the largest input block.
        provenance.pop("occurrences", None)
    return payload


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
    if analysis_result.decision_graph is not None:
        scoped = analysis_result.decision_graph.decision_for_occurrence(
            input_occurrence_from_workbench_occurrence(occurrence)
        )
        if scoped is None:
            raise WorkbenchAnalysisError(
                f"Decision graph did not produce the final finding scope for {occurrence.cve_id}."
            )
        return scoped.decision
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
    _ = occurrence
    return _decision_status(decision)


def _suppressed_by_vex_for_occurrence(
    decision: PrioritizedFinding,
    occurrence: NormalizedOccurrence,
) -> bool:
    _ = occurrence
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

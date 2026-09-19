"""
Pure adapters between immutable evaluation inputs and Ledger decision payloads.

The legacy adapter preserves historical v2 decisions that lack replay inputs.
It cannot promise a full replay and never manufactures a canonical input record.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from pydantic import ValidationError

from app.decision_core.contracts import (
    FindingDecisionEvidenceV2,
    OccurrenceEvidenceV2,
    OccurrenceScopeV2,
)
from app.decision_core.decision_graph import ScopeKey
from app.decision_core.evaluation import ScopeEvaluationInput, evaluate_scope
from app.decision_core.ledger import DecisionLedgerInvariantError
from app.domain.asset_identity import normalize_asset_identity_value
from app.domain.engine.inputs.parsers.common import (
    normalize_asset_criticality,
    normalize_asset_environment,
    normalize_asset_exposure,
)
from app.domain.engine.models import (
    FindingProvenance,
    InputOccurrence,
    PrioritizedFinding,
    ProviderEvidence,
)
from app.domain.engine.services.contextualization import (
    SUPPRESSED_VEX_STATUSES,
    aggregate_provenance,
    is_suppressed_by_vex,
    is_under_investigation,
)
from app.domain.engine.services.prioritization import PrioritizationService
from app.models import FindingStatus


def evaluate_evidence_payload(
    payload: dict[str, Any],
    *,
    inputs: ScopeEvaluationInput | None = None,
) -> tuple[dict[str, Any], PrioritizedFinding]:
    """Evaluate exact inputs and replace every decision field without I/O or a clock."""
    evidence = FindingDecisionEvidenceV2.model_validate(payload)
    actual = inputs if inputs is not None else evidence.evaluation_input
    if actual is None:
        raise DecisionLedgerInvariantError(
            "Historical evidence has no replayable evaluation inputs."
        )
    expected_scope = _projection_scope_sort_key(evidence)
    if actual.cve_id != evidence.cve_id or any(
        ScopeKey.from_occurrence(item).sort_key() != expected_scope for item in actual.observations
    ):
        raise DecisionLedgerInvariantError("Evaluation inputs changed the stored finding scope.")
    decision = evaluate_scope(actual)
    updated = _apply_recomputed_decision(payload, decision)
    updated["evaluation_input"] = actual.model_dump(mode="json")
    return FindingDecisionEvidenceV2.model_validate(updated).to_jsonable(), decision


def _stored_projection_decision(evidence: FindingDecisionEvidenceV2) -> PrioritizedFinding:
    """Rehydrate a complete current decision only when explicit inputs are unchanged."""
    raw = {
        key: value
        for key, value in evidence.priority_evidence.raw.items()
        if key in PrioritizedFinding.model_fields
    }
    if evidence.evaluation_input is not None:
        inputs = evidence.evaluation_input
        raw["provenance"] = aggregate_provenance([evidence.cve_id], inputs.observations)[
            evidence.cve_id
        ]
        raw["provider_evidence"] = inputs.provider_evidence
    raw["operational_rank"] = evidence.operational_rank
    return PrioritizedFinding.model_validate(raw)


def _recompute_projection_decision(payload: dict[str, Any]) -> PrioritizedFinding:
    """Rebuild score, priority state, reasons, and context guidance via the domain engine."""
    evidence = FindingDecisionEvidenceV2.model_validate(payload)
    if evidence.evaluation_input is not None:
        return evaluate_scope(evidence.evaluation_input)
    raw = deepcopy(evidence.priority_evidence.raw)
    raw.pop("waiver", None)
    raw.pop("explanation", None)
    raw.pop("decision_guidance", None)
    # Lifecycle-only metadata is retained in evidence but is not part of the
    # strict domain decision model.
    raw.pop("asset_context", None)
    input_occurrences = _projection_input_occurrences(evidence)
    provenance = aggregate_provenance([evidence.cve_id], input_occurrences)[evidence.cve_id]
    has_typed_vex_evidence = any(item.vex_status for item in input_occurrences)
    if not has_typed_vex_evidence and evidence.governance.vex_statuses:
        provenance = _with_compact_vex_provenance(
            provenance,
            evidence.governance.vex_statuses,
            stored_suppressed=evidence.suppressed_by_vex,
        )
    suppressed_by_vex = is_suppressed_by_vex(provenance)
    under_investigation = is_under_investigation(provenance)
    if not has_typed_vex_evidence:
        # Compact distributions can be partial, while the stored decision flags
        # are the reviewed aggregate outcome. Preserve a positive investigation
        # signal even when its row-level status is absent from the distribution.
        under_investigation = (
            under_investigation
            or evidence.under_investigation
            or evidence.governance.under_investigation
        )
    if not has_typed_vex_evidence and not evidence.governance.vex_statuses:
        # Older and compact projections can carry a reviewed VEX decision only
        # at the finding/governance level.  A waiver refresh must not silently
        # turn that evidence into an actionable finding merely because the
        # historical occurrence list is absent.
        suppressed_by_vex = evidence.suppressed_by_vex or evidence.governance.suppressed_by_vex
    raw["provenance"] = provenance.model_dump(mode="json")
    raw.update(
        {
            "cve_id": evidence.cve_id,
            "cvss_base_score": evidence.cvss_base_score,
            "epss": evidence.epss,
            "in_kev": evidence.in_kev,
            "attack_mapped": evidence.attack_mapped,
            "suppressed_by_vex": suppressed_by_vex,
            "under_investigation": under_investigation,
            "highest_asset_criticality": provenance.highest_asset_criticality,
            "asset_count": provenance.asset_count,
            "waived": evidence.waived,
            "priority_label": evidence.priority_evidence.priority_label,
            "priority_rank": evidence.priority_rank,
            "priority_state": evidence.priority_evidence.priority_state,
            "operational_rank": evidence.operational_rank,
            "operational_score": int(
                evidence.priority_evidence.operational_score or evidence.risk_score or 0
            ),
            "operational_score_reasons": list(evidence.priority_evidence.operational_score_reasons),
            "rationale": evidence.rationale
            or "Stored Workbench finding without raw rationale payload.",
            "recommended_action": evidence.recommended_action
            or "Review the finding with the asset owner.",
        }
    )
    provider_payload = evidence.provider.provider_evidence
    if provider_payload:
        try:
            raw["provider_evidence"] = ProviderEvidence.model_validate(provider_payload)
        except (TypeError, ValueError, ValidationError):
            raw.pop("provider_evidence", None)
    domain_payload = {
        key: value for key, value in raw.items() if key in PrioritizedFinding.model_fields
    }
    try:
        decision = PrioritizedFinding.model_validate(domain_payload)
    except (TypeError, ValueError, ValidationError) as exc:
        raise DecisionLedgerInvariantError(
            f"Current projection {evidence.finding_id} cannot be recomputed losslessly."
        ) from exc
    return PrioritizationService().assign_operational_ranks([decision])[0]


def _with_compact_vex_provenance(
    provenance: FindingProvenance,
    vex_statuses: dict[str, int],
    *,
    stored_suppressed: bool,
) -> FindingProvenance:
    """Restore aggregate VEX counts when compact evidence has no row details."""
    normalized_statuses: dict[str, int] = {}
    for status, count in vex_statuses.items():
        normalized_status = status.strip().lower()
        normalized_count = int(count)
        if normalized_status and normalized_count > 0:
            normalized_statuses[normalized_status] = (
                normalized_statuses.get(normalized_status, 0) + normalized_count
            )
    total = sum(normalized_statuses.values())
    if total == 0:
        return provenance
    known_suppressed = sum(
        count for status, count in normalized_statuses.items() if status in SUPPRESSED_VEX_STATUSES
    )
    known_active = total - known_suppressed
    if stored_suppressed and known_active == 0:
        occurrence_count = max(provenance.occurrence_count, total, 1)
        active_occurrence_count = 0
        suppressed_occurrence_count = occurrence_count
    else:
        # vex_statuses contains only annotated rows. A stored non-suppressed
        # decision proves at least one active row may be absent from the
        # compact distribution, so partial counts cannot imply suppression.
        active_occurrence_count = max(
            provenance.active_occurrence_count,
            known_active,
            1,
        )
        occurrence_count = max(
            provenance.occurrence_count,
            total,
            known_suppressed + active_occurrence_count,
        )
        suppressed_occurrence_count = min(
            known_suppressed,
            occurrence_count - active_occurrence_count,
        )
    return provenance.model_copy(
        update={
            "occurrence_count": occurrence_count,
            "active_occurrence_count": active_occurrence_count,
            "suppressed_occurrence_count": suppressed_occurrence_count,
            "vex_statuses": normalized_statuses,
        }
    )


def _projection_input_occurrences(
    evidence: FindingDecisionEvidenceV2,
) -> list[InputOccurrence]:
    """Restore observations using the same context aliases as the import boundary."""
    if evidence.occurrences:
        items = [
            _input_occurrence_from_evidence(item, cve_id=evidence.cve_id)
            for item in evidence.occurrences
        ]
    elif evidence.occurrence_scope.model_dump(exclude_none=True):
        items = [_input_occurrence_from_scope(evidence.occurrence_scope, cve_id=evidence.cve_id)]
    else:
        return []
    return [
        item.model_copy(
            update={
                "asset_environment": normalize_asset_environment(
                    item.asset_environment, warnings=[], row_number=0
                ),
                "asset_exposure": normalize_asset_exposure(
                    item.asset_exposure, warnings=[], row_number=0
                ),
                "asset_criticality": normalize_asset_criticality(
                    item.asset_criticality, warnings=[], row_number=0
                ),
            }
        )
        for item in items
    ]


def _projection_scope_sort_key(
    evidence: FindingDecisionEvidenceV2,
) -> tuple[str, tuple[bool, str], str, tuple[bool, str]]:
    """
    Restore the canonical final scope used by Decision Graph ranking.

    New v2 projections carry one explicit occurrence scope.  For older v2
    payloads, all retained occurrences must still agree on one final scope;
    otherwise reranking would invent an order for ambiguous historical data.
    """
    dedup_scope_keys = {
        ScopeKey(
            cve_id=parts.cve_id,
            component_identity=parts.component_identity,
            target_kind=parts.target_kind,
            target_ref=parts.target_ref,
        )
        for item in evidence.occurrences
        if (parts := item.dedup.parts) is not None
        and parts.cve_id is not None
        and parts.target_kind is not None
    }
    if dedup_scope_keys:
        if len(dedup_scope_keys) != 1:
            raise DecisionLedgerInvariantError(
                f"Current projection {evidence.finding_id} contains multiple dedup scopes."
            )
        return next(iter(dedup_scope_keys)).sort_key()

    occurrences = _projection_input_occurrences(evidence)
    if not occurrences:
        occurrences = [InputOccurrence(cve_id=evidence.cve_id)]
    scope_keys = {ScopeKey.from_occurrence(item) for item in occurrences}
    if len(scope_keys) != 1:
        raise DecisionLedgerInvariantError(
            f"Current projection {evidence.finding_id} contains multiple final scopes."
        )
    return next(iter(scope_keys)).sort_key()


def _input_occurrence_from_scope(
    scope: OccurrenceScopeV2,
    *,
    cve_id: str,
) -> InputOccurrence:
    """Restore the evidence-safe subset available in a compact v2 scope."""
    return InputOccurrence(
        cve_id=cve_id,
        source_format=scope.source or "current-projection-scope",
        source_id=scope.source_id,
        source_record_id=scope.source_record_id,
        component_name=scope.component_name,
        component_version=scope.component_version,
        purl=scope.purl,
        package_type=scope.package_type,
        target_kind=scope.target_kind or "generic",
        target_ref=scope.target_ref,
        asset_id=scope.asset_id,
        asset_criticality=scope.asset_criticality,
        asset_exposure=scope.asset_exposure,
        asset_environment=scope.asset_environment,
        asset_owner=scope.asset_owner,
        asset_business_service=scope.asset_business_service,
        vex_status=scope.vex_status,
        vex_match_type=scope.vex_match_type,
        vex_source_path=scope.vex_source_path,
    )


def _input_occurrence_from_evidence(
    item: OccurrenceEvidenceV2,
    *,
    cve_id: str,
) -> InputOccurrence:
    """Restore typed occurrence context omitted from the compact raw decision payload."""
    import_evidence = item.import_evidence
    fix_versions = list(item.fix_versions or [])
    if not fix_versions and item.fix_version:
        fix_versions = [item.fix_version]
    asset_id = item.asset_id or _string_value(import_evidence.get("asset_id"))
    if asset_id is not None:
        asset_id = normalize_asset_identity_value(asset_id) or None
    asset_criticality = (
        item.asset_criticality
        or _string_value(import_evidence.get("asset_criticality"))
        or _string_value(import_evidence.get("criticality"))
    )
    asset_exposure = (
        item.asset_exposure
        or _string_value(import_evidence.get("asset_exposure"))
        or _string_value(import_evidence.get("exposure"))
    )
    asset_environment = (
        item.asset_environment
        or _string_value(import_evidence.get("asset_environment"))
        or _string_value(import_evidence.get("environment"))
    )
    return InputOccurrence(
        cve_id=cve_id,
        source_format=item.source_format or item.source or "unknown",
        source_id=item.source_id,
        source_record_id=item.source_record_id,
        component_name=item.component_name,
        component_version=item.component_version,
        purl=item.purl,
        package_type=item.package_type or _string_value(import_evidence.get("package_type")),
        file_path=_string_value(import_evidence.get("file_path")),
        dependency_path=_string_value(import_evidence.get("dependency_path")),
        fix_versions=fix_versions,
        raw_severity=item.raw_severity,
        target_kind=item.target_kind
        or _string_value(import_evidence.get("target_kind"))
        or "generic",
        target_ref=item.target_ref,
        asset_id=asset_id,
        asset_criticality=asset_criticality,
        asset_exposure=asset_exposure,
        asset_environment=asset_environment,
        asset_owner=item.asset_owner
        or _string_value(import_evidence.get("asset_owner"))
        or _string_value(import_evidence.get("owner")),
        asset_business_service=item.asset_business_service
        or _string_value(import_evidence.get("asset_business_service"))
        or _string_value(import_evidence.get("business_service")),
        asset_match_rule_id=_string_value(import_evidence.get("asset_match_rule_id")),
        asset_match_row=_int_value(import_evidence.get("asset_match_row")),
        asset_match_mode=_string_value(import_evidence.get("asset_match_mode")),
        asset_match_pattern=_string_value(import_evidence.get("asset_match_pattern")),
        asset_match_precedence=_int_value(import_evidence.get("asset_match_precedence")),
        asset_match_candidate_count=(
            _int_value(import_evidence.get("asset_match_candidate_count")) or 0
        ),
        vex_status=item.vex_status,
        vex_justification=item.vex_justification,
        vex_action_statement=item.vex_action_statement,
        vex_match_type=item.vex_match_type,
        vex_source_format=item.vex_source_format,
        vex_source_record_id=item.vex_source_record_id,
        vex_source_path=item.vex_source_path,
        vex_candidate_count=item.vex_candidate_count,
    )


def _apply_recomputed_decision(
    payload: dict[str, Any],
    decision: PrioritizedFinding,
) -> dict[str, Any]:
    """Project a recomputed domain decision into mutable v2 current evidence."""
    updated = deepcopy(payload)
    priority_evidence = _object_value(updated.get("priority_evidence"))
    governance = _object_value(updated.get("governance"))
    remediation = _object_value(updated.get("remediation"))
    decision_payload = decision.model_dump(mode="json", exclude={"provider_evidence"})
    provenance = _object_value(decision_payload.get("provenance"))
    provenance.pop("occurrences", None)
    decision_payload["provenance"] = provenance
    if governance.get("waiver"):
        decision_payload["waiver"] = deepcopy(governance["waiver"])
    lifecycle_asset_context = _object_value(
        _object_value(priority_evidence.get("raw")).get("asset_context")
    )
    if lifecycle_asset_context:
        decision_payload["asset_context"] = deepcopy(lifecycle_asset_context)

    lifecycle_flags = [
        flag
        for flag in priority_evidence.get("data_quality_flags", [])
        if isinstance(flag, dict) and flag.get("code") == "asset_context_rescore_needed"
    ]
    priority_evidence.update(
        {
            "priority_label": decision.priority_label,
            "priority_rank": decision.priority_rank,
            "priority_state": decision.priority_state,
            "operational_score": decision.operational_score,
            "operational_score_reasons": list(decision.operational_score_reasons),
            "explanation": decision.explanation.model_dump(mode="json")
            if decision.explanation is not None
            else {},
            "rationale": decision.rationale,
            "data_quality_confidence": (
                priority_evidence.get("data_quality_confidence")
                if lifecycle_flags
                else decision.data_quality_confidence
            ),
            "data_quality_flags": [
                flag.model_dump(mode="json") for flag in decision.data_quality_flags
            ]
            + lifecycle_flags,
            "raw": decision_payload,
        }
    )
    guidance = decision.decision_guidance
    if guidance is not None:
        guidance_payload = guidance.model_dump(mode="json")
        remediation.update(
            {
                "recommended_action": decision.recommended_action,
                "decision_statement": guidance.decision_statement,
                "recommendation": guidance.recommendation,
                "recommendation_label": guidance.recommendation_label,
                "business_impact": guidance.business_impact.text,
                "sla": guidance.sla.model_dump(mode="json"),
                "raw": guidance_payload,
            }
        )
    governance["waived"] = decision.waived
    governance["suppressed_by_vex"] = decision.suppressed_by_vex
    governance["under_investigation"] = decision.under_investigation
    governance["vex_statuses"] = dict(decision.provenance.vex_statuses)
    provider = _object_value(updated.get("provider"))
    if decision.provider_evidence is not None:
        provider["provider_evidence"] = decision.provider_evidence.model_dump(mode="json")
    updated.update(
        {
            "provider": provider,
            "status": _status_for_recomputed_decision(
                decision,
                current_status=_finding_status_value(updated.get("status")),
                previously_waived=bool(payload.get("waived")),
            ),
            "priority": decision.priority_label.lower(),
            "priority_rank": decision.priority_rank,
            "in_kev": decision.in_kev,
            "epss": decision.epss,
            "cvss_base_score": decision.cvss_base_score,
            "attack_mapped": decision.attack_mapped,
            "risk_score": float(decision.operational_score),
            "operational_rank": decision.operational_rank,
            "waived": decision.waived,
            "suppressed_by_vex": decision.suppressed_by_vex,
            "under_investigation": decision.under_investigation,
            "rationale": decision.rationale,
            "recommended_action": decision.recommended_action,
            "priority_evidence": priority_evidence,
            "governance": governance,
            "remediation": remediation,
        }
    )
    return FindingDecisionEvidenceV2.model_validate(updated).to_jsonable()


def _status_for_recomputed_decision(
    decision: PrioritizedFinding,
    *,
    current_status: str,
    previously_waived: bool = False,
) -> str:
    """Keep workflow state unless terminal governance determines the public status."""
    if decision.priority_state == "Fixed":
        return FindingStatus.FIXED.value
    if decision.priority_state == "Suppressed" or decision.suppressed_by_vex:
        return FindingStatus.SUPPRESSED.value
    if decision.priority_state == "Accepted" or decision.waived:
        return FindingStatus.ACCEPTED.value
    if previously_waived and current_status == FindingStatus.ACCEPTED.value:
        return FindingStatus.OPEN.value
    return current_status


def _object_value(value: object) -> dict[str, Any]:
    """Object value function."""
    return value if isinstance(value, dict) else {}


def _finding_status_value(status: object) -> str:
    """Return the persisted status string for enum and SQL-loaded string values."""
    if isinstance(status, FindingStatus):
        return status.value
    return str(status or FindingStatus.OPEN.value)


def _string_value(value: object) -> str | None:
    return value if isinstance(value, str) and value.strip() else None


def _int_value(value: object) -> int | None:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    return None

"""Asset context projection and rescore helpers."""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import datetime
from typing import Any

from app.models import (
    Asset,
    AssetCriticality,
    AssetEnvironment,
    AssetExposure,
    Finding,
)
from vuln_prioritizer.inputs.loader import AssetContextRecord
from vuln_prioritizer.models import (
    ContextPolicyProfile,
    FindingProvenance,
    InputOccurrence,
    PrioritizedFinding,
)


def _with_rescore_flag(
    payload: dict[str, Any],
    *,
    asset_id: uuid.UUID,
    changed_fields: Sequence[str],
    changed_at: datetime,
) -> dict[str, Any]:
    """With rescore flag function."""
    data_quality = dict(payload or {})
    raw_flags = data_quality.get("flags")
    flags = (
        [dict(flag) for flag in raw_flags if isinstance(flag, dict)]
        if isinstance(raw_flags, list)
        else []
    )
    flags = [flag for flag in flags if flag.get("code") != "asset_context_rescore_needed"]
    flags.append(
        {
            "source": "asset_context",
            "code": "asset_context_rescore_needed",
            "severity": "warning",
            "message": (
                "Asset context changed; rerun analysis or review the operational "
                "score before relying on this priority."
            ),
            "asset_id": str(asset_id),
            "changed_fields": list(changed_fields),
            "changed_at": changed_at.isoformat(),
        }
    )
    data_quality["flags"] = flags
    data_quality["confidence"] = "medium"
    return data_quality


def _records_by_asset_key(records: Sequence[AssetContextRecord]) -> list[AssetContextRecord]:
    """Records by asset key function."""
    deduped: dict[str, AssetContextRecord] = {}
    for record in records:
        deduped[record.asset_id] = record
    return list(deduped.values())


def _asset_snapshot(asset: Asset | None) -> dict[str, Any]:
    """Asset snapshot function."""
    if asset is None:
        return {}
    return {
        "asset_key": asset.asset_key,
        "target_ref": asset.target_ref,
        "owner": asset.owner,
        "business_service": asset.business_service,
        "environment": str(asset.environment),
        "exposure": str(asset.exposure),
        "criticality": str(asset.criticality),
    }


def _changed_asset_fields(
    before: dict[str, Any],
    after: dict[str, Any],
) -> list[str]:
    """Changed asset fields function."""
    return sorted(field for field, previous in before.items() if after.get(field) != previous)


def _asset_environment(value: str | None) -> AssetEnvironment:
    """Asset environment function."""
    normalized = (value or "").strip().lower().replace("_", "-")
    return {
        "prod": AssetEnvironment.PRODUCTION,
        "production": AssetEnvironment.PRODUCTION,
        "stage": AssetEnvironment.STAGING,
        "staging": AssetEnvironment.STAGING,
        "dev": AssetEnvironment.DEVELOPMENT,
        "development": AssetEnvironment.DEVELOPMENT,
        "test": AssetEnvironment.TEST,
        "testing": AssetEnvironment.TEST,
        "unknown": AssetEnvironment.UNKNOWN,
    }.get(normalized, AssetEnvironment.UNKNOWN)


def _asset_exposure(value: str | None) -> AssetExposure:
    """Asset exposure function."""
    normalized = (value or "").strip().lower().replace("_", "-")
    return {
        "external": AssetExposure.INTERNET_FACING,
        "internet": AssetExposure.INTERNET_FACING,
        "internet-facing": AssetExposure.INTERNET_FACING,
        "public": AssetExposure.INTERNET_FACING,
        "internal": AssetExposure.INTERNAL,
        "private": AssetExposure.PRIVATE,
        "unknown": AssetExposure.UNKNOWN,
    }.get(normalized, AssetExposure.UNKNOWN)


def _asset_criticality(value: str | None) -> AssetCriticality:
    """Asset criticality function."""
    normalized = (value or "").strip().lower().replace("_", "-")
    return {
        "critical": AssetCriticality.CRITICAL,
        "high": AssetCriticality.HIGH,
        "medium": AssetCriticality.MEDIUM,
        "med": AssetCriticality.MEDIUM,
        "low": AssetCriticality.LOW,
        "unknown": AssetCriticality.UNKNOWN,
    }.get(normalized, AssetCriticality.UNKNOWN)


def _with_rescore_evidence(
    payload: dict[str, Any],
    *,
    asset_id: uuid.UUID,
    changed_fields: Sequence[str],
    changed_at: datetime,
) -> dict[str, Any]:
    """With rescore evidence function."""
    evidence = dict(payload or {})
    evidence["asset_context"] = {
        "rescore_needed": True,
        "asset_id": str(asset_id),
        "changed_fields": list(changed_fields),
        "changed_at": changed_at.isoformat(),
    }
    return evidence


def _finding_as_prioritized(finding: Finding) -> PrioritizedFinding:
    """Finding as prioritized function."""
    payload = dict(finding.explanation_json or {})
    if payload.get("cve_id") == finding.cve_id:
        try:
            return PrioritizedFinding.model_validate(payload)
        except ValueError:
            pass
    return PrioritizedFinding(
        cve_id=finding.cve_id,
        description=getattr(finding.vulnerability, "description", None),
        cvss_base_score=finding.cvss_base_score,
        epss=finding.epss,
        in_kev=finding.in_kev,
        attack_mapped=finding.attack_mapped,
        suppressed_by_vex=finding.suppressed_by_vex,
        under_investigation=finding.under_investigation,
        waived=finding.waived,
        priority_label=_priority_label(str(finding.priority)),
        priority_rank=finding.priority_rank,
        priority_state=_priority_label(str(finding.priority)),
        operational_rank=finding.operational_rank,
        operational_score=int(finding.risk_score or 0),
        rationale=finding.rationale or "Stored Workbench finding without raw rationale payload.",
        recommended_action=finding.recommended_action or "Review the finding with the asset owner.",
        provenance=_provenance_from_finding(finding),
    )


def _with_current_asset_context(finding: PrioritizedFinding, asset: Asset) -> PrioritizedFinding:
    """With current asset context function."""
    target_ref = asset.target_ref or asset.asset_key
    occurrence_updates = {
        "target_ref": target_ref,
        "asset_id": asset.asset_key,
        "asset_criticality": asset.criticality,
        "asset_exposure": asset.exposure,
        "asset_environment": asset.environment,
        "asset_owner": asset.owner,
        "asset_business_service": asset.business_service,
    }
    occurrences = [
        occurrence.model_copy(update=occurrence_updates)
        for occurrence in finding.provenance.occurrences
    ]
    if not occurrences:
        occurrences = [
            InputOccurrence(
                cve_id=finding.cve_id,
                source_format="workbench-asset-context",
                target_ref=target_ref,
                asset_id=asset.asset_key,
                asset_criticality=asset.criticality,
                asset_exposure=asset.exposure,
                asset_environment=asset.environment,
                asset_owner=asset.owner,
                asset_business_service=asset.business_service,
            )
        ]
    provenance = finding.provenance.model_copy(
        update={
            "occurrences": occurrences,
            "targets": _value_list(target_ref),
            "asset_ids": _value_list(asset.asset_key),
            "highest_asset_criticality": asset.criticality,
            "highest_asset_exposure": asset.exposure,
            "asset_environments": _value_list(asset.environment),
            "asset_owners": _value_list(asset.owner),
            "asset_business_services": _value_list(asset.business_service),
            "asset_count": 1,
        }
    )
    context_summary, context_recommendation = ContextPolicyProfile().describe(provenance)
    return finding.model_copy(
        update={
            "provenance": provenance,
            "context_summary": context_summary,
            "context_recommendation": context_recommendation,
            "highest_asset_criticality": asset.criticality,
            "asset_count": 1,
        }
    )


def _provenance_from_finding(finding: Finding) -> FindingProvenance:
    """Provenance from finding function."""
    asset = finding.asset
    if asset is None:
        return FindingProvenance()
    target_ref = asset.target_ref or asset.asset_key
    occurrence = InputOccurrence(
        cve_id=finding.cve_id,
        source_format="workbench-asset-context",
        target_ref=target_ref,
        asset_id=asset.asset_key,
        asset_criticality=asset.criticality,
        asset_exposure=asset.exposure,
        asset_environment=asset.environment,
        asset_owner=asset.owner,
        asset_business_service=asset.business_service,
    )
    return FindingProvenance(
        occurrence_count=1,
        active_occurrence_count=1,
        source_formats=["workbench-asset-context"],
        targets=_value_list(target_ref),
        asset_ids=_value_list(asset.asset_key),
        highest_asset_criticality=asset.criticality,
        highest_asset_exposure=asset.exposure,
        asset_environments=_value_list(asset.environment),
        asset_owners=_value_list(asset.owner),
        asset_business_services=_value_list(asset.business_service),
        asset_count=1,
        occurrences=[occurrence],
    )


def _recalculated_explanation_json(
    payload: dict[str, Any],
    *,
    prioritized: PrioritizedFinding,
    priority_state: str,
    score: int,
    reasons: list[str],
) -> dict[str, Any]:
    """Recalculated explanation json function."""
    updated = dict(payload or {})
    updated["provenance"] = prioritized.provenance.model_dump()
    updated["context_summary"] = prioritized.context_summary
    updated["context_recommendation"] = prioritized.context_recommendation
    updated["highest_asset_criticality"] = prioritized.highest_asset_criticality
    updated["asset_count"] = prioritized.asset_count
    updated["priority_state"] = priority_state
    updated["operational_score"] = score
    updated["operational_score_reasons"] = reasons
    explanation = dict(updated.get("explanation") or {})
    explanation["score_inputs"] = {
        **dict(explanation.get("score_inputs") or {}),
        "asset_context_recalculated": True,
        "operational_score": score,
    }
    updated["explanation"] = explanation
    return updated


def _recalculated_evidence_json(
    payload: dict[str, Any],
    *,
    asset: Asset,
    recalculated_at: datetime,
    score: int,
    reasons: list[str],
) -> dict[str, Any]:
    """Recalculated evidence json function."""
    evidence = dict(payload or {})
    evidence["asset_context"] = {
        "rescore_needed": False,
        "asset_id": str(asset.id),
        "asset_key": asset.asset_key,
        "recalculated_at": recalculated_at.isoformat(),
        "operational_score": score,
        "operational_score_reasons": list(reasons),
    }
    return evidence


def _without_rescore_flag(
    payload: dict[str, Any],
    *,
    flags_key: str,
    confidence_key: str,
) -> tuple[dict[str, Any], int]:
    """Without rescore flag function."""
    updated = dict(payload or {})
    raw_flags = updated.get(flags_key)
    flags = (
        [dict(flag) for flag in raw_flags if isinstance(flag, dict)]
        if isinstance(raw_flags, list)
        else []
    )
    kept = [flag for flag in flags if flag.get("code") != "asset_context_rescore_needed"]
    removed = len(flags) - len(kept)
    if flags or flags_key in updated:
        updated[flags_key] = kept
    if removed and not kept and updated.get(confidence_key) == "medium":
        updated[confidence_key] = "high"
    return updated, removed


def _priority_label(value: str) -> str:
    """Priority label function."""
    normalized = value.split(".", maxsplit=1)[-1].strip().lower()
    return {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
    }.get(normalized, "Low")


def _value_list(value: Any) -> list[str]:
    """Value list function."""
    if value is None:
        return []
    text = str(value).strip()
    return [text] if text else []


__all__ = [
    "_with_rescore_flag",
    "_records_by_asset_key",
    "_asset_snapshot",
    "_changed_asset_fields",
    "_asset_environment",
    "_asset_exposure",
    "_asset_criticality",
    "_with_rescore_evidence",
    "_finding_as_prioritized",
    "_with_current_asset_context",
    "_provenance_from_finding",
    "_recalculated_explanation_json",
    "_recalculated_evidence_json",
    "_without_rescore_flag",
    "_priority_label",
    "_value_list",
]

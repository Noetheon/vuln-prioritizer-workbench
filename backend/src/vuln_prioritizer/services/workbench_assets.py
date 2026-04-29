"""Asset context import and recalculation helpers for the Workbench."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from vuln_prioritizer.explanations import build_priority_explanation
from vuln_prioritizer.inputs.loader import AssetContextRecord, load_asset_context_file
from vuln_prioritizer.models import ContextPolicyProfile, PrioritizedFinding, PriorityPolicy
from vuln_prioritizer.scoring import build_operational_score, determine_priority_state
from vuln_prioritizer.services.decision_guidance import DecisionGuidanceService
from vuln_prioritizer.utils import iso_utc_now

ASSET_CONTEXT_FIELDS = (
    "asset_id",
    "target_ref",
    "owner",
    "business_service",
    "environment",
    "exposure",
    "criticality",
)
RESCORE_FLAG_CODE = "asset_context_rescore_needed"


@dataclass(frozen=True, slots=True)
class AssetContextImportResult:
    """Summary for an asset context CSV import."""

    imported_assets: int
    created_assets: int
    updated_assets: int
    unchanged_assets: int
    rescore_needed_findings: int
    total_rows: int
    loaded_rows: int
    skipped_rows: int
    warnings: tuple[str, ...]
    asset_ids: tuple[str, ...]

    def as_payload(self, *, project_id: str) -> dict[str, Any]:
        return {
            "project_id": project_id,
            "imported_assets": self.imported_assets,
            "created_assets": self.created_assets,
            "updated_assets": self.updated_assets,
            "unchanged_assets": self.unchanged_assets,
            "rescore_needed_findings": self.rescore_needed_findings,
            "total_rows": self.total_rows,
            "loaded_rows": self.loaded_rows,
            "skipped_rows": self.skipped_rows,
            "warnings": list(self.warnings),
            "asset_ids": list(self.asset_ids),
        }


@dataclass(frozen=True, slots=True)
class AssetRecalculationResult:
    """Summary for an asset context recalculation."""

    recalculated_findings: int
    cleared_rescore_flags: int
    operational_scores: tuple[int, ...]

    def as_payload(self, *, asset: Any) -> dict[str, Any]:
        return {
            "asset_id": asset.id,
            "asset_key": asset.asset_id,
            "recalculated_findings": self.recalculated_findings,
            "cleared_rescore_flags": self.cleared_rescore_flags,
            "operational_scores": list(self.operational_scores),
        }


def filter_assets_by_context(
    assets: list[Any],
    *,
    owner: str | None = None,
    service: str | None = None,
) -> list[Any]:
    """Apply case-insensitive owner/service substring filters to asset rows."""

    owner_filter = _normalized_filter(owner)
    service_filter = _normalized_filter(service)
    filtered: list[Any] = []
    for asset in assets:
        if owner_filter and owner_filter not in (asset.owner or "").casefold():
            continue
        if service_filter and service_filter not in (asset.business_service or "").casefold():
            continue
        filtered.append(asset)
    return filtered


def asset_rescore_needed(asset: Any) -> bool:
    """Return whether any linked finding still carries a stale asset-context flag."""

    return any(_finding_has_rescore_flag(finding) for finding in getattr(asset, "findings", []))


def import_asset_context_csv(
    repo: Any,
    *,
    project_id: str,
    asset_context_path: Path,
) -> AssetContextImportResult:
    """Import an asset-context CSV as editable Workbench asset rows."""

    catalog, diagnostics = load_asset_context_file(asset_context_path, return_diagnostics=True)
    records = _records_by_asset_id(tuple(rule.asset_record for rule in catalog.rules))
    created_assets = 0
    updated_assets = 0
    unchanged_assets = 0
    rescore_needed_findings = 0
    imported_asset_ids: list[str] = []

    for record in records:
        existing = repo.get_project_asset_by_asset_id(project_id, record.asset_id)
        previous = _asset_snapshot(existing) if existing is not None else None
        asset = repo.upsert_asset(
            project_id=project_id,
            asset_id=record.asset_id,
            target_ref=record.target_ref,
            owner=record.owner,
            business_service=record.business_service,
            environment=record.environment,
            exposure=record.exposure,
            criticality=record.criticality,
        )
        imported_asset_ids.append(asset.asset_id)
        if previous is None:
            created_assets += 1
            continue

        changed_fields = _changed_asset_fields(previous, _asset_snapshot(asset))
        if changed_fields:
            updated_assets += 1
            rescore_needed_findings += mark_asset_findings_rescore_needed(
                asset,
                changed_fields=changed_fields,
            )
        else:
            unchanged_assets += 1

    return AssetContextImportResult(
        imported_assets=len(records),
        created_assets=created_assets,
        updated_assets=updated_assets,
        unchanged_assets=unchanged_assets,
        rescore_needed_findings=rescore_needed_findings,
        total_rows=diagnostics.total_rows,
        loaded_rows=diagnostics.loaded_rows,
        skipped_rows=diagnostics.skipped_rows,
        warnings=diagnostics.warnings,
        asset_ids=tuple(imported_asset_ids),
    )


def mark_asset_findings_rescore_needed(
    asset: Any,
    *,
    changed_fields: list[str],
) -> int:
    """Mark findings linked to an edited asset as needing explicit recalculation."""

    changed = sorted(set(changed_fields))
    if not changed:
        return 0
    changed_at = iso_utc_now()
    marked = 0
    for finding in getattr(asset, "findings", []):
        flag = {
            "source": "asset_context",
            "code": RESCORE_FLAG_CODE,
            "severity": "warning",
            "message": (
                "Asset context changed for "
                f"{asset.asset_id}; use the asset recalculation action before relying on "
                f"the operational score. Changed fields: {', '.join(changed)}. "
                f"Changed at: {changed_at}."
            ),
        }
        finding.finding_json = _with_rescore_flag(finding.finding_json, flag)
        finding.explanation_json = _with_rescore_flag(finding.explanation_json, flag)
        marked += 1
    return marked


def recalculate_asset_findings(
    asset: Any,
    *,
    policy: PriorityPolicy | None = None,
) -> AssetRecalculationResult:
    """Re-score findings linked to an asset with the current editable asset context."""

    active_policy = policy or PriorityPolicy()
    guidance_service = DecisionGuidanceService()
    recalculated = 0
    cleared_flags = 0
    scores: list[int] = []
    for finding in getattr(asset, "findings", []):
        prioritized = _prioritized_finding_from_db(finding)
        prioritized = _with_current_asset_context(prioritized, asset)
        prioritized, removed_flags = _without_rescore_flags(prioritized)
        score, reasons = build_operational_score(prioritized, active_policy)
        scored = prioritized.model_copy(
            update={
                "priority_state": determine_priority_state(prioritized).value,
                "operational_score": score,
                "operational_score_reasons": reasons,
                "operational_rank": finding.operational_rank,
            }
        )
        scored = scored.model_copy(
            update={"explanation": build_priority_explanation(scored, active_policy)}
        )
        scored = scored.model_copy(update={"decision_guidance": guidance_service.build(scored)})
        payload = _without_rescore_flag_payload(scored.model_dump())
        finding.finding_json = payload
        finding.explanation_json = payload
        finding.risk_score = float(score)
        finding.rationale = scored.rationale
        finding.recommended_action = scored.recommended_action
        recalculated += 1
        cleared_flags += removed_flags
        scores.append(score)

    return AssetRecalculationResult(
        recalculated_findings=recalculated,
        cleared_rescore_flags=cleared_flags,
        operational_scores=tuple(scores),
    )


def changed_asset_fields(before: dict[str, Any], after: dict[str, Any]) -> list[str]:
    """Return asset-context fields that changed between two snapshots."""

    return _changed_asset_fields(before, after)


def asset_snapshot(asset: Any) -> dict[str, Any]:
    """Return the editable asset-context snapshot used for audits and recalculation."""

    return _asset_snapshot(asset)


def _normalized_filter(value: str | None) -> str:
    return (value or "").strip().casefold()


def _records_by_asset_id(records: tuple[AssetContextRecord, ...]) -> list[AssetContextRecord]:
    selected: dict[str, AssetContextRecord] = {}
    for record in records:
        current = selected.get(record.asset_id)
        if current is None or _record_sort_key(record) >= _record_sort_key(current):
            selected[record.asset_id] = record
    return [selected[key] for key in sorted(selected)]


def _record_sort_key(record: AssetContextRecord) -> tuple[int, int]:
    return (record.precedence, record.row_number or 0)


def _asset_snapshot(asset: Any) -> dict[str, Any]:
    if asset is None:
        return {}
    return {field: getattr(asset, field) for field in ASSET_CONTEXT_FIELDS}


def _changed_asset_fields(before: dict[str, Any], after: dict[str, Any]) -> list[str]:
    return [field for field in ASSET_CONTEXT_FIELDS if before.get(field) != after.get(field)]


def _with_rescore_flag(payload: dict[str, Any] | None, flag: dict[str, Any]) -> dict[str, Any]:
    updated = dict(payload or {})
    flags = _payload_flags(updated)
    flags = [item for item in flags if item.get("code") != RESCORE_FLAG_CODE]
    flags.append(flag)
    updated["data_quality_flags"] = flags
    updated["data_quality_confidence"] = "medium"
    return updated


def _without_rescore_flags(finding: PrioritizedFinding) -> tuple[PrioritizedFinding, int]:
    flags = list(finding.data_quality_flags)
    kept = [flag for flag in flags if getattr(flag, "code", None) != RESCORE_FLAG_CODE]
    return finding.model_copy(update={"data_quality_flags": kept}), len(flags) - len(kept)


def _without_rescore_flag_payload(payload: dict[str, Any]) -> dict[str, Any]:
    updated = dict(payload)
    flags = _payload_flags(updated)
    kept = [item for item in flags if item.get("code") != RESCORE_FLAG_CODE]
    updated["data_quality_flags"] = kept
    if not kept and updated.get("data_quality_confidence") == "medium":
        updated["data_quality_confidence"] = "high"
    return updated


def _payload_flags(payload: dict[str, Any]) -> list[dict[str, Any]]:
    raw_flags = payload.get("data_quality_flags")
    if not isinstance(raw_flags, list):
        return []
    return [dict(flag) for flag in raw_flags if isinstance(flag, dict)]


def _finding_has_rescore_flag(finding: Any) -> bool:
    payload = finding.finding_json if isinstance(finding.finding_json, dict) else {}
    return any(flag.get("code") == RESCORE_FLAG_CODE for flag in _payload_flags(payload))


def _prioritized_finding_from_db(finding: Any) -> PrioritizedFinding:
    payload = finding.finding_json if isinstance(finding.finding_json, dict) else {}
    if payload:
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
        priority_label=finding.priority,
        priority_rank=finding.priority_rank,
        priority_state=finding.priority,
        operational_rank=finding.operational_rank,
        operational_score=int(finding.risk_score or 0),
        rationale=finding.rationale or "Stored Workbench finding without raw rationale payload.",
        recommended_action=finding.recommended_action or "Review the finding with the asset owner.",
    )


def _with_current_asset_context(finding: PrioritizedFinding, asset: Any) -> PrioritizedFinding:
    occurrence_updates = {
        "target_ref": asset.target_ref,
        "asset_id": asset.asset_id,
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
    provenance = finding.provenance.model_copy(
        update={
            "occurrences": occurrences,
            "targets": _value_list(asset.target_ref),
            "asset_ids": _value_list(asset.asset_id),
            "highest_asset_criticality": asset.criticality,
            "highest_asset_exposure": asset.exposure,
            "asset_environments": _value_list(asset.environment),
            "asset_owners": _value_list(asset.owner),
            "asset_business_services": _value_list(asset.business_service),
            "asset_count": 1 if asset.asset_id else 0,
        }
    )
    context_summary, context_recommendation = ContextPolicyProfile().describe(provenance)
    return finding.model_copy(
        update={
            "provenance": provenance,
            "context_summary": context_summary,
            "context_recommendation": context_recommendation,
            "highest_asset_criticality": asset.criticality,
            "asset_count": 1 if asset.asset_id else 0,
        }
    )


def _value_list(value: str | None) -> list[str]:
    return [value] if value else []

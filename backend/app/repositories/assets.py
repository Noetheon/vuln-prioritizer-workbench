"""Asset repository for template Workbench persistence."""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import datetime
from typing import Any

from sqlmodel import Session, col, select

from app.models import (
    Asset,
    AssetCreate,
    AssetCriticality,
    AssetEnvironment,
    AssetExposure,
    AssetUpdate,
    Finding,
)
from app.models.base import get_datetime_utc
from vuln_prioritizer.inputs.loader import AssetContextCatalog, AssetContextRecord
from vuln_prioritizer.models import (
    ContextPolicyProfile,
    FindingProvenance,
    InputOccurrence,
    PrioritizedFinding,
    PriorityPolicy,
)
from vuln_prioritizer.scoring import build_operational_score, determine_priority_state


class AssetRepository:
    """Asset persistence helpers."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def upsert_asset(
        self,
        *,
        project_id: uuid.UUID,
        asset_key: str,
        name: str | None = None,
        target_ref: str | None = None,
        owner: str | None = None,
        business_service: str | None = None,
        environment: AssetEnvironment | str = AssetEnvironment.UNKNOWN,
        exposure: AssetExposure | str = AssetExposure.UNKNOWN,
        criticality: AssetCriticality | str = AssetCriticality.UNKNOWN,
        flush: bool = True,
    ) -> Asset:
        """Create or update a project-scoped asset by business dedup key."""
        statement = select(Asset).where(
            Asset.project_id == project_id,
            Asset.asset_key == asset_key,
        )
        asset = self.session.exec(statement).first()
        if asset is None:
            asset = Asset(project_id=project_id, asset_key=asset_key, name=name or asset_key)
            self.session.add(asset)
        elif name is not None:
            asset.name = name

        asset.target_ref = target_ref
        asset.owner = owner
        asset.business_service = business_service
        asset.environment = AssetEnvironment(environment)
        asset.exposure = AssetExposure(exposure)
        asset.criticality = AssetCriticality(criticality)
        if flush:
            self.session.flush()
        return asset

    def create_asset(self, *, project_id: uuid.UUID, asset_in: AssetCreate) -> Asset:
        """Create or update a project asset from API payload."""
        return self.upsert_asset(
            project_id=project_id,
            asset_key=asset_in.asset_key,
            name=asset_in.name,
            target_ref=asset_in.target_ref,
            owner=asset_in.owner,
            business_service=asset_in.business_service,
            environment=asset_in.environment,
            exposure=asset_in.exposure,
            criticality=asset_in.criticality,
        )

    def import_asset_context_catalog(
        self,
        *,
        project_id: uuid.UUID,
        catalog: AssetContextCatalog,
    ) -> dict[str, Any]:
        """Import asset-context records into editable project asset rows."""
        records = _records_by_asset_key([rule.asset_record for rule in catalog.rules])
        created_assets = 0
        updated_assets = 0
        unchanged_assets = 0
        rescore_needed_findings = 0
        asset_keys: list[str] = []

        for record in records:
            existing = self.get_project_asset_by_key(project_id, record.asset_id)
            previous = _asset_snapshot(existing) if existing is not None else None
            asset = self.upsert_asset(
                project_id=project_id,
                asset_key=record.asset_id,
                name=record.asset_id,
                target_ref=record.target_ref,
                owner=record.owner,
                business_service=record.business_service,
                environment=_asset_environment(record.environment),
                exposure=_asset_exposure(record.exposure),
                criticality=_asset_criticality(record.criticality),
            )
            asset_keys.append(asset.asset_key)
            if previous is None:
                created_assets += 1
                continue

            changed_fields = _changed_asset_fields(previous, _asset_snapshot(asset))
            if changed_fields:
                updated_assets += 1
                rescore_needed_findings += self.mark_asset_findings_rescore_needed(
                    asset_id=asset.id,
                    changed_fields=changed_fields,
                )
            else:
                unchanged_assets += 1

        diagnostics = catalog.diagnostics
        return {
            "project_id": project_id,
            "imported_assets": len(records),
            "created_assets": created_assets,
            "updated_assets": updated_assets,
            "unchanged_assets": unchanged_assets,
            "rescore_needed_findings": rescore_needed_findings,
            "total_rows": diagnostics.total_rows,
            "loaded_rows": diagnostics.loaded_rows,
            "skipped_rows": diagnostics.skipped_rows,
            "warnings": list(diagnostics.warnings),
            "asset_keys": asset_keys,
        }

    def get_asset(self, asset_id: uuid.UUID) -> Asset | None:
        """Return an asset by primary key."""
        return self.session.get(Asset, asset_id)

    def get_project_asset_by_key(self, project_id: uuid.UUID, asset_key: str) -> Asset | None:
        """Return a project-scoped asset by business key."""
        statement = select(Asset).where(
            Asset.project_id == project_id,
            Asset.asset_key == asset_key,
        )
        return self.session.exec(statement).first()

    def list_project_assets(
        self,
        project_id: uuid.UUID,
        *,
        owner: str | None = None,
        service: str | None = None,
    ) -> list[Asset]:
        """Return project assets ordered for stable API output."""
        filters: list[Any] = [Asset.project_id == project_id]
        if owner and owner.strip():
            filters.append(col(Asset.owner).ilike(f"%{owner.strip()}%"))
        if service and service.strip():
            filters.append(col(Asset.business_service).ilike(f"%{service.strip()}%"))
        statement = select(Asset).where(*filters).order_by(Asset.asset_key)
        return list(self.session.exec(statement).all())

    def update_asset(self, asset: Asset, asset_in: AssetUpdate) -> Asset:
        """Update mutable asset fields without committing the transaction."""
        update_data = asset_in.model_dump(exclude_unset=True)
        asset.sqlmodel_update(update_data)
        asset.updated_at = get_datetime_utc()
        self.session.add(asset)
        self.session.flush()
        return asset

    def mark_asset_findings_rescore_needed(
        self,
        *,
        asset_id: uuid.UUID,
        changed_fields: Sequence[str],
        changed_at: datetime | None = None,
    ) -> int:
        """Mark findings linked to an edited asset for explicit re-score review."""
        timestamp = changed_at or get_datetime_utc()
        changed = sorted(set(changed_fields))
        statement = select(Finding).where(Finding.asset_id == asset_id)
        findings = list(self.session.exec(statement).all())
        for finding in findings:
            finding.data_quality_json = _with_rescore_flag(
                finding.data_quality_json,
                asset_id=asset_id,
                changed_fields=changed,
                changed_at=timestamp,
            )
            finding.evidence_json = _with_rescore_evidence(
                finding.evidence_json,
                asset_id=asset_id,
                changed_fields=changed,
                changed_at=timestamp,
            )
            finding.updated_at = timestamp
            self.session.add(finding)
        self.session.flush()
        return len(findings)

    def recalculate_asset_findings(self, asset: Asset) -> dict[str, Any]:
        """Recalculate linked finding operational scores from current asset context."""
        timestamp = get_datetime_utc()
        statement = select(Finding).where(Finding.asset_id == asset.id)
        findings = list(self.session.exec(statement).all())
        cleared_flags = 0
        scores: list[int] = []
        for finding in findings:
            prioritized = _finding_as_prioritized(finding)
            prioritized = _with_current_asset_context(prioritized, asset)
            score, reasons = build_operational_score(prioritized, PriorityPolicy())
            priority_state = determine_priority_state(prioritized).value
            explanation_json = _recalculated_explanation_json(
                finding.explanation_json,
                prioritized=prioritized,
                priority_state=priority_state,
                score=score,
                reasons=reasons,
            )
            data_quality_json, removed_from_data_quality = _without_rescore_flag(
                finding.data_quality_json,
                flags_key="flags",
                confidence_key="confidence",
            )
            explanation_json, removed_from_explanation = _without_rescore_flag(
                explanation_json,
                flags_key="data_quality_flags",
                confidence_key="data_quality_confidence",
            )
            evidence_json = _recalculated_evidence_json(
                finding.evidence_json,
                asset=asset,
                recalculated_at=timestamp,
                score=score,
                reasons=reasons,
            )
            finding.risk_score = float(score)
            finding.explanation_json = explanation_json
            finding.data_quality_json = data_quality_json
            finding.evidence_json = evidence_json
            finding.updated_at = timestamp
            self.session.add(finding)
            cleared_flags += removed_from_data_quality + removed_from_explanation
            scores.append(score)
        self.session.flush()
        return {
            "asset_id": asset.id,
            "asset_key": asset.asset_key,
            "recalculated_findings": len(findings),
            "cleared_rescore_flags": cleared_flags,
            "operational_scores": scores,
            "rescore_needed": False,
        }


def _with_rescore_flag(
    payload: dict[str, Any],
    *,
    asset_id: uuid.UUID,
    changed_fields: Sequence[str],
    changed_at: datetime,
) -> dict[str, Any]:
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
    deduped: dict[str, AssetContextRecord] = {}
    for record in records:
        deduped[record.asset_id] = record
    return list(deduped.values())


def _asset_snapshot(asset: Asset | None) -> dict[str, Any]:
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
    return sorted(field for field, previous in before.items() if after.get(field) != previous)


def _asset_environment(value: str | None) -> AssetEnvironment:
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
    evidence = dict(payload or {})
    evidence["asset_context"] = {
        "rescore_needed": True,
        "asset_id": str(asset_id),
        "changed_fields": list(changed_fields),
        "changed_at": changed_at.isoformat(),
    }
    return evidence


def _finding_as_prioritized(finding: Finding) -> PrioritizedFinding:
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
        rationale=finding.rationale or "Stored template finding without raw rationale payload.",
        recommended_action=finding.recommended_action or "Review the finding with the asset owner.",
        provenance=_provenance_from_finding(finding),
    )


def _with_current_asset_context(finding: PrioritizedFinding, asset: Asset) -> PrioritizedFinding:
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
                source_format="template-asset-context",
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
    asset = finding.asset
    if asset is None:
        return FindingProvenance()
    target_ref = asset.target_ref or asset.asset_key
    occurrence = InputOccurrence(
        cve_id=finding.cve_id,
        source_format="template-asset-context",
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
        source_formats=["template-asset-context"],
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
    normalized = value.split(".", maxsplit=1)[-1].strip().lower()
    return {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
    }.get(normalized, "Low")


def _value_list(value: Any) -> list[str]:
    if value is None:
        return []
    text = str(value).strip()
    return [text] if text else []

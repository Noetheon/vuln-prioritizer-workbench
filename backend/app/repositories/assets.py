"""Asset repository for Workbench persistence."""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import datetime
from typing import Any

from sqlmodel import Session, col, func, select

from app.decision_core.contracts import FindingDecisionEvidenceV2
from app.domain.asset_context_projection import (
    _asset_criticality,
    _asset_environment,
    _asset_exposure,
    _asset_snapshot,
    _changed_asset_fields,
    _records_by_asset_key,
)
from app.domain.engine.inputs.loader import AssetContextCatalog
from app.models import (
    Asset,
    AssetCreate,
    AssetCriticality,
    AssetEnvironment,
    AssetExposure,
    AssetUpdate,
    Finding,
    FindingDecisionEvidence,
)
from app.models.base import get_datetime_utc

ASSET_CONTEXT_RESCORE_FLAG = "asset_context_rescore_needed"


class AssetRepository:
    """Asset persistence helpers."""

    def __init__(self, session: Session) -> None:
        """Initialize a new instance of AssetRepository."""
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
        limit: int | None = None,
        offset: int = 0,
    ) -> list[Asset]:
        """Return project assets ordered for stable API output."""
        filters: list[Any] = [Asset.project_id == project_id]
        if owner and owner.strip():
            filters.append(col(Asset.owner).ilike(f"%{owner.strip()}%"))
        if service and service.strip():
            filters.append(col(Asset.business_service).ilike(f"%{service.strip()}%"))
        statement = select(Asset).where(*filters).order_by(Asset.asset_key).offset(offset)
        if limit is not None:
            statement = statement.limit(limit)
        return list(self.session.exec(statement).all())

    def list_project_assets_page(
        self,
        project_id: uuid.UUID,
        *,
        owner: str | None = None,
        service: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[list[Asset], int]:
        """Return a bounded asset page and total count."""
        filters: list[Any] = [Asset.project_id == project_id]
        if owner and owner.strip():
            filters.append(col(Asset.owner).ilike(f"%{owner.strip()}%"))
        if service and service.strip():
            filters.append(col(Asset.business_service).ilike(f"%{service.strip()}%"))
        count_statement = select(func.count()).select_from(Asset).where(*filters)
        count = int(self.session.exec(count_statement).one())
        assets = self.list_project_assets(
            project_id,
            owner=owner,
            service=service,
            limit=limit,
            offset=offset,
        )
        return assets, count

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
            record = self._latest_finding_evidence_record(finding.id)
            if record is not None:
                record.payload_json = _mark_decision_evidence_rescore_needed(
                    record.payload_json,
                    asset_id=asset_id,
                    changed_fields=changed,
                    changed_at=timestamp,
                )
                record.updated_at = timestamp
                self.session.add(record)
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
            finding.updated_at = timestamp
            self.session.add(finding)
            record = self._latest_finding_evidence_record(finding.id)
            operational_score = 0
            if record is not None:
                updated_payload, cleared = _clear_decision_evidence_rescore_needed(
                    record.payload_json,
                    asset=asset,
                    recalculated_at=timestamp,
                )
                record.payload_json = updated_payload
                record.updated_at = timestamp
                self.session.add(record)
                cleared_flags += cleared
                operational_score = int(
                    float(_decision_payload(updated_payload).get("risk_score") or 0)
                )
            scores.append(operational_score)
        self.session.flush()
        return {
            "asset_id": asset.id,
            "asset_key": asset.asset_key,
            "recalculated_findings": len(findings),
            "cleared_rescore_flags": cleared_flags,
            "operational_scores": scores,
            "rescore_needed": False,
        }

    def finding_rescore_needed(self, finding: Finding) -> bool:
        """Return whether the latest v2 finding evidence is marked for re-score."""
        record = self._latest_finding_evidence_record(finding.id)
        return record is not None and _decision_evidence_rescore_needed(record.payload_json)

    def _latest_finding_evidence_record(
        self,
        finding_id: uuid.UUID,
    ) -> FindingDecisionEvidence | None:
        return self.session.exec(
            select(FindingDecisionEvidence)
            .where(FindingDecisionEvidence.finding_id == finding_id)
            .order_by(col(FindingDecisionEvidence.created_at).desc())
        ).first()


def _mark_decision_evidence_rescore_needed(
    payload: dict[str, Any],
    *,
    asset_id: uuid.UUID,
    changed_fields: Sequence[str],
    changed_at: datetime,
) -> dict[str, Any]:
    candidate = _decision_payload(payload)
    priority_evidence = _object_value(candidate.get("priority_evidence"))
    flags = _flag_items(priority_evidence.get("data_quality_flags"))
    flags = [flag for flag in flags if flag.get("code") != ASSET_CONTEXT_RESCORE_FLAG]
    flags.append(
        {
            "source": "asset_context",
            "code": ASSET_CONTEXT_RESCORE_FLAG,
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
    priority_evidence["data_quality_flags"] = flags
    priority_evidence["data_quality_confidence"] = "medium"
    candidate["priority_evidence"] = priority_evidence
    return FindingDecisionEvidenceV2.model_validate(candidate).to_jsonable()


def _clear_decision_evidence_rescore_needed(
    payload: dict[str, Any],
    *,
    asset: Asset,
    recalculated_at: datetime,
) -> tuple[dict[str, Any], int]:
    candidate = _decision_payload(payload)
    priority_evidence = _object_value(candidate.get("priority_evidence"))
    flags = _flag_items(priority_evidence.get("data_quality_flags"))
    kept = [flag for flag in flags if flag.get("code") != ASSET_CONTEXT_RESCORE_FLAG]
    cleared = len(flags) - len(kept)
    priority_evidence["data_quality_flags"] = kept
    priority_evidence["raw"] = _with_asset_rescore_metadata(
        _object_value(priority_evidence.get("raw")),
        asset=asset,
        recalculated_at=recalculated_at,
    )
    candidate["priority_evidence"] = priority_evidence
    candidate["risk_score"] = float(candidate.get("risk_score") or 0)
    return FindingDecisionEvidenceV2.model_validate(candidate).to_jsonable(), cleared


def _decision_evidence_rescore_needed(payload: dict[str, Any]) -> bool:
    priority_evidence = _object_value(_object_value(payload).get("priority_evidence"))
    return any(
        flag.get("code") == ASSET_CONTEXT_RESCORE_FLAG
        for flag in _flag_items(priority_evidence.get("data_quality_flags"))
    )


def _with_asset_rescore_metadata(
    raw: dict[str, Any],
    *,
    asset: Asset,
    recalculated_at: datetime,
) -> dict[str, Any]:
    updated = dict(raw)
    asset_context = _object_value(updated.get("asset_context"))
    asset_context.update(
        {
            "asset_id": str(asset.id),
            "asset_key": asset.asset_key,
            "rescore_needed": False,
            "recalculated_at": recalculated_at.isoformat(),
        }
    )
    updated["asset_context"] = asset_context
    return updated


def _decision_payload(payload: dict[str, Any]) -> dict[str, Any]:
    return dict(_object_value(payload))


def _object_value(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def _flag_items(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [dict(item) for item in value if isinstance(item, dict)]

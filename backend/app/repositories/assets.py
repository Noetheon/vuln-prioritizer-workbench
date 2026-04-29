"""Asset repository for template Workbench persistence."""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import datetime
from typing import Any

from sqlmodel import Session, select

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

    def get_asset(self, asset_id: uuid.UUID) -> Asset | None:
        """Return an asset by primary key."""
        return self.session.get(Asset, asset_id)

    def list_project_assets(self, project_id: uuid.UUID) -> list[Asset]:
        """Return project assets ordered for stable API output."""
        statement = select(Asset).where(Asset.project_id == project_id).order_by(Asset.asset_key)
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

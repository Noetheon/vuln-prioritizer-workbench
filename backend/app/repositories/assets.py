"""Asset repository for template Workbench persistence."""

from __future__ import annotations

import uuid

from sqlmodel import Session, select

from app.models import (
    Asset,
    AssetCreate,
    AssetCriticality,
    AssetEnvironment,
    AssetExposure,
    AssetUpdate,
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

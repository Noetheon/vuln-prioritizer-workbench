"""Asset repository for template Workbench persistence."""

from __future__ import annotations

import uuid

from sqlmodel import Session, select

from app.models import Asset, AssetCriticality, AssetEnvironment, AssetExposure


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

    def get_asset(self, asset_id: uuid.UUID) -> Asset | None:
        """Return an asset by primary key."""
        return self.session.get(Asset, asset_id)

    def list_project_assets(self, project_id: uuid.UUID) -> list[Asset]:
        """Return project assets ordered for stable API output."""
        statement = select(Asset).where(Asset.project_id == project_id).order_by(Asset.asset_key)
        return list(self.session.exec(statement).all())

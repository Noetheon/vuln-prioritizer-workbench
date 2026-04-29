"""Asset and waiver persistence helpers for Workbench repositories."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from vuln_prioritizer.db.models import Asset, Waiver


class AssetWaiverRepositoryMixin:
    """Asset and waiver persistence methods."""

    session: Session

    def upsert_asset(
        self,
        *,
        project_id: str,
        asset_id: str,
        target_ref: str | None = None,
        owner: str | None = None,
        business_service: str | None = None,
        environment: str | None = None,
        exposure: str | None = None,
        criticality: str | None = None,
    ) -> Asset:
        asset = self.session.scalar(
            select(Asset).where(Asset.project_id == project_id, Asset.asset_id == asset_id)
        )
        if asset is None:
            asset = Asset(project_id=project_id, asset_id=asset_id)
            self.session.add(asset)
        asset.target_ref = target_ref
        asset.owner = owner
        asset.business_service = business_service
        asset.environment = environment
        asset.exposure = exposure
        asset.criticality = criticality
        self.session.flush()
        return asset

    def list_project_assets(self, project_id: str) -> list[Asset]:
        statement = select(Asset).where(Asset.project_id == project_id).order_by(Asset.asset_id)
        return list(self.session.scalars(statement))

    def get_asset(self, asset_id: str) -> Asset | None:
        return self.session.get(Asset, asset_id)

    def update_asset(
        self,
        asset: Asset,
        *,
        asset_id: str | None = None,
        target_ref: str | None = None,
        owner: str | None = None,
        business_service: str | None = None,
        environment: str | None = None,
        exposure: str | None = None,
        criticality: str | None = None,
    ) -> Asset:
        if asset_id is not None:
            asset.asset_id = asset_id
        asset.target_ref = target_ref
        asset.owner = owner
        asset.business_service = business_service
        asset.environment = environment
        asset.exposure = exposure
        asset.criticality = criticality
        self.session.flush()
        return asset

    def create_waiver(
        self,
        *,
        project_id: str,
        owner: str,
        reason: str,
        expires_on: str,
        cve_id: str | None = None,
        finding_id: str | None = None,
        asset_id: str | None = None,
        component_name: str | None = None,
        component_version: str | None = None,
        service: str | None = None,
        review_on: str | None = None,
        approval_ref: str | None = None,
        ticket_url: str | None = None,
    ) -> Waiver:
        waiver = Waiver(
            project_id=project_id,
            owner=owner,
            reason=reason,
            expires_on=expires_on,
            cve_id=cve_id,
            finding_id=finding_id,
            asset_id=asset_id,
            component_name=component_name,
            component_version=component_version,
            service=service,
            review_on=review_on,
            approval_ref=approval_ref,
            ticket_url=ticket_url,
        )
        self.session.add(waiver)
        self.session.flush()
        return waiver

    def update_waiver(
        self,
        waiver: Waiver,
        *,
        owner: str,
        reason: str,
        expires_on: str,
        cve_id: str | None = None,
        finding_id: str | None = None,
        asset_id: str | None = None,
        component_name: str | None = None,
        component_version: str | None = None,
        service: str | None = None,
        review_on: str | None = None,
        approval_ref: str | None = None,
        ticket_url: str | None = None,
    ) -> Waiver:
        waiver.owner = owner
        waiver.reason = reason
        waiver.expires_on = expires_on
        waiver.cve_id = cve_id
        waiver.finding_id = finding_id
        waiver.asset_id = asset_id
        waiver.component_name = component_name
        waiver.component_version = component_version
        waiver.service = service
        waiver.review_on = review_on
        waiver.approval_ref = approval_ref
        waiver.ticket_url = ticket_url
        self.session.flush()
        return waiver

    def get_waiver(self, waiver_id: str) -> Waiver | None:
        return self.session.get(Waiver, waiver_id)

    def list_project_waivers(self, project_id: str) -> list[Waiver]:
        statement = (
            select(Waiver)
            .where(Waiver.project_id == project_id)
            .order_by(Waiver.expires_on, Waiver.created_at)
        )
        return list(self.session.scalars(statement))

    def delete_waiver(self, waiver: Waiver) -> None:
        self.session.delete(waiver)
        self.session.flush()

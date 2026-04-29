"""Asset API routes for the Workbench domain."""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, HTTPException

from app.api.deps import CurrentUser, SessionDep
from app.api.routes.workbench_access import require_visible_project
from app.models import Asset, AssetCreate, AssetPublic, AssetsPublic, AssetUpdate
from app.repositories import AssetRepository

router = APIRouter(tags=["assets"])

ASSET_CONTEXT_FIELDS = {
    "asset_key",
    "target_ref",
    "owner",
    "business_service",
    "environment",
    "exposure",
    "criticality",
}


@router.get("/projects/{project_id}/assets/", response_model=AssetsPublic)
def read_project_assets(
    project_id: uuid.UUID,
    session: SessionDep,
    current_user: CurrentUser,
) -> AssetsPublic:
    """List assets for a visible project."""
    require_visible_project(session, current_user, project_id)
    assets = AssetRepository(session).list_project_assets(project_id)
    return AssetsPublic(
        data=[_asset_public(asset) for asset in assets],
        count=len(assets),
    )


@router.post("/projects/{project_id}/assets/", response_model=AssetPublic)
def create_project_asset(
    *,
    project_id: uuid.UUID,
    session: SessionDep,
    current_user: CurrentUser,
    asset_in: AssetCreate,
) -> AssetPublic:
    """Create or upsert an asset for a visible project."""
    require_visible_project(session, current_user, project_id)
    asset = AssetRepository(session).create_asset(project_id=project_id, asset_in=asset_in)
    session.commit()
    session.refresh(asset)
    return _asset_public(asset)


@router.patch("/assets/{asset_id}", response_model=AssetPublic)
def update_asset(
    *,
    asset_id: uuid.UUID,
    session: SessionDep,
    current_user: CurrentUser,
    asset_in: AssetUpdate,
) -> AssetPublic:
    """Update an asset if its project is visible."""
    repository = AssetRepository(session)
    asset = repository.get_asset(asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    require_visible_project(session, current_user, asset.project_id)
    before_context = _asset_context(asset)
    updated = repository.update_asset(asset, asset_in)
    after_context = _asset_context(updated)
    changed_fields = [
        field for field, previous in before_context.items() if after_context.get(field) != previous
    ]
    if changed_fields:
        repository.mark_asset_findings_rescore_needed(
            asset_id=updated.id,
            changed_fields=changed_fields,
        )
    session.commit()
    session.refresh(updated)
    return _asset_public(updated)


def _asset_public(asset: Asset) -> AssetPublic:
    """Return asset DTO with lightweight finding context for the Assets page."""
    return AssetPublic.model_validate(asset).model_copy(
        update={
            "finding_count": len(asset.findings),
            "rescore_needed": any(_finding_rescore_needed(finding) for finding in asset.findings),
        }
    )


def _asset_context(asset: Asset) -> dict[str, Any]:
    """Return mutable asset context fields that affect operational scoring."""
    return {field: getattr(asset, field) for field in ASSET_CONTEXT_FIELDS}


def _finding_rescore_needed(finding: Any) -> bool:
    data_quality = getattr(finding, "data_quality_json", {}) or {}
    if not isinstance(data_quality, dict):
        return False
    flags = data_quality.get("flags")
    return isinstance(flags, list) and any(
        isinstance(flag, dict) and flag.get("code") == "asset_context_rescore_needed"
        for flag in flags
    )

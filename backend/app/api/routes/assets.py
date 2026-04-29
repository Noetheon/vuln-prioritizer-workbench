"""Asset API routes for the Workbench domain."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, HTTPException

from app.api.deps import CurrentUser, SessionDep
from app.api.routes.workbench_access import require_visible_project
from app.models import Asset, AssetCreate, AssetPublic, AssetsPublic, AssetUpdate
from app.repositories import AssetRepository

router = APIRouter(tags=["assets"])


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
        data=[AssetPublic.model_validate(asset) for asset in assets],
        count=len(assets),
    )


@router.post("/projects/{project_id}/assets/", response_model=AssetPublic)
def create_project_asset(
    *,
    project_id: uuid.UUID,
    session: SessionDep,
    current_user: CurrentUser,
    asset_in: AssetCreate,
) -> Asset:
    """Create or upsert an asset for a visible project."""
    require_visible_project(session, current_user, project_id)
    asset = AssetRepository(session).create_asset(project_id=project_id, asset_in=asset_in)
    session.commit()
    session.refresh(asset)
    return asset


@router.patch("/assets/{asset_id}", response_model=AssetPublic)
def update_asset(
    *,
    asset_id: uuid.UUID,
    session: SessionDep,
    current_user: CurrentUser,
    asset_in: AssetUpdate,
) -> Asset:
    """Update an asset if its project is visible."""
    repository = AssetRepository(session)
    asset = repository.get_asset(asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    require_visible_project(session, current_user, asset.project_id)
    updated = repository.update_asset(asset, asset_in)
    session.commit()
    session.refresh(updated)
    return updated

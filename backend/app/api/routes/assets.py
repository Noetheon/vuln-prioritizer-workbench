"""Asset API routes for the Workbench domain."""

from __future__ import annotations

import uuid
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from fastapi import APIRouter, File, HTTPException, Query, Request, UploadFile

from app.api.deps import LocalActor, SessionDep
from app.api.routes.workbench_access import require_project
from app.core.app_state import workbench_settings
from app.models import (
    Asset,
    AssetContextImportPublic,
    AssetCreate,
    AssetPublic,
    AssetRecalculatePublic,
    AssetsPublic,
    AssetUpdate,
)
from app.repositories import AssetRepository, WaiverRepository
from app.services.audit import record_audit_event
from vuln_prioritizer.inputs.loader import load_asset_context_file

router = APIRouter(tags=["assets"])

ASSET_CONTEXT_FIELDS = (
    "asset_key",
    "target_ref",
    "owner",
    "business_service",
    "environment",
    "exposure",
    "criticality",
)
WAIVER_MATCH_CONTEXT_FIELDS = {"asset_key", "business_service"}


@router.get("/projects/{project_id}/assets/", response_model=AssetsPublic)
def read_project_assets(
    project_id: uuid.UUID,
    session: SessionDep,
    local_actor: LocalActor,
    owner: str | None = Query(default=None, max_length=200),
    service: str | None = Query(default=None, max_length=200),
) -> AssetsPublic:
    """List assets for a visible project."""
    require_project(session, project_id)
    assets = AssetRepository(session).list_project_assets(
        project_id,
        owner=owner,
        service=service,
    )
    return AssetsPublic(
        data=[_asset_public(asset) for asset in assets],
        count=len(assets),
    )


@router.post("/projects/{project_id}/assets/", response_model=AssetPublic)
def create_project_asset(
    *,
    project_id: uuid.UUID,
    session: SessionDep,
    local_actor: LocalActor,
    asset_in: AssetCreate,
) -> AssetPublic:
    """Create or upsert an asset for a visible project."""
    require_project(session, project_id)
    repository = AssetRepository(session)
    existing = repository.get_project_asset_by_key(project_id, asset_in.asset_key)
    before_context = _asset_context(existing) if existing is not None else None
    asset = repository.create_asset(project_id=project_id, asset_in=asset_in)
    changed_fields = (
        [
            field
            for field, previous in before_context.items()
            if _asset_context(asset).get(field) != previous
        ]
        if before_context is not None
        else []
    )
    if changed_fields:
        repository.mark_asset_findings_rescore_needed(
            asset_id=asset.id,
            changed_fields=changed_fields,
        )
    if WAIVER_MATCH_CONTEXT_FIELDS.intersection(changed_fields):
        WaiverRepository(session).sync_project_waivers(project_id)
    record_audit_event(
        session,
        action="asset.create",
        resource_type="asset",
        resource_id=asset.id,
        actor=local_actor,
        project_id=project_id,
        detail={"asset_key": asset.asset_key, "name": asset.name, "changed_fields": changed_fields},
    )
    session.commit()
    session.refresh(asset)
    return _asset_public(asset)


@router.post("/projects/{project_id}/assets/import", response_model=AssetContextImportPublic)
async def import_project_assets(
    *,
    project_id: uuid.UUID,
    request: Request,
    session: SessionDep,
    local_actor: LocalActor,
    asset_context_file: UploadFile | None = File(None),
) -> AssetContextImportPublic:
    """Import asset-context CSV rows into editable assets for a visible project."""
    require_project(session, project_id)
    if asset_context_file is None or not asset_context_file.filename:
        raise HTTPException(status_code=422, detail="Asset context CSV file is required.")
    _validate_asset_context_upload(asset_context_file)
    active_settings = workbench_settings(request)
    content = await asset_context_file.read(active_settings.max_upload_bytes + 1)
    if len(content) > active_settings.max_upload_bytes:
        raise HTTPException(status_code=413, detail="Upload exceeds configured limit.")
    if not content:
        raise HTTPException(status_code=422, detail="Asset context CSV file is required.")

    try:
        with TemporaryDirectory(prefix="asset-context-import-") as temporary_dir:
            asset_context_path = Path(temporary_dir) / "asset-context.csv"
            asset_context_path.write_bytes(content)
            catalog = load_asset_context_file(asset_context_path)
    except ValueError as exc:
        raise HTTPException(
            status_code=422,
            detail=f"Asset context CSV import failed: {exc}",
        ) from exc

    result = AssetRepository(session).import_asset_context_catalog(
        project_id=project_id,
        catalog=catalog,
    )
    WaiverRepository(session).sync_project_waivers(project_id)
    record_audit_event(
        session,
        action="asset.import",
        resource_type="asset",
        actor=local_actor,
        project_id=project_id,
        detail=dict(result),
    )
    session.commit()
    return AssetContextImportPublic.model_validate(result)


@router.patch("/assets/{asset_id}", response_model=AssetPublic)
def update_asset(
    *,
    asset_id: uuid.UUID,
    session: SessionDep,
    local_actor: LocalActor,
    asset_in: AssetUpdate,
) -> AssetPublic:
    """Update an asset if its project is visible."""
    repository = AssetRepository(session)
    asset = repository.get_asset(asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    require_project(session, asset.project_id)
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
    if WAIVER_MATCH_CONTEXT_FIELDS.intersection(changed_fields):
        WaiverRepository(session).sync_project_waivers(updated.project_id)
    record_audit_event(
        session,
        action="asset.update",
        resource_type="asset",
        resource_id=updated.id,
        actor=local_actor,
        project_id=updated.project_id,
        detail={"changed_fields": changed_fields},
    )
    session.commit()
    session.refresh(updated)
    return _asset_public(updated)


@router.post("/assets/{asset_id}/recalculate", response_model=AssetRecalculatePublic)
def recalculate_asset(
    *,
    asset_id: uuid.UUID,
    session: SessionDep,
    local_actor: LocalActor,
) -> AssetRecalculatePublic:
    """Recalculate linked finding scores for a visible asset."""
    repository = AssetRepository(session)
    asset = repository.get_asset(asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    require_project(session, asset.project_id)
    result = repository.recalculate_asset_findings(asset)
    WaiverRepository(session).sync_project_waivers(asset.project_id)
    record_audit_event(
        session,
        action="asset.recalculate",
        resource_type="asset",
        resource_id=asset.id,
        actor=local_actor,
        project_id=asset.project_id,
        detail=dict(result),
    )
    session.commit()
    session.refresh(asset)
    return AssetRecalculatePublic.model_validate(result)


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


def _validate_asset_context_upload(file: UploadFile) -> None:
    _reject_unsafe_upload_filename(file.filename or "")
    if Path(file.filename or "").suffix.lower() != ".csv":
        raise HTTPException(status_code=422, detail="Asset context file must be a CSV.")
    normalized = (file.content_type or "").split(";", maxsplit=1)[0].strip().lower()
    if normalized in {"", "application/octet-stream"}:
        return
    if normalized not in {"text/csv", "text/plain", "application/vnd.ms-excel"}:
        raise HTTPException(
            status_code=422,
            detail="Asset context content type must be text/csv.",
        )


def _reject_unsafe_upload_filename(filename: str) -> None:
    if "/" in filename or "\\" in filename or Path(filename).name != filename:
        raise HTTPException(status_code=422, detail="Upload filename is not allowed.")
    if any(ord(character) < 32 for character in filename):
        raise HTTPException(status_code=422, detail="Upload filename is not allowed.")

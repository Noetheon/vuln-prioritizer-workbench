"""Waiver and risk-acceptance API routes for the template Workbench."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, HTTPException
from sqlmodel import Session

from app.api.deps import CurrentUser, SessionDep
from app.api.routes.workbench_access import require_visible_project
from app.models import Waiver, WaiverCreate, WaiverPublic, WaiversPublic, WaiverUpdate
from app.repositories import AssetRepository, FindingRepository, WaiverRepository

router = APIRouter(tags=["waivers"])


@router.get("/projects/{project_id}/waivers/", response_model=WaiversPublic)
def read_project_waivers(
    project_id: uuid.UUID,
    session: SessionDep,
    current_user: CurrentUser,
) -> WaiversPublic:
    """List visible project waivers."""
    require_visible_project(session, current_user, project_id)
    repository = WaiverRepository(session)
    waivers = repository.list_project_waivers(project_id)
    return WaiversPublic(
        data=[_waiver_public(repository, waiver) for waiver in waivers],
        count=len(waivers),
    )


@router.post("/projects/{project_id}/waivers/", response_model=WaiverPublic)
def create_project_waiver(
    *,
    project_id: uuid.UUID,
    session: SessionDep,
    current_user: CurrentUser,
    waiver_in: WaiverCreate,
) -> WaiverPublic:
    """Create a scoped risk acceptance for a visible project."""
    require_visible_project(session, current_user, project_id)
    _validate_project_scope(session, project_id=project_id, waiver_in=waiver_in)
    repository = WaiverRepository(session)
    waiver = repository.create_project_waiver(project_id=project_id, waiver_in=waiver_in)
    repository.sync_project_waivers(project_id)
    session.commit()
    session.refresh(waiver)
    return _waiver_public(repository, waiver)


@router.patch("/waivers/{waiver_id}", response_model=WaiverPublic)
def update_waiver(
    *,
    waiver_id: uuid.UUID,
    session: SessionDep,
    current_user: CurrentUser,
    waiver_in: WaiverUpdate,
) -> WaiverPublic:
    """Update a waiver's scope, owner, reason, approval, and lifecycle dates."""
    repository = WaiverRepository(session)
    waiver = repository.get_waiver(waiver_id)
    if waiver is None:
        raise HTTPException(status_code=404, detail="Waiver not found")
    require_visible_project(session, current_user, waiver.project_id)
    _validate_project_scope(session, project_id=waiver.project_id, waiver_in=waiver_in)
    updated = repository.update_waiver(waiver, waiver_in)
    repository.sync_project_waivers(updated.project_id)
    session.commit()
    session.refresh(updated)
    return _waiver_public(repository, updated)


@router.post("/waivers/{waiver_id}/expire", response_model=WaiverPublic)
def expire_waiver(
    waiver_id: uuid.UUID,
    session: SessionDep,
    current_user: CurrentUser,
) -> WaiverPublic:
    """Expire a waiver and resynchronize visible accepted-risk state."""
    repository = WaiverRepository(session)
    waiver = repository.get_waiver(waiver_id)
    if waiver is None:
        raise HTTPException(status_code=404, detail="Waiver not found")
    require_visible_project(session, current_user, waiver.project_id)
    expired = repository.expire_waiver(waiver)
    repository.sync_project_waivers(expired.project_id)
    session.commit()
    session.refresh(expired)
    return _waiver_public(repository, expired)


def _validate_project_scope(
    session: Session,
    *,
    project_id: uuid.UUID,
    waiver_in: WaiverCreate | WaiverUpdate,
) -> None:
    if waiver_in.finding_id is not None:
        finding = FindingRepository(session).get_finding(waiver_in.finding_id)
        if finding is None or finding.project_id != project_id:
            raise HTTPException(status_code=422, detail="finding_id does not belong to project.")
    if waiver_in.asset_id is not None:
        asset = AssetRepository(session).get_asset(waiver_in.asset_id)
        if asset is None or asset.project_id != project_id:
            raise HTTPException(status_code=422, detail="asset_id does not belong to project.")


def _waiver_public(
    repository: WaiverRepository,
    waiver: Waiver,
    *,
    matched_findings: int | None = None,
) -> WaiverPublic:
    status, days_remaining = repository_status(waiver)
    return WaiverPublic.model_validate(
        waiver,
        update={
            "status": status,
            "days_remaining": days_remaining,
            "matched_findings": matched_findings
            if matched_findings is not None
            else repository.matching_finding_count(waiver),
        },
    )


def repository_status(waiver: Waiver) -> tuple[str, int | None]:
    from app.repositories.waivers import waiver_lifecycle_status

    return waiver_lifecycle_status(waiver)

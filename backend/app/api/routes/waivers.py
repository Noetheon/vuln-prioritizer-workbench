"""Waiver and risk-acceptance API routes for the Workbench."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, HTTPException, Query, Response
from sqlmodel import Session

from app.api.deps import LocalActor, SessionDep
from app.api.routes.workbench_access import lock_existing_project_resource, require_project
from app.models import Waiver, WaiverCreate, WaiverPublic, WaiversPublic, WaiverUpdate
from app.repositories import AssetRepository, FindingRepository, WaiverRepository
from app.services.audit import record_audit_event
from app.services.decision_scope_lock import lock_project_decision_scope

router = APIRouter(tags=["waivers"])


@router.get("/projects/{project_id}/waivers/", response_model=WaiversPublic)
def read_project_waivers(
    project_id: uuid.UUID,
    session: SessionDep,
    local_actor: LocalActor,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> WaiversPublic:
    """List visible project waivers."""
    require_project(session, project_id)
    repository = WaiverRepository(session)
    waivers, count = repository.list_project_waivers_page(
        project_id,
        limit=limit,
        offset=offset,
    )
    matched_counts = repository.matching_finding_counts(waivers)
    return WaiversPublic(
        data=[
            _waiver_public(
                repository,
                waiver,
                matched_findings=matched_counts[waiver.id],
            )
            for waiver in waivers
        ],
        count=count,
    )


@router.post("/projects/{project_id}/waivers/", response_model=WaiverPublic)
def create_project_waiver(
    *,
    project_id: uuid.UUID,
    session: SessionDep,
    local_actor: LocalActor,
    waiver_in: WaiverCreate,
) -> WaiverPublic:
    """Create a scoped risk acceptance for a visible project."""
    require_project(session, project_id)
    lock_project_decision_scope(session, project_id)
    _validate_project_scope(session, project_id=project_id, waiver_in=waiver_in)
    repository = WaiverRepository(session)
    waiver = repository.create_project_waiver(project_id=project_id, waiver_in=waiver_in)
    repository.sync_project_waivers(project_id)
    record_audit_event(
        session,
        action="waiver.create",
        resource_type="waiver",
        resource_id=waiver.id,
        actor=local_actor,
        project_id=project_id,
        detail={"cve_id": waiver.cve_id, "owner": waiver.owner},
    )
    session.commit()
    session.refresh(waiver)
    return _waiver_public(repository, waiver)


@router.patch("/waivers/{waiver_id}", response_model=WaiverPublic)
def update_waiver(
    *,
    waiver_id: uuid.UUID,
    session: SessionDep,
    local_actor: LocalActor,
    waiver_in: WaiverUpdate,
) -> WaiverPublic:
    """Update a waiver's scope, owner, reason, approval, and lifecycle dates."""
    repository = WaiverRepository(session)
    waiver = _lock_existing_waiver(session, waiver_id=waiver_id, repository=repository)
    _validate_project_scope(session, project_id=waiver.project_id, waiver_in=waiver_in)
    updated = repository.update_waiver(waiver, waiver_in)
    repository.sync_project_waivers(updated.project_id)
    record_audit_event(
        session,
        action="waiver.update",
        resource_type="waiver",
        resource_id=updated.id,
        actor=local_actor,
        project_id=updated.project_id,
        detail=waiver_in.model_dump(exclude_unset=True, mode="json"),
    )
    session.commit()
    session.refresh(updated)
    return _waiver_public(repository, updated)


@router.delete("/waivers/{waiver_id}", status_code=204)
def delete_waiver(
    waiver_id: uuid.UUID,
    session: SessionDep,
    local_actor: LocalActor,
) -> Response:
    """Delete a waiver and rebuild the project's mutable decision queue."""
    repository = WaiverRepository(session)
    waiver = _lock_existing_waiver(session, waiver_id=waiver_id, repository=repository)
    project_id = waiver.project_id
    lifecycle_status, days_remaining = repository_status(waiver)
    audit_detail = {
        "deleted_waiver": waiver.model_dump(mode="json"),
        "lifecycle_status": lifecycle_status,
        "days_remaining": days_remaining,
    }
    repository.delete_waiver(waiver)
    repository.sync_project_waivers(project_id, force=True)
    record_audit_event(
        session,
        action="waiver.delete",
        resource_type="waiver",
        resource_id=waiver_id,
        actor=local_actor,
        project_id=project_id,
        detail=audit_detail,
    )
    session.commit()
    return Response(status_code=204)


@router.post("/waivers/{waiver_id}/expire", response_model=WaiverPublic)
def expire_waiver(
    waiver_id: uuid.UUID,
    session: SessionDep,
    local_actor: LocalActor,
) -> WaiverPublic:
    """Expire a waiver and resynchronize visible accepted-risk state."""
    repository = WaiverRepository(session)
    waiver = _lock_existing_waiver(session, waiver_id=waiver_id, repository=repository)
    expired = repository.expire_waiver(waiver)
    repository.sync_project_waivers(expired.project_id)
    record_audit_event(
        session,
        action="waiver.expire",
        resource_type="waiver",
        resource_id=expired.id,
        actor=local_actor,
        project_id=expired.project_id,
        detail={"cve_id": expired.cve_id, "owner": expired.owner},
    )
    session.commit()
    session.refresh(expired)
    return _waiver_public(repository, expired)


def _lock_existing_waiver(
    session: Session,
    *,
    waiver_id: uuid.UUID,
    repository: WaiverRepository,
) -> Waiver:
    """Lock a waiver's project, then reject a concurrently deleted stale row."""
    stale = repository.get_waiver(waiver_id)
    if stale is None:
        raise HTTPException(status_code=404, detail="Waiver not found")
    return lock_existing_project_resource(
        session,
        model=Waiver,
        resource_id=waiver_id,
        project_id=stale.project_id,
        not_found_detail="Waiver not found",
    )


def _validate_project_scope(
    session: Session,
    *,
    project_id: uuid.UUID,
    waiver_in: WaiverCreate | WaiverUpdate,
) -> None:
    """Validate project scope function."""
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
    """Waiver public function."""
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
    """Repository status function."""
    from app.repositories.waivers import waiver_lifecycle_status

    return waiver_lifecycle_status(waiver)

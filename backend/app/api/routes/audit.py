"""Audit routes for the local Workbench runtime."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Query

from app.api.deps import LocalActor, SessionDep
from app.models import (
    AuditEventsPublic,
)
from app.models.audit import audit_event_public
from app.repositories import AuditEventRepository

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("/events", response_model=AuditEventsPublic)
def list_audit_events(
    session: SessionDep,
    _local_actor: LocalActor,
    project_id: uuid.UUID | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> AuditEventsPublic:
    """List recent audit events for administrators."""
    events, count = AuditEventRepository(session).list_audit_events(
        limit=limit,
        offset=offset,
        project_id=project_id,
    )
    return AuditEventsPublic(data=[audit_event_public(event) for event in events], count=count)

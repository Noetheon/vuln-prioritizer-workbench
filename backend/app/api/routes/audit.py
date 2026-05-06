"""Audit and session administration routes."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Query

from app.api.deps import ScopedAdminUser, SessionDep
from app.models import (
    AuditEventsPublic,
    AuthSessionsPublic,
)
from app.models.audit import audit_event_public
from app.models.sessions import auth_session_public
from app.repositories import AuditEventRepository, AuthSessionRepository

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("/events", response_model=AuditEventsPublic)
def list_audit_events(
    session: SessionDep,
    _current_user: ScopedAdminUser,
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


@router.get("/sessions", response_model=AuthSessionsPublic)
def list_auth_sessions(
    session: SessionDep,
    _current_user: ScopedAdminUser,
    limit: int = Query(default=100, ge=1, le=500),
) -> AuthSessionsPublic:
    """List recent browser sessions without token material."""
    records = AuthSessionRepository(session).list_auth_sessions(limit=limit)
    return AuthSessionsPublic(
        data=[auth_session_public(record) for record in records],
        count=len(records),
    )

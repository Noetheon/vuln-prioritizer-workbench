"""Scoped API token routes for Workbench automation."""

from __future__ import annotations

import secrets
import uuid

from fastapi import APIRouter, HTTPException

from app.api.deps import ScopedAdminUser, SessionDep
from app.api.routes.workbench_access import require_visible_project
from app.models import (
    ApiTokenCreate,
    ApiTokenCreatePublic,
    ApiTokenPublic,
    ApiTokensPublic,
)
from app.models.api_tokens import api_token_create_public, api_token_public
from app.repositories import ApiTokenRepository
from app.services.audit import record_audit_event
from vuln_prioritizer.security_tokens import api_token_digest

router = APIRouter(prefix="/api-tokens", tags=["api-tokens"])

API_TOKEN_PREFIX = "vpr_"


@router.post("/", response_model=ApiTokenCreatePublic)
def create_api_token(
    payload: ApiTokenCreate,
    session: SessionDep,
    current_user: ScopedAdminUser,
) -> ApiTokenCreatePublic:
    """Create a scoped service token and return its secret value once."""
    if payload.project_id is not None:
        require_visible_project(session, current_user, payload.project_id)
    token_value = API_TOKEN_PREFIX + secrets.token_urlsafe(32)
    token = ApiTokenRepository(session).create_api_token(
        name=payload.name,
        token_hash=api_token_digest(token_value),
        scopes=payload.scopes,
        project_id=payload.project_id,
    )
    record_audit_event(
        session,
        action="api_token.create",
        resource_type="api_token",
        resource_id=token.id,
        actor=current_user,
        project_id=token.project_id,
        detail={"name": token.name, "scopes": list(token.scopes)},
    )
    session.commit()
    session.refresh(token)
    return api_token_create_public(token, cleartext_token=token_value)


@router.get("/", response_model=ApiTokensPublic)
def list_api_tokens(
    session: SessionDep,
    _current_user: ScopedAdminUser,
) -> ApiTokensPublic:
    """List token metadata without exposing token secrets or hashes."""
    tokens = ApiTokenRepository(session).list_api_tokens()
    return ApiTokensPublic(
        data=[api_token_public(token) for token in tokens],
        count=len(tokens),
    )


@router.delete("/{token_id}", response_model=ApiTokenPublic)
def revoke_api_token(
    token_id: uuid.UUID,
    session: SessionDep,
    current_user: ScopedAdminUser,
) -> ApiTokenPublic:
    """Revoke a service token so it can no longer authorize API requests."""
    repo = ApiTokenRepository(session)
    token = repo.get_api_token(token_id)
    if token is None:
        raise HTTPException(status_code=404, detail="API token not found")
    repo.revoke_api_token(token)
    record_audit_event(
        session,
        action="api_token.revoke",
        resource_type="api_token",
        resource_id=token.id,
        actor=current_user,
        project_id=token.project_id,
        detail={"name": token.name, "scopes": list(token.scopes)},
    )
    session.commit()
    session.refresh(token)
    return api_token_public(token)

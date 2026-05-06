"""Minimal template login routes for the active backend runtime."""

from __future__ import annotations

from datetime import timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.security import OAuth2PasswordRequestForm

from app.api.deps import CurrentUser, SessionDep, TokenDep
from app.core import security
from app.core.config import Settings, settings
from app.core.db import ensure_configured_superuser
from app.core.rate_limit import InMemoryRateLimiter
from app.models import Token, User, UserPublic
from app.repositories import AuthSessionRepository
from app.services.audit import record_audit_event

router = APIRouter(tags=["login"])


@router.post("/login/access-token")
def login_access_token(
    request: Request,
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    session: SessionDep,
) -> Token:
    """OAuth2 compatible token login for the configured template-shell user."""
    _enforce_login_rate_limit(request, form_data.username)
    if (
        form_data.username != settings.FIRST_SUPERUSER
        or form_data.password != settings.FIRST_SUPERUSER_PASSWORD
    ):
        record_audit_event(
            session,
            action="login.failure",
            resource_type="auth_session",
            status="failure",
            detail={"username": form_data.username},
        )
        session.commit()
        raise HTTPException(status_code=400, detail="Incorrect email or password")

    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    expires_at = security.access_token_expires_at(access_token_expires)
    jti = security.new_token_jti()
    user = ensure_configured_superuser(session)
    auth_session = AuthSessionRepository(session).create_auth_session(
        user_id=user.id,
        jti_hash=security.token_jti_digest(jti),
        expires_at=expires_at,
    )
    record_audit_event(
        session,
        action="login.success",
        resource_type="auth_session",
        resource_id=auth_session.id,
        actor=user,
    )
    session.commit()
    return Token(
        access_token=security.create_access_token(
            settings.FIRST_SUPERUSER,
            expires_delta=access_token_expires,
            expires_at=expires_at,
            jti=jti,
        )
    )


@router.post("/login/test-token", response_model=UserPublic)
def test_token(current_user: CurrentUser) -> User:
    """Test access token."""
    return current_user


def _enforce_login_rate_limit(request: Request, username: str) -> None:
    active_settings = getattr(request.app.state, "template_settings", settings)
    limiter = getattr(request.app.state, "rate_limiter", None)
    if not isinstance(active_settings, Settings) or not active_settings.RATE_LIMIT_ENABLED:
        return
    if not isinstance(limiter, InMemoryRateLimiter):
        return
    client_host = request.client.host if request.client else "unknown"
    normalized_username = username.strip().lower() or "unknown"
    decision = limiter.check(
        f"login-user:{client_host}:{normalized_username}",
        limit=active_settings.LOGIN_RATE_LIMIT_PER_MINUTE,
    )
    if not decision.allowed:
        raise HTTPException(
            status_code=429,
            detail="Too many requests.",
            headers={"Retry-After": str(decision.retry_after_seconds)},
        )


@router.post("/login/logout", response_model=UserPublic)
def logout_current_token(
    session: SessionDep,
    token: TokenDep,
    current_user: CurrentUser,
) -> User:
    """Revoke the active browser session token."""
    payload = security.decode_access_token(token)
    jti = payload.get("jti")
    if isinstance(jti, str):
        auth_session = AuthSessionRepository(session).get_active_auth_session_by_hash(
            security.token_jti_digest(jti)
        )
        if auth_session is not None:
            AuthSessionRepository(session).revoke_auth_session(auth_session)
            record_audit_event(
                session,
                action="login.logout",
                resource_type="auth_session",
                resource_id=auth_session.id,
                actor=current_user,
            )
            session.commit()
    return current_user

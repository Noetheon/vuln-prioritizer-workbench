"""Minimal template login routes for the active backend runtime."""

from __future__ import annotations

import secrets
from datetime import timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.security import OAuth2PasswordRequestForm

from app.api.deps import CurrentUser, SessionDep
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
    response: Response,
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    session: SessionDep,
) -> Token:
    """OAuth2 compatible token login for the configured template-shell user."""
    _enforce_login_rate_limit(request, form_data.username)
    active_settings = _request_settings(request)
    user = ensure_configured_superuser(session, active_settings=active_settings)
    if not _credentials_are_valid(user, form_data.username, form_data.password):
        record_audit_event(
            session,
            action="login.failure",
            resource_type="auth_session",
            status="failure",
            detail={"username": form_data.username},
        )
        session.commit()
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    if not user.is_active:
        record_audit_event(
            session,
            action="login.failure",
            resource_type="auth_session",
            status="failure",
            detail={"username": form_data.username, "reason": "inactive_user"},
        )
        session.commit()
        raise HTTPException(status_code=400, detail="Incorrect email or password")

    access_token_expires = timedelta(minutes=active_settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    expires_at = security.access_token_expires_at(access_token_expires)
    jti = security.new_token_jti()
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
    access_token = security.create_access_token(
        user.email,
        expires_delta=access_token_expires,
        expires_at=expires_at,
        jti=jti,
        secret_key=active_settings.SECRET_KEY,
    )
    csrf_token = security.create_csrf_token(jti, secret_key=active_settings.SECRET_KEY)
    _set_session_cookies(
        request,
        response,
        access_token=access_token,
        csrf_token=csrf_token,
        max_age_seconds=int(access_token_expires.total_seconds()),
    )
    return Token(
        access_token=access_token,
        csrf_token=csrf_token,
    )


@router.post("/login/test-token", response_model=UserPublic)
def test_token(current_user: CurrentUser) -> User:
    """Test access token."""
    return current_user


def _enforce_login_rate_limit(request: Request, username: str) -> None:
    active_settings = _request_settings(request)
    limiter = getattr(request.app.state, "rate_limiter", None)
    if not active_settings.RATE_LIMIT_ENABLED:
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
    request: Request,
    response: Response,
    session: SessionDep,
    current_user: CurrentUser,
) -> User:
    """Revoke the active browser session token."""
    jti = getattr(request.state, "auth_jti", None)
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
    _clear_session_cookies(response)
    return current_user


def _credentials_are_valid(user: User, username: str, password: str) -> bool:
    normalized_username = username.strip().lower()
    normalized_email = user.email.strip().lower()
    return secrets.compare_digest(
        normalized_username.encode(),
        normalized_email.encode(),
    ) and security.verify_password(password, user.hashed_password)


def _set_session_cookies(
    request: Request,
    response: Response,
    *,
    access_token: str,
    csrf_token: str,
    max_age_seconds: int,
) -> None:
    cookie_secure = _session_cookie_secure(request)
    response.set_cookie(
        security.SESSION_COOKIE_NAME,
        access_token,
        max_age=max_age_seconds,
        path="/",
        httponly=True,
        secure=cookie_secure,
        samesite="lax",
    )
    response.set_cookie(
        security.CSRF_COOKIE_NAME,
        csrf_token,
        max_age=max_age_seconds,
        path="/",
        httponly=False,
        secure=cookie_secure,
        samesite="lax",
    )


def _clear_session_cookies(response: Response) -> None:
    response.delete_cookie(security.SESSION_COOKIE_NAME, path="/")
    response.delete_cookie(security.CSRF_COOKIE_NAME, path="/")


def _session_cookie_secure(request: Request) -> bool:
    active_settings = _request_settings(request)
    if active_settings.ENVIRONMENT != "local":
        return True
    return request.url.scheme == "https"


def _request_settings(request: Request) -> Settings:
    active_settings = getattr(request.app.state, "template_settings", settings)
    if isinstance(active_settings, Settings):
        return active_settings
    return settings

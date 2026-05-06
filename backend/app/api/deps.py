"""Template-style dependency helpers for the active backend runtime."""

from __future__ import annotations

import secrets
from collections.abc import Callable, Generator
from hashlib import sha256
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from pydantic import ValidationError
from sqlmodel import Session

from app.core import security
from app.core.config import settings
from app.core.db import engine, ensure_configured_superuser
from app.core.rate_limit import InMemoryRateLimiter
from app.models import ApiToken, ApiTokenScope, TokenPayload, User
from app.models.api_tokens import attach_api_token_context, scope_set
from app.repositories import ApiTokenRepository, AuthSessionRepository
from vuln_prioritizer.security_tokens import api_token_digest

reusable_oauth2 = OAuth2PasswordBearer(tokenUrl=f"{settings.API_V1_STR}/login/access-token")

TokenDep = Annotated[str, Depends(reusable_oauth2)]


def get_db() -> Generator[Session, None, None]:
    """Yield a SQLModel session for template-backed API routes."""
    with Session(engine) as session:
        yield session


SessionDep = Annotated[Session, Depends(get_db)]


def _current_user_from_jwt(session: Session, token: str) -> User:
    """Validate a JWT and resolve the configured active-runtime user."""
    try:
        payload = security.decode_access_token(token)
        token_data = TokenPayload(**payload)
    except (security.TokenDecodeError, ValidationError) as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Could not validate credentials",
        ) from exc

    if token_data.sub != settings.FIRST_SUPERUSER:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if token_data.jti is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Could not validate credentials",
        )
    auth_session_repo = AuthSessionRepository(session)
    auth_session = auth_session_repo.get_active_auth_session_by_hash(
        security.token_jti_digest(token_data.jti)
    )
    if auth_session is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Session is expired or revoked",
        )
    auth_session_repo.mark_auth_session_seen(auth_session)
    session.commit()
    user = ensure_configured_superuser(session)
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Inactive user")
    return user


def get_current_user(session: SessionDep, token: TokenDep) -> User:
    """Require a configured-user JWT for active UI/session routes."""
    return _current_user_from_jwt(session, token)


CurrentUser = Annotated[User, Depends(get_current_user)]


def get_current_active_superuser(current_user: CurrentUser) -> User:
    """Require the configured user to be active and superuser."""
    if not current_user.is_superuser:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not enough privileges")
    return current_user


def require_api_scope(required_scope: ApiTokenScope) -> Callable[..., User]:
    """Accept a user JWT or a service token with the requested scope."""

    def dependency(request: Request, session: SessionDep, token: TokenDep) -> User:
        try:
            user = _current_user_from_jwt(session, token)
        except HTTPException as jwt_error:
            token_record = _active_service_token(session, token)
            if token_record is None:
                _enforce_token_failure_rate_limit(request, token)
                raise jwt_error
            scopes = scope_set(token_record)
            if required_scope not in scopes and "admin" not in scopes:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"API token requires {required_scope} scope.",
                )
            repo = ApiTokenRepository(session)
            repo.mark_api_token_used(token_record)
            session.commit()
            principal = ensure_configured_superuser(session)
            attach_api_token_context(
                principal,
                token_id=token_record.id,
                project_id=token_record.project_id,
                scopes=scopes,
            )
            return principal
        if required_scope == "admin" and not user.is_superuser:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not enough privileges",
            )
        return user

    return dependency


def _enforce_token_failure_rate_limit(request: Request, raw_token: str) -> None:
    active_settings = getattr(request.app.state, "template_settings", settings)
    limiter = getattr(request.app.state, "rate_limiter", None)
    if not active_settings.RATE_LIMIT_ENABLED or not isinstance(limiter, InMemoryRateLimiter):
        return
    client_host = request.client.host if request.client else "unknown"
    token_hint = sha256(raw_token.encode("utf-8")).hexdigest()[:16]
    decision = limiter.check(
        f"token-failure:{client_host}:{token_hint}",
        limit=active_settings.TOKEN_FAILURE_RATE_LIMIT_PER_MINUTE,
    )
    if not decision.allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many requests.",
            headers={"Retry-After": str(decision.retry_after_seconds)},
        )


def _active_service_token(session: Session, raw_token: str) -> ApiToken | None:
    token_hash = api_token_digest(raw_token)
    token_record = ApiTokenRepository(session).get_active_api_token_by_hash(token_hash)
    if token_record is None:
        return None
    if not secrets.compare_digest(token_record.token_hash, token_hash):
        return None
    return token_record


ScopedReadUser = Annotated[User, Depends(require_api_scope("read"))]
ScopedImportUser = Annotated[User, Depends(require_api_scope("import"))]
ScopedReportUser = Annotated[User, Depends(require_api_scope("report"))]
ScopedAdminUser = Annotated[User, Depends(require_api_scope("admin"))]

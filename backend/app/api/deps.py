"""Dependency helpers for the active local Workbench runtime."""

from __future__ import annotations

import secrets
from collections.abc import Callable, Generator
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from sqlmodel import Session

from app.core.app_state import workbench_engine, workbench_settings
from app.core.db import ensure_configured_superuser
from app.core.rate_limit import RateLimiter, rate_limit_client_host
from app.models import ApiToken, ApiTokenScope, User
from app.models.api_tokens import attach_api_token_context, scope_set
from app.repositories import ApiTokenRepository
from app.services.audit import record_audit_event
from vuln_prioritizer.security_tokens import api_token_digest

SERVICE_TOKEN_PREFIX = "vpr_"
SERVICE_TOKEN_MIN_LENGTH = 40
SERVICE_TOKEN_MAX_LENGTH = 128
SERVICE_TOKEN_ALLOWED_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)


def get_db(request: Request) -> Generator[Session, None, None]:
    """Yield a SQLModel session for active API routes."""
    with Session(workbench_engine(request)) as session:
        yield session


SessionDep = Annotated[Session, Depends(get_db)]


def get_current_user(request: Request, session: SessionDep) -> User:
    """Return the local single-user Workbench principal.

    The current product scope is a local/self-hosted single-user Workbench, so
    API routes should not require login, RBAC, service-token scopes, or session
    cookies during normal operation. We still keep a configured user record so
    existing project ownership, audit rows, and report metadata have a stable
    actor until those models are simplified in a later cleanup.
    """
    user = ensure_configured_superuser(
        session,
        active_settings=workbench_settings(request, required=False),
    )
    request.state.auth_token = None
    request.state.auth_token_source = "local"
    request.state.auth_jti = None
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


def get_current_active_superuser(current_user: CurrentUser) -> User:
    """Return the local Workbench user for legacy admin-shaped routes."""
    if not current_user.is_superuser:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not enough privileges")
    return current_user


def require_api_scope(
    required_scope: ApiTokenScope,
    *,
    require_superuser_for_jwt: bool | None = None,
) -> Callable[..., User]:
    """Return the local single-user principal and ignore legacy API scopes.

    The signature intentionally remains compatible with existing route
    declarations while removing API-token/RBAC friction from the active runtime.
    """

    def dependency(request: Request, session: SessionDep) -> User:
        user = get_current_user(request, session)
        raw_token = _bearer_token(request)
        if raw_token is None or _looks_like_browser_session_token(raw_token):
            return user
        if not _looks_like_service_token(raw_token):
            _enforce_token_failure_rate_limit(request)
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Could not validate API token.",
            )

        _enforce_token_failure_rate_limit(request, record=False)
        token_record = _active_service_token(session, raw_token)
        if token_record is None:
            _enforce_token_failure_rate_limit(request)
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Could not validate API token.",
            )
        if not user.is_active:
            record_audit_event(
                session,
                action="api_token.auth.failure",
                resource_type="api_token",
                resource_id=token_record.id,
                status="failure",
                actor=user,
                project_id=token_record.project_id,
                detail={"reason": "inactive_user", "scopes": sorted(scope_set(token_record))},
            )
            session.commit()
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Inactive user",
            )
        scopes = scope_set(token_record)
        if required_scope not in scopes and "admin" not in scopes:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"API token requires {required_scope} scope.",
            )
        attach_api_token_context(
            user,
            token_id=token_record.id,
            project_id=token_record.project_id,
            scopes=scopes,
        )
        ApiTokenRepository(session).mark_api_token_used(token_record)
        session.commit()
        return user

    setattr(dependency, "_vpw_auth_dependency", True)
    setattr(dependency, "_vpw_required_scope", required_scope)
    setattr(dependency, "_vpw_legacy_superuser_gate", require_superuser_for_jwt)
    return dependency


ScopedReadUser = Annotated[User, Depends(require_api_scope("read"))]
ScopedWriteUser = Annotated[User, Depends(require_api_scope("write"))]
ScopedImportUser = Annotated[User, Depends(require_api_scope("import"))]
ScopedReportUser = Annotated[User, Depends(require_api_scope("report"))]
ScopedAdminTokenOrUser = Annotated[
    User,
    Depends(require_api_scope("admin", require_superuser_for_jwt=False)),
]
ScopedAdminUser = Annotated[User, Depends(require_api_scope("admin"))]


def _bearer_token(request: Request) -> str | None:
    authorization = request.headers.get("authorization", "")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        return None
    return token.strip()


def _looks_like_service_token(raw_token: str) -> bool:
    if not raw_token.startswith(SERVICE_TOKEN_PREFIX):
        return False
    if not SERVICE_TOKEN_MIN_LENGTH <= len(raw_token) <= SERVICE_TOKEN_MAX_LENGTH:
        return False
    token_body = raw_token[len(SERVICE_TOKEN_PREFIX) :]
    return bool(token_body) and all(char in SERVICE_TOKEN_ALLOWED_CHARS for char in token_body)


def _looks_like_browser_session_token(raw_token: str) -> bool:
    return raw_token.count(".") == 2


def _enforce_token_failure_rate_limit(request: Request, *, record: bool = True) -> None:
    active_settings = workbench_settings(request, required=False)
    limiter = getattr(request.app.state, "rate_limiter", None)
    if not active_settings.RATE_LIMIT_ENABLED or not isinstance(limiter, RateLimiter):
        return
    client_host = rate_limit_client_host(request, active_settings)
    decision = limiter.check(
        f"token-failure:{client_host}",
        limit=active_settings.TOKEN_FAILURE_RATE_LIMIT_PER_MINUTE,
        record=record,
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

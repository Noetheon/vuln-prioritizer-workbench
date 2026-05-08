"""Dependency helpers for the active Workbench runtime."""

from __future__ import annotations

import secrets
from collections.abc import Callable, Generator
from typing import Annotated, Literal

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from pydantic import ValidationError
from sqlmodel import Session

from app.core import security
from app.core.app_state import workbench_engine, workbench_settings
from app.core.config import Settings, settings
from app.core.db import ensure_configured_superuser
from app.core.rate_limit import RateLimiter, rate_limit_client_host
from app.models import ApiToken, ApiTokenScope, TokenPayload, User
from app.models.api_tokens import attach_api_token_context, scope_set
from app.repositories import ApiTokenRepository, AuthSessionRepository
from app.services.audit import record_audit_event
from vuln_prioritizer.security_tokens import api_token_digest

reusable_oauth2 = OAuth2PasswordBearer(
    tokenUrl=f"{settings.API_V1_STR}/login/access-token",
    auto_error=False,
)

TokenDep = Annotated[str | None, Depends(reusable_oauth2)]
AuthTokenSource = Literal["bearer", "cookie"]
UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
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


def _current_user_from_jwt(
    session: Session,
    token: str,
    *,
    active_settings: Settings | None = None,
    request: Request | None = None,
    token_source: AuthTokenSource = "bearer",
) -> User:
    """Validate a JWT and resolve the configured active-runtime user."""
    selected_settings = active_settings or settings
    try:
        payload = security.decode_access_token(
            token,
            secret_key=selected_settings.SECRET_KEY,
        )
        token_data = TokenPayload(**payload)
    except (security.TokenDecodeError, ValidationError) as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Could not validate credentials",
        ) from exc

    if token_data.sub != selected_settings.FIRST_SUPERUSER:
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
    if request is not None and token_source == "cookie":
        _enforce_cookie_csrf(request, token_data.jti, active_settings=selected_settings)
    auth_session_repo.mark_auth_session_seen(auth_session)
    session.commit()
    if request is not None:
        request.state.auth_token = token
        request.state.auth_token_source = token_source
        request.state.auth_jti = token_data.jti
    user = ensure_configured_superuser(session, active_settings=selected_settings)
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Inactive user")
    return user


def get_current_user(request: Request, session: SessionDep, token: TokenDep) -> User:
    """Require a configured-user JWT for active UI/session routes."""
    raw_token, token_source = _resolve_request_token(request, token)
    return _current_user_from_jwt(
        session,
        raw_token,
        active_settings=_request_settings(request),
        request=request,
        token_source=token_source,
    )


CurrentUser = Annotated[User, Depends(get_current_user)]


def get_current_active_superuser(current_user: CurrentUser) -> User:
    """Require the configured user to be active and superuser."""
    if not current_user.is_superuser:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not enough privileges")
    return current_user


def require_api_scope(
    required_scope: ApiTokenScope,
    *,
    require_superuser_for_jwt: bool | None = None,
) -> Callable[..., User]:
    """Accept a user JWT or a service token with the requested scope."""
    jwt_needs_superuser = (
        required_scope == "admin"
        if require_superuser_for_jwt is None
        else require_superuser_for_jwt
    )

    def dependency(request: Request, session: SessionDep, token: TokenDep) -> User:
        raw_token, token_source = _resolve_request_token(request, token)
        active_settings = _request_settings(request)
        try:
            user = _current_user_from_jwt(
                session,
                raw_token,
                active_settings=active_settings,
                request=request,
                token_source=token_source,
            )
        except HTTPException as jwt_error:
            if token_source != "bearer":
                raise jwt_error
            if not _looks_like_service_token(raw_token):
                _enforce_token_failure_rate_limit(request)
                raise jwt_error
            _enforce_token_failure_rate_limit(request, record=False)
            token_record = _active_service_token(session, raw_token)
            if token_record is None:
                _enforce_token_failure_rate_limit(request)
                raise jwt_error
            scopes = scope_set(token_record)
            if required_scope not in scopes and "admin" not in scopes:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"API token requires {required_scope} scope.",
                )
            principal = ensure_configured_superuser(
                session,
                active_settings=active_settings,
            )
            attach_api_token_context(
                principal,
                token_id=token_record.id,
                project_id=token_record.project_id,
                scopes=scopes,
            )
            if not principal.is_active:
                record_audit_event(
                    session,
                    action="api_token.auth.failure",
                    resource_type="api_token",
                    resource_id=token_record.id,
                    status="failure",
                    actor=principal,
                    project_id=token_record.project_id,
                    detail={"reason": "inactive_user", "scopes": sorted(scopes)},
                )
                session.commit()
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Inactive user",
                )
            repo = ApiTokenRepository(session)
            repo.mark_api_token_used(token_record)
            session.commit()
            return principal
        if jwt_needs_superuser and not user.is_superuser:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not enough privileges",
            )
        return user

    setattr(dependency, "_vpw_auth_dependency", True)
    setattr(dependency, "_vpw_required_scope", required_scope)
    return dependency


def _request_settings(request: Request) -> Settings:
    return workbench_settings(request, required=False)


def _resolve_request_token(
    request: Request,
    bearer_token: str | None,
) -> tuple[str, AuthTokenSource]:
    if bearer_token:
        return bearer_token, "bearer"
    cookie_token = request.cookies.get(security.SESSION_COOKIE_NAME)
    if cookie_token:
        return cookie_token, "cookie"
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated",
        headers={"WWW-Authenticate": "Bearer"},
    )


def _enforce_cookie_csrf(
    request: Request,
    jti: str,
    *,
    active_settings: Settings,
) -> None:
    if request.method.upper() not in UNSAFE_METHODS:
        return
    header_token = request.headers.get(security.CSRF_HEADER_NAME)
    cookie_token = request.cookies.get(security.CSRF_COOKIE_NAME)
    if (
        not header_token
        or not cookie_token
        or not secrets.compare_digest(header_token, cookie_token)
        or not security.verify_csrf_token(
            jti,
            header_token,
            secret_key=active_settings.SECRET_KEY,
        )
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CSRF token missing or invalid",
        )


def _enforce_token_failure_rate_limit(
    request: Request,
    *,
    record: bool = True,
) -> None:
    active_settings = workbench_settings(request, required=False)
    limiter = getattr(request.app.state, "rate_limiter", None)
    if not isinstance(active_settings, Settings) or not active_settings.RATE_LIMIT_ENABLED:
        return
    if not isinstance(limiter, RateLimiter):
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


def _looks_like_service_token(raw_token: str) -> bool:
    if not raw_token.startswith(SERVICE_TOKEN_PREFIX):
        return False
    if not SERVICE_TOKEN_MIN_LENGTH <= len(raw_token) <= SERVICE_TOKEN_MAX_LENGTH:
        return False
    token_body = raw_token[len(SERVICE_TOKEN_PREFIX) :]
    return bool(token_body) and all(char in SERVICE_TOKEN_ALLOWED_CHARS for char in token_body)


def _active_service_token(session: Session, raw_token: str) -> ApiToken | None:
    token_hash = api_token_digest(raw_token)
    token_record = ApiTokenRepository(session).get_active_api_token_by_hash(token_hash)
    if token_record is None:
        return None
    if not secrets.compare_digest(token_record.token_hash, token_hash):
        return None
    return token_record


ScopedReadUser = Annotated[User, Depends(require_api_scope("read"))]
ScopedWriteUser = Annotated[User, Depends(require_api_scope("write"))]
ScopedImportUser = Annotated[User, Depends(require_api_scope("import"))]
ScopedReportUser = Annotated[User, Depends(require_api_scope("report"))]
ScopedAdminTokenOrUser = Annotated[
    User,
    Depends(require_api_scope("admin", require_superuser_for_jwt=False)),
]
ScopedAdminUser = Annotated[User, Depends(require_api_scope("admin"))]

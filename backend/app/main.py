"""FastAPI entrypoint for the active Workbench runtime."""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.routing import APIRoute
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.responses import JSONResponse, Response
from starlette.types import Message

from app.api.errors import (
    error_response_content,
    http_exception_handler,
    install_error_openapi_schema,
    unhandled_exception_handler,
    validation_error_handler,
)
from app.api.main import api_router, assert_api_auth_policy
from app.core.app_state import configure_workbench_state, workbench_settings
from app.core.config import Settings, settings
from app.core.db import create_db_engine
from app.core.rate_limit import RateLimiter, create_rate_limiter, rate_limit_key
from app.core.schema_smoke import assert_migrated_schema
from app.services.import_background import reconcile_stale_background_import_runs

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "same-origin",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    "Content-Security-Policy": (
        "default-src 'self'; base-uri 'none'; object-src 'none'; "
        "script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "connect-src 'self'; frame-ancestors 'none'"
    ),
}
_AUTH_REQUEST_MAX_BYTES = 64 * 1024


def custom_generate_unique_id(route: APIRoute) -> str:
    """Use stable tag-prefixed operation IDs for generated clients."""
    if route.tags:
        return f"{route.tags[0]}-{route.name}"
    return route.name


def create_app(active_settings: Settings | None = None) -> FastAPI:
    """Create the active Workbench backend runtime."""
    selected_settings = active_settings or settings
    openapi_url = (
        f"{selected_settings.API_V1_STR}/openapi.json"
        if selected_settings.api_docs_enabled
        else None
    )
    app = FastAPI(
        title=selected_settings.PROJECT_NAME,
        openapi_url=openapi_url,
        docs_url="/docs" if selected_settings.api_docs_enabled else None,
        redoc_url="/redoc" if selected_settings.api_docs_enabled else None,
        generate_unique_id_function=custom_generate_unique_id,
    )
    active_engine = create_db_engine(selected_settings)
    assert_api_auth_policy(selected_settings.API_V1_STR)
    configure_workbench_state(
        app,
        active_settings=selected_settings,
        active_engine=active_engine,
    )
    app.state.rate_limiter = create_rate_limiter(selected_settings, active_engine)
    if selected_settings.ENVIRONMENT != "local":
        app.router.on_startup.append(lambda: assert_migrated_schema(active_engine))
        app.router.on_startup.append(
            lambda: reconcile_stale_background_import_runs(
                engine=active_engine,
                settings=selected_settings,
            )
        )
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=list(selected_settings.ALLOWED_HOSTS),
    )
    if selected_settings.all_cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=list(selected_settings.all_cors_origins),
            allow_credentials=True,
            allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
            allow_headers=["Authorization", "Content-Type", "Accept", "X-CSRF-Token"],
        )
    app.middleware("http")(_rate_limit_guard)
    app.middleware("http")(_upload_size_guard)
    app.middleware("http")(_security_headers)
    app.include_router(api_router, prefix=selected_settings.API_V1_STR)
    app.add_exception_handler(StarletteHTTPException, http_exception_handler)
    app.add_exception_handler(RequestValidationError, validation_error_handler)
    app.add_exception_handler(Exception, unhandled_exception_handler)
    install_error_openapi_schema(
        app,
        oauth2_token_url=f"{selected_settings.API_V1_STR}/login/access-token",
    )
    return app


async def _security_headers(
    request: Request,
    call_next: Callable[[Request], Awaitable[Response]],
) -> Response:
    response = await call_next(request)
    for header, value in SECURITY_HEADERS.items():
        response.headers.setdefault(header, value)
    return response


async def _rate_limit_guard(
    request: Request,
    call_next: Callable[[Request], Awaitable[Response]],
) -> Response:
    active_settings = workbench_settings(request, required=False)
    key_and_limit = rate_limit_key(request, active_settings)
    limiter = getattr(request.app.state, "rate_limiter", None)
    if key_and_limit is not None and isinstance(limiter, RateLimiter):
        key, limit = key_and_limit
        decision = limiter.check(key, limit=limit)
        if not decision.allowed:
            return JSONResponse(
                status_code=429,
                content=error_response_content(
                    status_code=429,
                    detail="Too many requests.",
                    request=request,
                ),
                headers={"Retry-After": str(decision.retry_after_seconds)},
            )
    return await call_next(request)


async def _upload_size_guard(
    request: Request,
    call_next: Callable[[Request], Awaitable[Response]],
) -> Response:
    if request.method == "POST":
        active_settings = workbench_settings(request, required=False)
        max_request_bytes = _request_size_limit(request.url.path, active_settings)
        if max_request_bytes is None:
            return await call_next(request)
        limit_detail = _request_too_large_detail(request.url.path)
        raw_content_length = request.headers.get("content-length")
        if raw_content_length is not None:
            try:
                content_length = int(raw_content_length)
            except ValueError:
                content_length = 0
            if content_length > max_request_bytes:
                return JSONResponse(
                    status_code=413,
                    content=error_response_content(
                        status_code=413,
                        detail=limit_detail,
                        request=request,
                    ),
                )
        consumed_bytes = 0
        receive = request._receive

        async def limited_receive() -> Message:
            nonlocal consumed_bytes
            message = await receive()
            if message.get("type") == "http.request":
                consumed_bytes += len(message.get("body", b""))
                if consumed_bytes > max_request_bytes:
                    raise RequestEntityTooLarge
            return message

        request._receive = limited_receive
        try:
            return await call_next(request)
        except RequestEntityTooLarge:
            return JSONResponse(
                status_code=413,
                content=error_response_content(
                    status_code=413,
                    detail=limit_detail,
                    request=request,
                ),
            )
    return await call_next(request)


def _request_size_limit(path: str, active_settings: Settings) -> int | None:
    if _is_workbench_auth_body_path(path):
        return _AUTH_REQUEST_MAX_BYTES
    if _is_workbench_upload_path(path, active_settings.API_V1_STR):
        return active_settings.max_upload_bytes + 64 * 1024
    return None


def _is_workbench_auth_body_path(path: str) -> bool:
    return (
        path.endswith("/login/access-token")
        or path.endswith("/login/logout")
        or path.endswith("/login/test-token")
    )


def _request_too_large_detail(path: str) -> str:
    if _is_workbench_auth_body_path(path):
        return "Request body exceeds configured limit."
    return "Upload exceeds configured limit."


def _is_workbench_upload_path(path: str, api_prefix: str) -> bool:
    normalized_prefix = f"/{api_prefix.strip('/')}"
    return path.startswith(f"{normalized_prefix}/projects/") and (
        path.endswith("/imports") or path.endswith("/assets/import")
    )


class RequestEntityTooLarge(Exception):
    """Raised when an upload stream exceeds the configured request limit."""


app = create_app()

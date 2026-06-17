"""FastAPI entrypoint for the active Workbench runtime."""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.routing import APIRoute
from sqlalchemy.engine import Engine
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
from app.api.main import api_router, assert_api_local_actor_policy
from app.core.app_state import configure_workbench_state, workbench_settings
from app.core.config import Settings, settings
from app.core.db import create_db_engine
from app.core.local_schema_bootstrap import bootstrap_local_sqlite_schema
from app.core.rate_limit import RateLimiter, create_rate_limiter, rate_limit_key
from app.core.schema_smoke import assert_migrated_schema
from app.services.provider_updates import reconcile_stale_provider_update_runs

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
    configure_workbench_state(
        app,
        active_settings=selected_settings,
        active_engine=active_engine,
    )
    app.state.rate_limiter = create_rate_limiter(selected_settings, active_engine)
    if selected_settings.ENVIRONMENT == "local":
        app.router.on_startup.append(
            lambda: bootstrap_local_sqlite_schema(active_engine, selected_settings)
        )
    else:
        app.router.on_startup.append(lambda: assert_migrated_schema(active_engine))
    app.router.on_startup.append(
        lambda: _reconcile_stale_import_runs_on_startup(active_engine, selected_settings)
    )
    app.router.on_shutdown.append(lambda: active_engine.dispose())
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
            allow_headers=["Content-Type", "Accept"],
        )
    app.middleware("http")(_rate_limit_guard)
    app.middleware("http")(_upload_size_guard)
    app.middleware("http")(_security_headers)
    app.include_router(api_router, prefix=selected_settings.API_V1_STR)
    assert_api_local_actor_policy(selected_settings.API_V1_STR, app.routes)
    app.add_exception_handler(StarletteHTTPException, http_exception_handler)
    app.add_exception_handler(RequestValidationError, validation_error_handler)
    app.add_exception_handler(Exception, unhandled_exception_handler)
    install_error_openapi_schema(app)
    return app


def _reconcile_stale_import_runs_on_startup(
    active_engine: Engine,
    selected_settings: Settings,
) -> int:
    """Reconcile stale local jobs without breaking first-run local schema setup."""
    try:
        reconciled = reconcile_stale_provider_update_runs(
            engine=active_engine,
            settings=selected_settings,
        )
        return reconciled
    except Exception:
        if selected_settings.ENVIRONMENT == "local":
            return 0
        raise


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
    if _request_method_can_have_bounded_body(request.method):
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
    if _is_workbench_upload_path(path, active_settings.API_V1_STR):
        return active_settings.max_upload_bytes + 64 * 1024
    if _is_bounded_api_write_path(path, active_settings.API_V1_STR):
        return active_settings.max_request_body_bytes
    return None


def _request_too_large_detail(path: str) -> str:
    if path.endswith("/imports") or path.endswith("/assets/import"):
        return "Upload exceeds configured limit."
    return "Request body exceeds configured limit."


def _is_bounded_api_write_path(path: str, api_prefix: str) -> bool:
    normalized_prefix = f"/{api_prefix.strip('/')}"
    return path.startswith(f"{normalized_prefix}/")


def _request_method_can_have_bounded_body(method: str) -> bool:
    return method in {"POST", "PUT", "PATCH"}


def _is_workbench_upload_path(path: str, api_prefix: str) -> bool:
    normalized_prefix = f"/{api_prefix.strip('/')}"
    return path.startswith(f"{normalized_prefix}/projects/") and (
        path.endswith("/imports") or path.endswith("/assets/import")
    )


class RequestEntityTooLarge(Exception):
    """Raised when an upload stream exceeds the configured request limit."""


app = create_app()

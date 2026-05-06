"""Template-aligned FastAPI entrypoint for the active Workbench runtime."""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.routing import APIRoute
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.responses import JSONResponse, Response

from app.api.errors import (
    error_response_content,
    http_exception_handler,
    unhandled_exception_handler,
    validation_error_handler,
)
from app.api.main import api_router
from app.core.config import Settings, settings
from app.core.db import create_db_engine
from app.core.rate_limit import InMemoryRateLimiter, rate_limit_key

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
    """Use the official template operation-id convention for generated clients."""
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
    app.state.template_settings = selected_settings
    app.state.template_engine = create_db_engine(selected_settings)
    app.state.rate_limiter = InMemoryRateLimiter()
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
    active_settings = getattr(request.app.state, "template_settings", settings)
    if isinstance(active_settings, Settings):
        key_and_limit = rate_limit_key(request, active_settings)
        limiter = getattr(request.app.state, "rate_limiter", None)
        if key_and_limit is not None and isinstance(limiter, InMemoryRateLimiter):
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
    if request.method == "POST" and _is_template_upload_path(request.url.path):
        raw_content_length = request.headers.get("content-length")
        if raw_content_length is not None:
            try:
                content_length = int(raw_content_length)
            except ValueError:
                content_length = 0
            active_settings = getattr(request.app.state, "template_settings", None)
            if isinstance(active_settings, Settings):
                multipart_overhead = 64 * 1024
                if content_length > active_settings.max_upload_bytes + multipart_overhead:
                    return JSONResponse(
                        status_code=413,
                        content=error_response_content(
                            status_code=413,
                            detail="Upload exceeds configured limit.",
                            request=request,
                        ),
                    )
    return await call_next(request)


def _is_template_upload_path(path: str) -> bool:
    return path.startswith("/api/v1/projects/") and (
        path.endswith("/imports") or path.endswith("/assets/import")
    )


app = create_app()

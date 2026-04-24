"""FastAPI application factory for Vuln Prioritizer Workbench."""

from __future__ import annotations

import secrets
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.engine import Engine
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.responses import Response

from vuln_prioritizer.api.routes import api_router
from vuln_prioritizer.api.security import api_token_digest
from vuln_prioritizer.db import create_db_engine, create_session_factory
from vuln_prioritizer.db.migrations import ensure_database_current
from vuln_prioritizer.db.repositories import WorkbenchRepository
from vuln_prioritizer.web.routes import templates, web_router
from vuln_prioritizer.workbench_config import (
    WorkbenchSettings,
    ensure_workbench_directories,
    load_workbench_settings,
    sqlite_path_from_url,
)


def create_app(
    settings: WorkbenchSettings | None = None,
    *,
    initialize_database: bool = True,
) -> FastAPI:
    """Create the Workbench ASGI application."""
    active_settings = settings or load_workbench_settings()
    ensure_workbench_directories(active_settings)
    _ensure_sqlite_parent(active_settings.database_url)

    engine = create_db_engine(active_settings.database_url)
    if initialize_database:
        ensure_database_current(active_settings.database_url)

    app = FastAPI(
        title="Vuln Prioritizer Workbench",
        version="0.2.0-workbench-mvp",
    )
    app.state.workbench_settings = active_settings
    app.state.db_engine = engine
    app.state.session_factory = create_session_factory(engine)

    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=list(active_settings.allowed_hosts),
    )
    app.middleware("http")(_api_token_auth)
    app.middleware("http")(_upload_size_guard)
    app.middleware("http")(_security_headers)
    app.mount(
        "/static",
        StaticFiles(directory=str(Path(__file__).parents[1] / "web" / "static")),
        name="static",
    )
    app.include_router(api_router)
    app.include_router(web_router)
    app.add_exception_handler(HTTPException, _http_error_handler)
    app.add_exception_handler(RequestValidationError, _validation_error_handler)
    app.add_exception_handler(Exception, _unexpected_error_handler)
    return app


async def _security_headers(request: Request, call_next: Any) -> Any:
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    response.headers.setdefault(
        "Permissions-Policy",
        "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    )
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; base-uri 'none'; object-src 'none'; "
        "script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "connect-src 'self'; frame-ancestors 'none'",
    )
    return response


async def _api_token_auth(request: Request, call_next: Any) -> Any:
    if not _requires_api_token_check(request):
        return await call_next(request)
    session_factory = getattr(request.app.state, "session_factory", None)
    if session_factory is None:
        return await call_next(request)
    with session_factory() as session:
        repo = WorkbenchRepository(session)
        if not repo.has_active_api_tokens():
            return await call_next(request)
        raw_token = _request_api_token(request)
        if raw_token is None:
            return JSONResponse(
                status_code=403,
                content=_error_payload(
                    detail="API token required.",
                    code="forbidden",
                    message="API token required.",
                    details=None,
                ),
            )
        token_hash = api_token_digest(raw_token)
        token = repo.get_active_api_token_by_hash(token_hash)
        if token is None or not secrets.compare_digest(token.token_hash, token_hash):
            return JSONResponse(
                status_code=403,
                content=_error_payload(
                    detail="Invalid API token.",
                    code="forbidden",
                    message="Invalid API token.",
                    details=None,
                ),
            )
        repo.mark_api_token_used(token)
        session.commit()
    return await call_next(request)


def _requires_api_token_check(request: Request) -> bool:
    if request.method not in {"POST", "PUT", "PATCH", "DELETE"}:
        return False
    return request.url.path.startswith("/api/")


def _request_api_token(request: Request) -> str | None:
    authorization = request.headers.get("authorization", "")
    if authorization.lower().startswith("bearer "):
        token = authorization[7:].strip()
        return token or None
    token = request.headers.get("x-api-token", "").strip()
    return token or None


async def _upload_size_guard(request: Request, call_next: Any) -> Any:
    if request.method == "POST" and _is_import_upload_path(request.url.path):
        raw_content_length = request.headers.get("content-length")
        if raw_content_length is not None:
            try:
                content_length = int(raw_content_length)
            except ValueError:
                content_length = 0
            settings = getattr(request.app.state, "workbench_settings", None)
            if isinstance(settings, WorkbenchSettings):
                multipart_overhead = 64 * 1024
                if content_length > settings.max_upload_bytes + multipart_overhead:
                    return JSONResponse(
                        status_code=413,
                        content={"detail": "Upload exceeds configured limit."},
                    )
    return await call_next(request)


def _is_import_upload_path(path: str) -> bool:
    is_project_import = path.startswith("/api/projects/") or path.startswith("/web/projects/")
    return is_project_import and path.endswith("/imports")


async def _unexpected_error_handler(_request: Request, exc: Exception) -> Response:
    if _should_render_html_error(_request):
        return _html_error_response(
            _request,
            status_code=500,
            code="internal_error",
            message="Internal Workbench error.",
            details=None,
        )
    return JSONResponse(
        status_code=500,
        content=_error_payload(
            detail="Internal Workbench error.",
            code="internal_error",
            message="Internal Workbench error.",
            details=None,
        ),
    )


async def _http_error_handler(_request: Request, exc: Exception) -> Response:
    if not isinstance(exc, HTTPException):
        return await _unexpected_error_handler(_request, exc)
    code = _http_error_code(exc.status_code)
    message = _detail_message(exc.detail, fallback=_http_status_title(exc.status_code))
    details = exc.detail if not isinstance(exc.detail, str) else None
    if _should_render_html_error(_request):
        return _html_error_response(
            _request,
            status_code=exc.status_code,
            code=code,
            message=message,
            details=details,
            headers=exc.headers,
        )
    return JSONResponse(
        status_code=exc.status_code,
        headers=exc.headers,
        content=_error_payload(
            detail=exc.detail,
            code=code,
            message=message,
            details=details,
        ),
    )


async def _validation_error_handler(
    _request: Request,
    exc: Exception,
) -> Response:
    if not isinstance(exc, RequestValidationError):
        return await _unexpected_error_handler(_request, exc)
    detail = exc.errors()
    if _should_render_html_error(_request):
        return _html_error_response(
            _request,
            status_code=422,
            code="validation_error",
            message="Request validation failed.",
            details=detail,
        )
    return JSONResponse(
        status_code=422,
        content=_error_payload(
            detail=detail,
            code="validation_error",
            message="Request validation failed.",
            details=detail,
        ),
    )


def _error_payload(*, detail: Any, code: str, message: str, details: Any | None) -> dict[str, Any]:
    return {
        "detail": detail,
        "error": {
            "code": code,
            "message": message,
            "details": details,
        },
    }


def _should_render_html_error(request: Request) -> bool:
    path = request.url.path
    return not (path.startswith("/api/") or path.startswith("/static/"))


def _html_error_response(
    request: Request,
    *,
    status_code: int,
    code: str,
    message: str,
    details: Any | None,
    headers: Mapping[str, str] | None = None,
) -> Response:
    return templates.TemplateResponse(
        request,
        "error.html",
        {
            "project": None,
            "status_code": status_code,
            "error_title": _http_status_title(status_code),
            "error_code": code,
            "error_message": message,
            "error_details": details,
        },
        status_code=status_code,
        headers=headers,
    )


def _detail_message(detail: Any, *, fallback: str) -> str:
    if isinstance(detail, str):
        return detail
    if isinstance(detail, dict) and isinstance(detail.get("message"), str):
        return detail["message"]
    return fallback


def _http_error_code(status_code: int) -> str:
    if status_code == 404:
        return "not_found"
    if status_code == 409:
        return "conflict"
    if status_code == 413:
        return "payload_too_large"
    if status_code == 422:
        return "validation_error"
    if status_code == 403:
        return "forbidden"
    return "http_error"


def _http_status_title(status_code: int) -> str:
    if status_code == 403:
        return "Forbidden"
    if status_code == 404:
        return "Not found"
    if status_code == 409:
        return "Conflict"
    if status_code == 413:
        return "Payload too large"
    if status_code == 422:
        return "Validation error"
    if status_code == 500:
        return "Internal error"
    return "Request failed"


def _ensure_sqlite_parent(database_url: str) -> None:
    sqlite_path = sqlite_path_from_url(database_url)
    if sqlite_path is not None:
        sqlite_path.parent.mkdir(parents=True, exist_ok=True)


def main(host: str = "127.0.0.1", port: int = 8000) -> None:
    """Run the Workbench app via Uvicorn."""
    uvicorn.run("vuln_prioritizer.api.app:create_app", factory=True, host=host, port=port)


def get_engine(app: FastAPI) -> Engine:
    """Return the app engine for tests and diagnostics."""
    engine = getattr(app.state, "db_engine")
    if not isinstance(engine, Engine):
        raise RuntimeError("Workbench database engine is not configured.")
    return engine

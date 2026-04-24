"""FastAPI application factory for Vuln Prioritizer Workbench."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.engine import Engine

from vuln_prioritizer.api.routes import api_router
from vuln_prioritizer.db import create_db_engine, create_schema, create_session_factory
from vuln_prioritizer.web.routes import web_router
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
        create_schema(engine)

    app = FastAPI(
        title="Vuln Prioritizer Workbench",
        version="0.2.0-workbench-mvp",
    )
    app.state.workbench_settings = active_settings
    app.state.db_engine = engine
    app.state.session_factory = create_session_factory(engine)

    app.middleware("http")(_security_headers)
    app.mount(
        "/static",
        StaticFiles(directory=str(Path(__file__).parents[1] / "web" / "static")),
        name="static",
    )
    app.include_router(api_router)
    app.include_router(web_router)
    app.add_exception_handler(Exception, _unexpected_error_handler)
    return app


async def _security_headers(request: Request, call_next: Any) -> Any:
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Frame-Ancestors", "'none'")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "connect-src 'self'; frame-ancestors 'none'",
    )
    return response


async def _unexpected_error_handler(_request: Request, exc: Exception) -> JSONResponse:
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal Workbench error.", "error": exc.__class__.__name__},
    )


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

"""Workbench routes exposed through the active API namespace."""

from __future__ import annotations

from fastapi import APIRouter, Request
from sqlalchemy import inspect, text
from sqlalchemy.exc import SQLAlchemyError
from sqlmodel import Session

from app.api.deps import ScopedReadUser, SessionDep
from app.core.config import Settings, settings
from app.models import WorkbenchHealth, WorkbenchStatus
from vuln_prioritizer import __version__

router = APIRouter(prefix="/workbench", tags=["workbench"])

REQUIRED_SCHEMA_TABLES = frozenset(
    {
        "analysis_run",
        "api_token",
        "audit_event",
        "auth_session",
        "project",
        "user",
    }
)
REQUIRED_API_TOKEN_COLUMNS = frozenset({"id", "project_id", "token_hash"})


@router.get("/health", response_model=WorkbenchHealth)
def template_workbench_health() -> WorkbenchHealth:
    """Return minimal unauthenticated liveness for browser and proxy checks."""
    return WorkbenchHealth(status="ok")


@router.get("/status")
def template_workbench_status(
    request: Request,
    session: SessionDep,
    _current_user: ScopedReadUser,
) -> WorkbenchStatus:
    """Return authenticated active Workbench readiness and version status."""
    active_settings = _request_settings(request)
    database, schema = _database_readiness(session)
    return WorkbenchStatus(
        status="ok",
        app=active_settings.PROJECT_NAME,
        core_package="vuln_prioritizer",
        core_version=__version__,
        database_status=database,
        schema_status=schema,
    )


def _request_settings(request: Request) -> Settings:
    active_settings = getattr(request.app.state, "template_settings", settings)
    if isinstance(active_settings, Settings):
        return active_settings
    return settings


def _database_readiness(session: Session) -> tuple[str, str]:
    try:
        session.execute(text("SELECT 1")).one()
        inspector = inspect(session.get_bind())
        table_names = set(inspector.get_table_names())
        if not REQUIRED_SCHEMA_TABLES.issubset(table_names):
            return "ready", "not_ready"
        api_token_columns = {column["name"] for column in inspector.get_columns("api_token")}
        if not REQUIRED_API_TOKEN_COLUMNS.issubset(api_token_columns):
            return "ready", "not_ready"
    except SQLAlchemyError:
        return "unavailable", "not_ready"
    return "ready", "ready"

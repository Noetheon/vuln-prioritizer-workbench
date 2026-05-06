"""Workbench routes exposed through the active API namespace."""

from __future__ import annotations

from fastapi import APIRouter, Request
from sqlalchemy import inspect, text
from sqlalchemy.exc import SQLAlchemyError
from sqlmodel import Session, SQLModel

from app.api.deps import ScopedReadUser, SessionDep
from app.core.app_state import workbench_settings
from app.core.config import Settings
from app.core.migration_bootstrap import ALEMBIC_HEAD
from app.models import WorkbenchHealth, WorkbenchStatus
from vuln_prioritizer import __version__

router = APIRouter(prefix="/workbench", tags=["workbench"])

REQUIRED_SCHEMA_TABLES = frozenset(
    table_name for table_name in SQLModel.metadata.tables if table_name != "alembic_version"
)
REQUIRED_API_TOKEN_COLUMNS = frozenset({"id", "project_id", "token_hash"})
REQUIRED_ALEMBIC_TABLE = "alembic_version"


@router.get("/health", response_model=WorkbenchHealth)
def workbench_health() -> WorkbenchHealth:
    """Return minimal unauthenticated liveness for browser and proxy checks."""
    return WorkbenchHealth(status="ok")


@router.get("/status")
def workbench_status(
    request: Request,
    session: SessionDep,
    _current_user: ScopedReadUser,
) -> WorkbenchStatus:
    """Return authenticated active Workbench readiness and version status."""
    active_settings = _request_settings(request)
    database, schema = _database_readiness(session)
    return WorkbenchStatus(
        status="ready" if database == "ready" and schema == "ready" else "not_ready",
        app=active_settings.PROJECT_NAME,
        core_package="vuln_prioritizer",
        core_version=__version__,
        database_status=database,
        schema_status=schema,
    )


def _request_settings(request: Request) -> Settings:
    return workbench_settings(request, required=False)


def _database_readiness(session: Session) -> tuple[str, str]:
    try:
        session.execute(text("SELECT 1")).one()
        inspector = inspect(session.get_bind())
        table_names = set(inspector.get_table_names())
        if not REQUIRED_SCHEMA_TABLES.issubset(table_names):
            return "ready", "not_ready"
        if REQUIRED_ALEMBIC_TABLE not in table_names:
            return "ready", "not_ready"
        if not _alembic_head_is_current(session):
            return "ready", "not_ready"
        api_token_columns = {column["name"] for column in inspector.get_columns("api_token")}
        if not REQUIRED_API_TOKEN_COLUMNS.issubset(api_token_columns):
            return "ready", "not_ready"
    except SQLAlchemyError:
        return "unavailable", "not_ready"
    return "ready", "ready"


def _alembic_head_is_current(session: Session) -> bool:
    rows = session.execute(text("SELECT version_num FROM alembic_version")).all()
    versions = {str(row[0]) for row in rows}
    return ALEMBIC_HEAD in versions

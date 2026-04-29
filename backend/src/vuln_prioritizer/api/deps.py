"""FastAPI dependencies for the Workbench app."""

from __future__ import annotations

from collections.abc import Generator

from fastapi import Request
from sqlalchemy.orm import Session, sessionmaker

from vuln_prioritizer.workbench_config import WorkbenchSettings


def get_workbench_settings(request: Request) -> WorkbenchSettings:
    """Return settings stored on the FastAPI app state."""
    settings = getattr(request.app.state, "workbench_settings")
    if not isinstance(settings, WorkbenchSettings):
        raise RuntimeError("Workbench settings are not configured.")
    return settings


def get_db_session(request: Request) -> Generator[Session, None, None]:
    """Yield a request-scoped SQLAlchemy session."""
    factory = getattr(request.app.state, "session_factory")
    if not isinstance(factory, sessionmaker):
        raise RuntimeError("Workbench database is not configured.")
    session = factory()
    try:
        yield session
    finally:
        session.close()

"""Database helpers for the active Workbench backend runtime."""

from __future__ import annotations

from sqlalchemy.engine import Engine
from sqlmodel import Session, create_engine

from app.core.config import Settings, settings


def _connect_args(database_uri: str) -> dict[str, bool]:
    if database_uri.startswith("sqlite"):
        return {"check_same_thread": False}
    return {}


def create_db_engine(active_settings: Settings) -> Engine:
    """Create a SQLAlchemy engine for one concrete settings object."""
    return create_engine(
        active_settings.SQLALCHEMY_DATABASE_URI,
        connect_args=_connect_args(active_settings.SQLALCHEMY_DATABASE_URI),
        pool_pre_ping=True,
    )


engine = create_db_engine(settings)


def init_db(session: Session, active_settings: Settings | None = None) -> None:
    """Retained entrypoint for startup hooks; local runtime needs no DB bootstrap."""
    _ = (session, active_settings)

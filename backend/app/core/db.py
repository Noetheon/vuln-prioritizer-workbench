"""Database helpers for the active Workbench backend runtime."""

from __future__ import annotations

from typing import Any

from sqlalchemy import event
from sqlalchemy.engine import Engine
from sqlmodel import Session, create_engine

from app.core.config import Settings, settings


def _connect_args(database_uri: str) -> dict[str, Any]:
    if database_uri.startswith("sqlite"):
        return {"check_same_thread": False, "timeout": 30}
    return {}


def create_db_engine(active_settings: Settings) -> Engine:
    """Create a SQLAlchemy engine for one concrete settings object."""
    active_engine = create_engine(
        active_settings.SQLALCHEMY_DATABASE_URI,
        connect_args=_connect_args(active_settings.SQLALCHEMY_DATABASE_URI),
        pool_pre_ping=True,
    )
    if active_settings.SQLALCHEMY_DATABASE_URI.startswith("sqlite"):
        configure_sqlite_connections(
            active_engine,
            enable_wal=_is_file_sqlite_uri(active_settings.SQLALCHEMY_DATABASE_URI),
        )
    return active_engine


def configure_sqlite_connections(engine: Engine, *, enable_wal: bool) -> None:
    """Enable the SQLite integrity and concurrency invariants on every connection."""

    @event.listens_for(engine, "connect")
    def set_sqlite_pragmas(dbapi_connection: Any, _connection_record: Any) -> None:
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA busy_timeout=30000")
            if enable_wal:
                cursor.execute("PRAGMA journal_mode=WAL")
                cursor.execute("PRAGMA synchronous=NORMAL")
                cursor.execute("PRAGMA wal_autocheckpoint=1000")
        finally:
            cursor.close()


def _is_file_sqlite_uri(database_uri: str) -> bool:
    normalized = database_uri.casefold()
    return normalized not in {"sqlite://", "sqlite:///:memory:"} and "mode=memory" not in normalized


engine = create_db_engine(settings)


def init_db(session: Session, active_settings: Settings | None = None) -> None:
    """Retained entrypoint for startup hooks; local runtime needs no DB bootstrap."""
    _ = (session, active_settings)

"""Engine and session helpers for the Workbench database."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from sqlalchemy import Engine, create_engine
from sqlalchemy.engine import URL
from sqlalchemy.orm import Session, sessionmaker

from vuln_prioritizer.db.base import metadata

SessionFactory = sessionmaker[Session]


def make_sqlite_url(db_path: Path | str) -> str:
    """Return a SQLAlchemy SQLite URL for a filesystem path or in-memory database."""
    value = str(db_path)
    if value == ":memory:":
        return "sqlite+pysqlite:///:memory:"
    return f"sqlite+pysqlite:///{Path(value)}"


def create_db_engine(
    database_url: str | URL,
    *,
    echo: bool = False,
    future: bool = True,
) -> Engine:
    """Create a SQLAlchemy engine for Workbench persistence."""
    return create_engine(database_url, echo=echo, future=future)


def create_sqlite_engine(db_path: Path | str, *, echo: bool = False) -> Engine:
    """Create a SQLite engine from a path-like value."""
    return create_db_engine(make_sqlite_url(db_path), echo=echo)


def create_session_factory(engine: Engine) -> SessionFactory:
    """Create the session factory used by repositories and request handlers."""
    return sessionmaker(bind=engine, expire_on_commit=False, future=True)


def create_schema(engine: Engine) -> None:
    """Create all Workbench tables from ORM metadata."""
    metadata.create_all(engine)


@contextmanager
def session_scope(factory: SessionFactory) -> Iterator[Session]:
    """Provide a transaction-scoped session."""
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()

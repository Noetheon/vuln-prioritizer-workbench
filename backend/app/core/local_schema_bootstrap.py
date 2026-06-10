"""Local-only schema bootstrap and repair helpers."""

from __future__ import annotations

from dataclasses import dataclass

from alembic import command
from sqlalchemy import inspect, text
from sqlalchemy.engine import Engine
from sqlmodel import SQLModel

from app.core.config import Settings
from app.core.migration_bootstrap import ALEMBIC_HEAD, _alembic_config
from app.core.schema_smoke import assert_migrated_schema, required_model_tables
from app.models import import_table_models


@dataclass(frozen=True, slots=True)
class LocalSchemaBootstrapResult:
    """Outcome of the local SQLite schema bootstrap."""

    status: str
    repaired: bool = False


def bootstrap_local_sqlite_schema(
    active_engine: Engine,
    active_settings: Settings,
) -> LocalSchemaBootstrapResult:
    """
    Bring a local SQLite Workbench database to a usable schema.

    This is intentionally scoped to local SQLite. Compose/Postgres and every
    non-local environment keep the stricter explicit migration/fail-fast model.
    """
    if active_settings.ENVIRONMENT != "local" or active_engine.dialect.name != "sqlite":
        return LocalSchemaBootstrapResult(status="skipped")

    if _schema_ready(active_engine):
        return LocalSchemaBootstrapResult(status="ready")

    try:
        _run_alembic_upgrade(active_settings.SQLALCHEMY_DATABASE_URI)
    except Exception:
        if not _can_repair_missing_sqlite_schema(active_engine):
            raise

    if _schema_ready(active_engine):
        return LocalSchemaBootstrapResult(status="migrated", repaired=True)

    if not _can_repair_missing_sqlite_schema(active_engine):
        assert_migrated_schema(active_engine)

    _repair_missing_sqlite_schema(active_engine)
    assert_migrated_schema(active_engine)
    return LocalSchemaBootstrapResult(status="repaired", repaired=True)


def _schema_ready(active_engine: Engine) -> bool:
    try:
        assert_migrated_schema(active_engine)
    except RuntimeError:
        return False
    return True


def _run_alembic_upgrade(database_uri: str) -> None:
    config = _alembic_config()
    config.set_main_option("sqlalchemy.url", database_uri)
    command.upgrade(config, "head")


def _can_repair_missing_sqlite_schema(active_engine: Engine) -> bool:
    inspector = inspect(active_engine)
    table_names = set(inspector.get_table_names())
    return bool(required_model_tables() - table_names) or "alembic_version" not in table_names


def _repair_missing_sqlite_schema(active_engine: Engine) -> None:
    import_table_models()
    SQLModel.metadata.create_all(active_engine)
    with active_engine.begin() as connection:
        table_names = set(inspect(connection).get_table_names())
        if "alembic_version" not in table_names:
            connection.execute(text("CREATE TABLE alembic_version (version_num VARCHAR(32))"))
        connection.execute(text("DELETE FROM alembic_version"))
        connection.execute(
            text("INSERT INTO alembic_version (version_num) VALUES (:version_num)"),
            {"version_num": ALEMBIC_HEAD},
        )

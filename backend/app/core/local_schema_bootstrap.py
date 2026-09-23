"""Local-only schema bootstrap and repair helpers."""

from __future__ import annotations

from dataclasses import dataclass

from alembic import command
from sqlalchemy import inspect, text
from sqlalchemy.engine import Engine
from sqlmodel import SQLModel

from app.core.config import Settings
from app.core.migration_bootstrap import ALEMBIC_HEAD, _alembic_config
from app.core.schema_smoke import (
    assert_migrated_schema,
    assert_required_model_columns,
    required_model_tables,
)
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

    repaired = False

    if not _schema_ready(active_engine):
        try:
            _run_alembic_upgrade(active_settings.SQLALCHEMY_DATABASE_URI)
        except Exception:
            if not _can_repair_missing_sqlite_schema(active_engine):
                raise

        if _schema_ready(active_engine):
            repaired = True
        else:
            if not _can_repair_missing_sqlite_schema(active_engine):
                assert_migrated_schema(active_engine)

            _repair_missing_sqlite_schema(active_engine)
            repaired = True

    legacy_tables = _legacy_blocking_column_tables(active_engine)
    for table_name in legacy_tables:
        _rebuild_sqlite_table(active_engine, table_name)
        repaired = True

    remaining_legacy_tables = _legacy_blocking_column_tables(active_engine)
    if remaining_legacy_tables:
        raise RuntimeError(
            "Local SQLite schema still has blocking legacy columns in: "
            + ", ".join(remaining_legacy_tables)
        )

    assert_migrated_schema(active_engine)
    return LocalSchemaBootstrapResult(
        status="repaired" if repaired else "ready",
        repaired=repaired,
    )


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
    """Only complete empty schemas can be reconstructed without inventing history."""
    with active_engine.connect() as connection:
        table_names = set(inspect(connection).get_table_names())
        if not (required_model_tables() - table_names or "alembic_version" not in table_names):
            return False
        if "alembic_version" in table_names:
            versions = tuple(
                connection.execute(text("SELECT version_num FROM alembic_version")).scalars()
            )
            if versions not in ((), (ALEMBIC_HEAD,)):
                return False
        try:
            assert_required_model_columns(connection)
        except RuntimeError:
            return False
        for table_name in required_model_tables() & table_names:
            if connection.execute(
                text(f"SELECT 1 FROM {_quote_identifier(table_name)} LIMIT 1")
            ).first():
                return False
    return True


def _legacy_blocking_column_tables(active_engine: Engine) -> tuple[str, ...]:
    import_table_models()
    with active_engine.connect() as connection:
        inspector = inspect(connection)
        actual_table_names = set(inspector.get_table_names())
        drifted_tables: list[str] = []
        for table_name, table in SQLModel.metadata.tables.items():
            if table_name == "alembic_version" or table_name not in actual_table_names:
                continue
            expected_columns = {column.name for column in table.columns}
            for column in inspector.get_columns(table_name):
                if (
                    column["name"] not in expected_columns
                    and not column.get("nullable", True)
                    and column.get("default") is None
                ):
                    drifted_tables.append(table_name)
                    break
    return tuple(drifted_tables)


def _repair_missing_sqlite_schema(active_engine: Engine) -> None:
    import_table_models()
    with active_engine.begin() as connection:
        connection.exec_driver_sql("BEGIN IMMEDIATE")
        SQLModel.metadata.create_all(connection)
        table_names = set(inspect(connection).get_table_names())
        if "alembic_version" not in table_names:
            connection.execute(text("CREATE TABLE alembic_version (version_num VARCHAR(32))"))
        connection.execute(text("DELETE FROM alembic_version"))
        connection.execute(
            text("INSERT INTO alembic_version (version_num) VALUES (:version_num)"),
            {"version_num": ALEMBIC_HEAD},
        )


def _rebuild_sqlite_table(active_engine: Engine, table_name: str) -> None:
    import_table_models()
    table = SQLModel.metadata.tables[table_name]
    backup_table_name = f"_{table_name}_legacy_repair"
    with active_engine.connect().execution_options(isolation_level="AUTOCOMMIT") as connection:
        assert_required_model_columns(connection)
        previous_fk = connection.exec_driver_sql("PRAGMA foreign_keys").scalar_one()
        previous_alter = connection.exec_driver_sql("PRAGMA legacy_alter_table").scalar_one()
        connection.exec_driver_sql("PRAGMA foreign_keys=OFF")
        connection.exec_driver_sql("PRAGMA legacy_alter_table=ON")
        connection.exec_driver_sql("BEGIN IMMEDIATE")
        try:
            if backup_table_name in inspect(connection).get_table_names():
                raise RuntimeError(f"Unresolved earlier schema repair: {backup_table_name}")
            # Reflection omits SQLite expression indexes. Read their real names
            # so rebuilding an occurrence table remains atomic and reproducible.
            index_names = list(
                connection.execute(
                    text(
                        "SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = :table "
                        "AND sql IS NOT NULL"
                    ),
                    {"table": table_name},
                ).scalars()
            )
            connection.execute(
                text(
                    f"ALTER TABLE {_quote_identifier(table_name)} "
                    f"RENAME TO {_quote_identifier(backup_table_name)}"
                )
            )
            for index_name in index_names:
                connection.execute(text(f"DROP INDEX IF EXISTS {_quote_identifier(index_name)}"))
            table.create(bind=connection)
            old_columns = {
                row[1]
                for row in connection.execute(
                    text(f"PRAGMA table_info({_quote_identifier(backup_table_name)})")
                ).all()
            }
            copy_columns = [column.name for column in table.columns if column.name in old_columns]
            if copy_columns:
                column_list = ", ".join(_quote_identifier(column) for column in copy_columns)
                connection.execute(
                    text(
                        f"INSERT INTO {_quote_identifier(table_name)} ({column_list}) "
                        f"SELECT {column_list} FROM {_quote_identifier(backup_table_name)}"
                    )
                )
            connection.execute(text(f"DROP TABLE {_quote_identifier(backup_table_name)}"))
            if connection.exec_driver_sql("PRAGMA foreign_key_check").first() is not None:
                raise RuntimeError("Schema repair would leave invalid foreign-key references.")
            connection.exec_driver_sql("COMMIT")
        except Exception:
            connection.exec_driver_sql("ROLLBACK")
            raise
        finally:
            connection.exec_driver_sql(f"PRAGMA legacy_alter_table={int(previous_alter)}")
            connection.exec_driver_sql(f"PRAGMA foreign_keys={int(previous_fk)}")


def _quote_identifier(identifier: str) -> str:
    return '"' + identifier.replace('"', '""') + '"'

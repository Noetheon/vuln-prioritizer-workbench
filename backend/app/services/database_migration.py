"""Verified cross-database copy support for the local runtime transition."""

from __future__ import annotations

import base64
import hashlib
import json
import math
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime
from decimal import Decimal
from enum import Enum
from pathlib import Path
from typing import Any

from sqlalchemy import Connection, Engine, inspect, select, text
from sqlmodel import Session, SQLModel

from app import models as _models  # noqa: F401 - registers every SQLModel table
from app.core.migration_bootstrap import ALEMBIC_HEAD
from app.repositories.current_projections import FindingCurrentProjectionRepository


class DatabaseMigrationInvariantError(RuntimeError):
    """Raised when a database copy cannot prove exact data parity."""


@dataclass(frozen=True, slots=True)
class TableMigrationParity:
    """Count and digest evidence for one copied table."""

    table: str
    rows: int
    sha256: str


@dataclass(frozen=True, slots=True)
class DatabaseMigrationResult:
    """Verified result for a complete application-database copy."""

    revision: str
    tables: tuple[TableMigrationParity, ...]

    @property
    def total_rows(self) -> int:
        """Return the number of copied application rows."""
        return sum(table.rows for table in self.tables)


def copy_database_with_parity(
    source_engine: Engine,
    target_engine: Engine,
    *,
    batch_size: int = 500,
    target_report_root: Path | None = None,
) -> DatabaseMigrationResult:
    """Copy the current schema and prove row-level parity before returning."""
    bounded_batch_size = max(1, min(batch_size, 2_000))
    _require_revision(source_engine, role="source")
    _require_revision(target_engine, role="target")
    tables = tuple(SQLModel.metadata.sorted_tables)
    _require_schema(source_engine, tables, role="source")
    _require_schema(target_engine, tables, role="target")
    _require_decision_ledger_parity(source_engine, role="source")

    source_connection = source_engine.connect()
    if source_engine.dialect.name == "postgresql":
        source_connection = source_connection.execution_options(isolation_level="REPEATABLE READ")
    target_connection = target_engine.connect()
    try:
        _prepare_target_connection(target_connection, target_engine)
        parity_rows: list[TableMigrationParity] = []
        with source_connection.begin(), target_connection.begin():
            _require_empty_target(target_connection, tables)
            for table in tables:
                source_digest = hashlib.sha256()
                copied = 0
                batch: list[dict[str, Any]] = []
                statement = select(table)
                if len(table.primary_key.columns) > 0:
                    statement = statement.order_by(*table.primary_key.columns)
                source_rows = source_connection.execute(statement).mappings()
                for row in source_rows:
                    values = {column.name: row[column.name] for column in table.columns}
                    values = _target_values(
                        table.name,
                        values,
                        target_report_root=target_report_root,
                    )
                    _update_row_digest(source_digest, table.name, values)
                    batch.append(values)
                    copied += 1
                    if len(batch) >= bounded_batch_size:
                        target_connection.execute(table.insert(), batch)
                        batch.clear()
                if batch:
                    target_connection.execute(table.insert(), batch)
                target_count, target_digest = _table_digest(target_connection, table)
                source_hex = source_digest.hexdigest()
                if target_count != copied or target_digest != source_hex:
                    raise DatabaseMigrationInvariantError(
                        f"Data parity failed for {table.name}: "
                        f"source={copied}/{source_hex}, "
                        f"target={target_count}/{target_digest}."
                    )
                parity_rows.append(
                    TableMigrationParity(
                        table=table.name,
                        rows=copied,
                        sha256=source_hex,
                    )
                )
        _validate_target_constraints(target_connection, target_engine)
        _require_decision_ledger_parity(target_engine, role="target")
        return DatabaseMigrationResult(revision=ALEMBIC_HEAD, tables=tuple(parity_rows))
    finally:
        target_connection.close()
        source_connection.close()


def _require_revision(engine: Engine, *, role: str) -> None:
    inspector = inspect(engine)
    if "alembic_version" not in inspector.get_table_names():
        raise DatabaseMigrationInvariantError(f"The {role} database has no Alembic revision.")
    with engine.connect() as connection:
        revisions = tuple(
            str(row[0])
            for row in connection.execute(text("SELECT version_num FROM alembic_version"))
        )
    if revisions != (ALEMBIC_HEAD,):
        rendered = ", ".join(revisions) if revisions else "none"
        raise DatabaseMigrationInvariantError(
            f"The {role} database must be at Alembic head {ALEMBIC_HEAD}; found {rendered}."
        )


def _require_schema(engine: Engine, tables: Sequence[Any], *, role: str) -> None:
    inspector = inspect(engine)
    available = set(inspector.get_table_names())
    missing_tables = sorted(table.name for table in tables if table.name not in available)
    if missing_tables:
        raise DatabaseMigrationInvariantError(
            f"The {role} database is missing tables: {', '.join(missing_tables)}."
        )
    for table in tables:
        expected = {column.name for column in table.columns}
        actual = {column["name"] for column in inspector.get_columns(table.name)}
        if actual != expected:
            missing = sorted(expected - actual)
            unexpected = sorted(actual - expected)
            raise DatabaseMigrationInvariantError(
                f"The {role} table {table.name} has schema drift; "
                f"missing={missing}, unexpected={unexpected}."
            )


def _require_decision_ledger_parity(engine: Engine, *, role: str) -> None:
    with Session(engine) as session:
        result = FindingCurrentProjectionRepository(session).verify_all_source_parity()
    if result.matches:
        return
    preview = ", ".join(result.mismatches[:20])
    suffix = "" if len(result.mismatches) <= 20 else ", ..."
    raise DatabaseMigrationInvariantError(
        f"The {role} Decision Ledger failed parity after {result.checked} checks: "
        f"{preview}{suffix}."
    )


def _prepare_target_connection(connection: Connection, engine: Engine) -> None:
    if engine.dialect.name != "sqlite":
        return
    connection.exec_driver_sql("PRAGMA foreign_keys=OFF")
    connection.commit()


def _require_empty_target(connection: Connection, tables: Sequence[Any]) -> None:
    populated = [
        table.name
        for table in tables
        if int(connection.execute(select(text("count(*)")).select_from(table)).scalar_one()) > 0
    ]
    if populated:
        raise DatabaseMigrationInvariantError(
            "The target database must be empty; populated tables: " + ", ".join(populated)
        )


def _table_digest(connection: Connection, table: Any) -> tuple[int, str]:
    digest = hashlib.sha256()
    count = 0
    statement = select(table)
    if len(table.primary_key.columns) > 0:
        statement = statement.order_by(*table.primary_key.columns)
    for row in connection.execute(statement).mappings():
        values = {column.name: row[column.name] for column in table.columns}
        _update_row_digest(digest, table.name, values)
        count += 1
    return count, digest.hexdigest()


def _update_row_digest(digest: Any, table_name: str, values: Mapping[str, Any]) -> None:
    payload = {
        "table": table_name,
        "values": {key: _canonical_value(value) for key, value in values.items()},
    }
    digest.update(
        json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    )
    digest.update(b"\n")


def _target_values(
    table_name: str,
    values: dict[str, Any],
    *,
    target_report_root: Path | None,
) -> dict[str, Any]:
    """Apply explicit runtime-location transforms before parity hashing and insert."""
    if table_name != "report" or target_report_root is None:
        return values
    migrated = dict(values)
    migrated["path"] = str(
        target_report_root
        / str(values["project_id"])
        / str(values["analysis_run_id"])
        / str(values["id"])
        / str(values["filename"])
    )
    return migrated


def _canonical_value(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise DatabaseMigrationInvariantError("Non-finite floats cannot be migrated safely.")
        return {"$float": format(value, ".17g")}
    if isinstance(value, Decimal):
        return {"$decimal": format(value, "f")}
    if isinstance(value, uuid.UUID):
        return {"$uuid": str(value)}
    if isinstance(value, datetime):
        normalized = value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
        return {"$datetime": normalized.isoformat(timespec="microseconds")}
    if isinstance(value, date):
        return {"$date": value.isoformat()}
    if isinstance(value, bytes):
        return {"$bytes": base64.b64encode(value).decode("ascii")}
    if isinstance(value, Enum):
        return {"$enum": _canonical_value(value.value)}
    if isinstance(value, Mapping):
        return {
            str(key): _canonical_value(item)
            for key, item in sorted(value.items(), key=lambda item: str(item[0]))
        }
    if isinstance(value, (list, tuple)):
        return [_canonical_value(item) for item in value]
    raise DatabaseMigrationInvariantError(
        f"Unsupported database value type during parity hashing: {type(value).__name__}."
    )


def _validate_target_constraints(connection: Connection, engine: Engine) -> None:
    if engine.dialect.name != "sqlite":
        return
    connection.exec_driver_sql("PRAGMA foreign_keys=ON")
    connection.commit()
    violations = connection.exec_driver_sql("PRAGMA foreign_key_check").all()
    if violations:
        preview = "; ".join(str(tuple(row)) for row in violations[:10])
        raise DatabaseMigrationInvariantError(
            f"The copied SQLite database has foreign-key violations: {preview}."
        )

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, select

from app.core import schema_smoke
from app.core.migration_bootstrap import ALEMBIC_HEAD
from app.core.schema_smoke import (
    SchemaSmokeResult,
    assert_migrated_schema,
    assert_postgres_engine,
    run_project_repository_smoke,
)
from app.models import Project, import_table_models


def test_schema_smoke_validates_model_tables_and_alembic_head() -> None:
    engine = _migrated_sqlite_engine()
    try:
        result = assert_migrated_schema(engine)
    finally:
        engine.dispose()

    assert result.dialect == "sqlite"
    assert ALEMBIC_HEAD in result.alembic_versions
    assert result.table_count >= 20


def test_schema_smoke_rejects_non_postgres_dialect_for_full_compose_smoke() -> None:
    engine = _migrated_sqlite_engine()
    try:
        with pytest.raises(RuntimeError, match="must run against PostgreSQL"):
            assert_postgres_engine(engine)
    finally:
        engine.dispose()


def test_schema_smoke_rejects_stale_alembic_head() -> None:
    engine = _migrated_sqlite_engine(alembic_version="20260428_0001")
    try:
        with pytest.raises(RuntimeError, match="Alembic head mismatch"):
            assert_migrated_schema(engine)
    finally:
        engine.dispose()


def test_schema_smoke_rejects_missing_model_tables() -> None:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE alembic_version (version_num VARCHAR(32))"))
        connection.execute(
            text("INSERT INTO alembic_version (version_num) VALUES (:version_num)"),
            {"version_num": ALEMBIC_HEAD},
        )

    try:
        with pytest.raises(RuntimeError, match="missing model tables"):
            assert_migrated_schema(engine)
    finally:
        engine.dispose()


def test_schema_smoke_rejects_missing_alembic_version_table() -> None:
    import_table_models()
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)

    try:
        with pytest.raises(RuntimeError, match="missing alembic_version"):
            assert_migrated_schema(engine)
    finally:
        engine.dispose()


def test_schema_smoke_exercises_project_repository_and_cleans_up() -> None:
    engine = _migrated_sqlite_engine()
    try:
        project_id = run_project_repository_smoke(engine)

        with Session(engine) as session:
            assert session.exec(select(Project).where(Project.id == project_id)).first() is None
    finally:
        engine.dispose()


def test_run_smoke_composes_postgres_schema_and_repository_steps(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = _migrated_sqlite_engine()
    try:
        project_id = uuid.uuid4()
        calls: list[str] = []

        def assert_postgres(active_engine: Engine) -> str:
            assert active_engine is engine
            calls.append("postgres")
            return "postgresql"

        def assert_schema(active_engine: Engine) -> SchemaSmokeResult:
            assert active_engine is engine
            calls.append("schema")
            return SchemaSmokeResult(
                dialect="postgresql",
                alembic_versions=(ALEMBIC_HEAD,),
                table_count=42,
            )

        def repository_smoke(active_engine: Engine) -> uuid.UUID:
            assert active_engine is engine
            calls.append("repository")
            return project_id

        monkeypatch.setattr(schema_smoke, "assert_postgres_engine", assert_postgres)
        monkeypatch.setattr(schema_smoke, "assert_migrated_schema", assert_schema)
        monkeypatch.setattr(schema_smoke, "run_project_repository_smoke", repository_smoke)

        result = schema_smoke.run_smoke(engine)

        assert calls == ["postgres", "schema", "repository"]
        assert result.repository_project_id == project_id
    finally:
        engine.dispose()


def test_schema_smoke_main_prints_compact_success_summary(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    project_id = uuid.uuid4()
    monkeypatch.setattr(
        schema_smoke,
        "run_smoke",
        lambda: SchemaSmokeResult(
            dialect="postgresql",
            alembic_versions=(ALEMBIC_HEAD,),
            table_count=42,
            repository_project_id=project_id,
        ),
    )

    schema_smoke.main()

    output = capsys.readouterr().out
    assert "Compose Postgres schema smoke passed" in output
    assert f"repository_project_id={project_id}" in output


def _migrated_sqlite_engine(*, alembic_version: str = ALEMBIC_HEAD) -> Engine:
    import_table_models()
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE alembic_version (version_num VARCHAR(32))"))
        connection.execute(
            text("INSERT INTO alembic_version (version_num) VALUES (:version_num)"),
            {"version_num": alembic_version},
        )
    return engine

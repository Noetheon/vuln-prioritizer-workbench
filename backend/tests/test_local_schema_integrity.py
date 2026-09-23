"""Startup must distinguish migrated data from incomplete or damaged storage."""

from __future__ import annotations

import uuid
from pathlib import Path

import pytest
from sqlalchemy import event, inspect, text
from sqlmodel import Session, SQLModel

from app.api.routes.workbench import _database_readiness
from app.core.config import Settings
from app.core.db import create_db_engine
from app.core.local_schema_bootstrap import _rebuild_sqlite_table, bootstrap_local_sqlite_schema
from app.core.migration_bootstrap import ALEMBIC_HEAD
from app.core.schema_smoke import assert_migrated_schema
from app.models import AnalysisEvidence, Project, import_table_models


def _database(tmp_path: Path):
    settings = Settings(SQLALCHEMY_DATABASE_URI=f"sqlite:///{tmp_path / 'schema.db'}")
    engine = create_db_engine(settings)
    import_table_models()
    SQLModel.metadata.create_all(engine)
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE alembic_version (version_num VARCHAR(32))"))
        connection.execute(
            text("INSERT INTO alembic_version VALUES (:head)"), {"head": ALEMBIC_HEAD}
        )
    return engine, settings


def test_missing_nullable_column_is_rejected_by_startup_and_readiness(tmp_path: Path) -> None:
    engine, settings = _database(tmp_path)
    try:
        with engine.begin() as connection:
            connection.exec_driver_sql("ALTER TABLE project DROP COLUMN description")
        with pytest.raises(RuntimeError, match=r"missing required columns: project.description"):
            bootstrap_local_sqlite_schema(engine, settings)
        with Session(engine) as session:
            assert _database_readiness(session) == ("ready", "not_ready")
        assert "description" not in {col["name"] for col in inspect(engine).get_columns("project")}
    finally:
        engine.dispose()


@pytest.mark.parametrize("unknown_revision", [False, True])
def test_startup_never_invents_missing_history_or_stamps_an_unknown_schema(
    tmp_path: Path, unknown_revision: bool
) -> None:
    engine, settings = _database(tmp_path)
    try:
        with Session(engine) as session:
            session.add(Project(name="Existing user data"))
            session.commit()
        version = "unknown_revision" if unknown_revision else ALEMBIC_HEAD
        with engine.begin() as connection:
            connection.execute(
                text("UPDATE alembic_version SET version_num=:head"), {"head": version}
            )
            connection.exec_driver_sql("DROP TABLE evidence_section")
        from alembic.util.exc import CommandError

        with pytest.raises((RuntimeError, CommandError)):
            bootstrap_local_sqlite_schema(engine, settings)
        with engine.connect() as connection:
            assert (
                connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
                == version
            )
            assert connection.execute(text("SELECT count(*) FROM project")).scalar_one() == 1
            assert "evidence_section" not in inspect(connection).get_table_names()
    finally:
        engine.dispose()


def test_legacy_rebuild_rolls_back_on_copy_failure_and_preserves_child_foreign_keys(
    tmp_path: Path,
) -> None:
    engine, _settings = _database(tmp_path)
    project_id, run_id = uuid.uuid4(), uuid.uuid4()
    try:
        with Session(engine) as session:
            session.add(Project(id=project_id, name="Legacy repair"))
            session.commit()
        with engine.begin() as connection:
            connection.exec_driver_sql(
                "ALTER TABLE analysis_run ADD COLUMN error_json JSON NOT NULL"
            )
            connection.execute(
                text(
                    "INSERT INTO analysis_run "
                    "(id, project_id, input_type, status, started_at, error_json) "
                    "VALUES (:id, :project, 'legacy', 'succeeded', '2026-09-01 00:00:00', '{}')"
                ),
                {"id": run_id.hex, "project": project_id.hex},
            )
        with Session(engine) as session:
            session.add(
                AnalysisEvidence(
                    project_id=project_id, analysis_run_id=run_id, payload_json={"retained": True}
                )
            )
            session.commit()

        def fail_copy(_connection, _cursor, statement, _parameters, _context, _many):
            if statement.startswith('INSERT INTO "analysis_run"'):
                raise RuntimeError("injected table copy failure")

        event.listen(engine, "before_cursor_execute", fail_copy)
        try:
            with pytest.raises(RuntimeError, match="injected table copy failure"):
                _rebuild_sqlite_table(engine, "analysis_run")
        finally:
            event.remove(engine, "before_cursor_execute", fail_copy)
        assert "error_json" in {col["name"] for col in inspect(engine).get_columns("analysis_run")}
        with engine.connect() as connection:
            assert connection.exec_driver_sql("PRAGMA foreign_keys").scalar_one() == 1
            assert connection.execute(text("SELECT count(*) FROM analysis_run")).scalar_one() == 1
            assert "_analysis_run_legacy_repair" not in inspect(connection).get_table_names()
        _rebuild_sqlite_table(engine, "analysis_run")
        # Exercise recreation of an expression index as well.
        _rebuild_sqlite_table(engine, "finding_occurrence")
        with engine.connect() as connection:
            assert connection.exec_driver_sql("PRAGMA foreign_key_check").all() == []
            assert (
                connection.execute(text("SELECT payload_json FROM analysis_evidence")).scalar_one()
                == '{"retained": true}'
            )
            assert connection.execute(text("SELECT count(*) FROM analysis_run")).scalar_one() == 1
            assert (
                connection.execute(
                    text(
                        "SELECT count(*) FROM sqlite_master "
                        "WHERE name='ix_finding_occurrence_identity'"
                    )
                ).scalar_one()
                == 1
            )
            assert all(
                not item["referred_table"].endswith("_legacy_repair")
                for item in inspect(connection).get_foreign_keys("analysis_evidence")
            )
        assert_migrated_schema(engine)
    finally:
        engine.dispose()

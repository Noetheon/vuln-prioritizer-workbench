from __future__ import annotations

import importlib
from pathlib import Path

from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from sqlalchemy import create_engine, inspect, text
from sqlmodel import SQLModel

from app.core.migration_bootstrap import ALEMBIC_HEAD, current_alembic_head

PUBLIC_MODEL_NAMES = (
    "AuditEvent",
    "AuditEventPublic",
    "AuditEventsPublic",
    "ProjectBase",
    "ProjectCreate",
    "ProjectUpdate",
    "Project",
    "ProjectPublic",
    "ProjectsPublic",
    "WorkbenchStatus",
)


def test_app_models_remains_public_aggregator_for_modular_models() -> None:
    app_models = importlib.import_module("app.models")

    exported_names = set(getattr(app_models, "__all__", ()))
    assert set(PUBLIC_MODEL_NAMES).issubset(exported_names)

    for model_name in PUBLIC_MODEL_NAMES:
        model = getattr(app_models, model_name)
        assert model.__module__.startswith("app.models.")
        assert model.__module__ != "app.models"


def test_app_models_import_registers_single_user_project_metadata() -> None:
    importlib.import_module("app.models")

    assert {"project", "audit_event"}.issubset(SQLModel.metadata.tables)
    assert {"user", "api_token", "auth_session"}.isdisjoint(SQLModel.metadata.tables)
    assert not SQLModel.metadata.tables["project"].foreign_keys


def test_workbench_alembic_head_matches_model_metadata(tmp_path: Path) -> None:
    importlib.import_module("app.models")

    config = _alembic_config(tmp_path)
    command.upgrade(config, "head")

    engine = create_engine(config.get_main_option("sqlalchemy.url"))
    try:
        with engine.connect() as connection:
            migration_context = MigrationContext.configure(connection)
            diffs = compare_metadata(migration_context, SQLModel.metadata)
            version = connection.execute(
                text("SELECT version_num FROM alembic_version")
            ).scalar_one()
    finally:
        engine.dispose()

    assert diffs == []
    assert version == ALEMBIC_HEAD


def test_workbench_migration_head_resolves_without_checked_out_alembic_ini(
    tmp_path: Path,
) -> None:
    assert current_alembic_head(tmp_path / "missing-alembic.ini") == ALEMBIC_HEAD


def test_workbench_initial_migration_is_local_single_user_schema(tmp_path: Path) -> None:
    config = _alembic_config(tmp_path)
    command.upgrade(config, "head")

    engine = create_engine(config.get_main_option("sqlalchemy.url"))
    try:
        inspector = inspect(engine)
        table_names = set(inspector.get_table_names())

        assert {"project", "audit_event", "analysis_run", "finding", "report"}.issubset(table_names)
        assert {"user", "api_token", "auth_session"}.isdisjoint(table_names)
        assert "owner_id" not in {column["name"] for column in inspector.get_columns("project")}
        assert "api_token_id" not in {
            column["name"] for column in inspector.get_columns("audit_event")
        }
        assert "actor_user_id" not in {
            column["name"] for column in inspector.get_columns("audit_event")
        }
    finally:
        engine.dispose()


def _alembic_config(tmp_path: Path) -> Config:
    script_location = Path(__file__).resolve().parents[2] / "app" / "alembic"
    database_url = f"sqlite:///{tmp_path / 'workbench.db'}"

    config = Config()
    config.set_main_option("script_location", str(script_location))
    config.set_main_option("sqlalchemy.url", database_url)
    return config

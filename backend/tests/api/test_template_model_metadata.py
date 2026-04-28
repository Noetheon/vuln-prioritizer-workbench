from __future__ import annotations

import importlib
from pathlib import Path

from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from sqlalchemy import create_engine
from sqlmodel import SQLModel

PUBLIC_MODEL_NAMES = (
    "Token",
    "TokenPayload",
    "UserBase",
    "User",
    "UserPublic",
    "UsersPublic",
    "ProjectBase",
    "ProjectCreate",
    "ProjectUpdate",
    "Project",
    "ProjectPublic",
    "ProjectsPublic",
    "MigrationStatus",
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


def test_app_models_import_registers_user_and_project_metadata() -> None:
    importlib.import_module("app.models")

    assert {"user", "project"}.issubset(SQLModel.metadata.tables)
    assert SQLModel.metadata.tables["project"].foreign_keys


def test_template_alembic_head_matches_model_metadata(tmp_path: Path) -> None:
    importlib.import_module("app.models")

    script_location = Path(__file__).resolve().parents[2] / "app" / "alembic"
    database_url = f"sqlite:///{tmp_path / 'template.db'}"

    config = Config()
    config.set_main_option("script_location", str(script_location))
    config.set_main_option("sqlalchemy.url", database_url)

    command.upgrade(config, "head")

    engine = create_engine(database_url)
    try:
        with engine.connect() as connection:
            migration_context = MigrationContext.configure(connection)
            diffs = compare_metadata(migration_context, SQLModel.metadata)
    finally:
        engine.dispose()

    assert diffs == []

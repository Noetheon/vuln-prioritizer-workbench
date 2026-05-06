from __future__ import annotations

import importlib
import json
from pathlib import Path

from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from sqlalchemy import create_engine, inspect, text
from sqlmodel import SQLModel

from app.core.migration_bootstrap import stamp_legacy_create_all_database

PUBLIC_MODEL_NAMES = (
    "Token",
    "TokenPayload",
    "UserBase",
    "User",
    "UserPublic",
    "UsersPublic",
    "AuthSession",
    "AuthSessionPublic",
    "AuthSessionsPublic",
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


def test_app_models_import_registers_user_and_project_metadata() -> None:
    importlib.import_module("app.models")

    assert {"user", "project", "auth_session", "audit_event"}.issubset(SQLModel.metadata.tables)
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


def test_template_migration_bootstrap_stamps_legacy_create_all_database(
    tmp_path: Path,
) -> None:
    script_location = Path(__file__).resolve().parents[2] / "app" / "alembic"
    config_path = Path(__file__).resolve().parents[2] / "alembic.ini"
    database_url = f"sqlite:///{tmp_path / 'template.db'}"

    config = Config(str(config_path))
    config.set_main_option("script_location", str(script_location))
    config.set_main_option("sqlalchemy.url", database_url)
    command.upgrade(config, "20260430_0009")

    engine = create_engine(database_url)
    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    """
                    INSERT INTO api_token
                        (name, token_hash, scopes_json, id, created_at, last_used_at, revoked_at)
                    VALUES
                        (
                            :read_name,
                            :read_hash,
                            :read_scopes,
                            :read_id,
                            CURRENT_TIMESTAMP,
                            NULL,
                            NULL
                        ),
                        (
                            :admin_name,
                            :admin_hash,
                            :admin_scopes,
                            :admin_id,
                            CURRENT_TIMESTAMP,
                            NULL,
                            NULL
                        )
                    """
                ),
                {
                    "read_name": "legacy-read",
                    "read_hash": "legacy-read-hash",
                    "read_scopes": json.dumps(["read"]),
                    "read_id": "11111111111111111111111111111111",
                    "admin_name": "legacy-admin",
                    "admin_hash": "legacy-admin-hash",
                    "admin_scopes": json.dumps(["admin"]),
                    "admin_id": "22222222222222222222222222222222",
                },
            )
            connection.execute(text("DROP TABLE alembic_version"))
        inspector = inspect(engine)
        assert "project_id" not in {column["name"] for column in inspector.get_columns("api_token")}
    finally:
        engine.dispose()

    stamped = stamp_legacy_create_all_database(
        database_url=database_url,
        config_path=config_path,
    )

    assert stamped == "20260430_0009"
    command.upgrade(config, "head")

    engine = create_engine(database_url)
    try:
        inspector = inspect(engine)
        assert "project_id" in {column["name"] for column in inspector.get_columns("api_token")}
        with engine.connect() as connection:
            version = connection.execute(
                text("SELECT version_num FROM alembic_version")
            ).scalar_one()
            legacy_token_rows = connection.execute(
                text("SELECT name, revoked_at FROM api_token ORDER BY name")
            ).all()
        assert {"auth_session", "audit_event"}.issubset(set(inspector.get_table_names()))
        assert version == "20260506_0011"
        assert legacy_token_rows[0][0] == "legacy-admin"
        assert legacy_token_rows[0][1] is None
        assert legacy_token_rows[1][0] == "legacy-read"
        assert legacy_token_rows[1][1] is not None
    finally:
        engine.dispose()

from __future__ import annotations

import importlib
import json
from pathlib import Path

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from sqlalchemy import create_engine, inspect, text
from sqlmodel import SQLModel

from app.core.migration_bootstrap import (
    ALEMBIC_HEAD,
    _connect_args,
    _legacy_revision_for_tables,
    stamp_legacy_create_all_database,
)

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


class _InspectorStub:
    def __init__(self, api_token_columns: set[str] | None = None) -> None:
        self.api_token_columns = api_token_columns or set()

    def get_columns(self, table_name: str) -> list[dict[str, str]]:
        assert table_name == "api_token"
        return [{"name": column_name} for column_name in sorted(self.api_token_columns)]


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


@pytest.mark.parametrize(
    ("table_names", "api_token_columns", "expected_revision"),
    [
        ({"api_token", "github_issue_export"}, set(), "20260430_0009"),
        (
            {"api_token", "github_issue_export", "auth_session", "audit_event"},
            {"project_id"},
            ALEMBIC_HEAD,
        ),
        ({"api_token", "github_issue_export"}, {"project_id"}, "20260505_0010"),
        ({"api_token"}, set(), "20260430_0008"),
        ({"api_token"}, {"project_id"}, None),
        ({"attack_stix_snapshot"}, set(), "20260430_0007"),
        ({"waiver"}, set(), "20260430_0006"),
        ({"finding_attack_context"}, set(), "20260429_0005"),
        ({"report"}, set(), "20260429_0004"),
        ({"analysis_run"}, set(), "20260428_0003"),
        ({"finding"}, set(), "20260428_0002"),
        ({"project", "user"}, set(), "20260428_0001"),
        ({"project"}, set(), None),
    ],
)
def test_template_migration_bootstrap_identifies_legacy_revision_from_schema_markers(
    table_names: set[str],
    api_token_columns: set[str],
    expected_revision: str | None,
) -> None:
    assert (
        _legacy_revision_for_tables(_InspectorStub(api_token_columns), table_names)
        == expected_revision
    )


def test_template_migration_bootstrap_connect_args_are_driver_specific() -> None:
    assert _connect_args("sqlite:///./workbench.db") == {"check_same_thread": False}
    assert _connect_args("postgresql+psycopg://workbench:secret@db/app") == {}


def test_template_migration_bootstrap_ignores_empty_and_already_versioned_databases(
    tmp_path: Path,
) -> None:
    empty_database_url = f"sqlite:///{tmp_path / 'empty.db'}"

    assert stamp_legacy_create_all_database(database_url=empty_database_url) is None

    versioned_database_url = f"sqlite:///{tmp_path / 'versioned.db'}"
    engine = create_engine(versioned_database_url)
    try:
        with engine.begin() as connection:
            connection.execute(
                text("CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL)")
            )
        assert stamp_legacy_create_all_database(database_url=versioned_database_url) is None
    finally:
        engine.dispose()


def test_template_migration_bootstrap_leaves_unknown_legacy_schema_unstamped(
    tmp_path: Path,
) -> None:
    database_url = f"sqlite:///{tmp_path / 'unknown-legacy.db'}"
    engine = create_engine(database_url)
    try:
        with engine.begin() as connection:
            connection.execute(text("CREATE TABLE legacy_cache (id INTEGER PRIMARY KEY)"))

        assert stamp_legacy_create_all_database(database_url=database_url) is None

        inspector = inspect(engine)
        assert "legacy_cache" in set(inspector.get_table_names())
        assert "alembic_version" not in set(inspector.get_table_names())
    finally:
        engine.dispose()


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

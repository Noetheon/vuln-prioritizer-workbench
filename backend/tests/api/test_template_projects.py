from __future__ import annotations

import uuid
from collections.abc import Generator
from pathlib import Path
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import inspect
from sqlalchemy.pool import StaticPool

from app.core.config import settings
from app.main import app

_SUPERUSER_ID = uuid.UUID("00000000-0000-4000-8000-000000000001")


def test_template_project_migration_creates_user_project_tables_without_item(
    tmp_path: Path,
) -> None:
    script_location = Path(__file__).resolve().parents[2] / "app" / "alembic"
    assert script_location.exists(), "Template app Alembic migrations must live under app/alembic"
    assert (script_location / "env.py").exists()

    config = Config()
    config.set_main_option("script_location", str(script_location))
    config.set_main_option("sqlalchemy.url", f"sqlite:///{tmp_path / 'template.db'}")

    command.upgrade(config, "head")

    from sqlalchemy import create_engine

    engine = create_engine(f"sqlite:///{tmp_path / 'template.db'}")
    inspector = inspect(engine)
    tables = set(inspector.get_table_names())

    assert {"user", "project"}.issubset(tables)
    assert "item" not in tables

    project_columns = {column["name"] for column in inspector.get_columns("project")}
    assert {"id", "name", "owner_id"}.issubset(project_columns)

    project_foreign_keys = inspector.get_foreign_keys("project")
    assert any(
        foreign_key["referred_table"] == "user"
        and foreign_key["constrained_columns"] == ["owner_id"]
        and foreign_key["referred_columns"] == ["id"]
        for foreign_key in project_foreign_keys
    )


def test_authenticated_superuser_can_create_list_and_read_projects() -> None:
    client, cleanup = _client_with_temp_database()
    try:
        token = _login(client)
        headers = {"Authorization": f"Bearer {token}"}
        current_user = client.get("/api/v1/users/me", headers=headers).json()

        create_response = client.post(
            "/api/v1/projects/",
            headers=headers,
            json={
                "name": "External Attack Surface",
                "description": "Internet-facing CVE prioritization workspace.",
            },
        )

        assert create_response.status_code == 200
        created = create_response.json()
        assert created["name"] == "External Attack Surface"
        assert created["description"] == "Internet-facing CVE prioritization workspace."
        assert created["owner_id"] == current_user["id"]
        assert created["id"]

        list_response = client.get("/api/v1/projects/", headers=headers)
        read_response = client.get(f"/api/v1/projects/{created['id']}", headers=headers)

        assert list_response.status_code == 200
        assert list_response.json() == {"data": [created], "count": 1}
        assert read_response.status_code == 200
        assert read_response.json() == created
    finally:
        cleanup()


def test_template_project_openapi_exposes_projects_without_items() -> None:
    client = TestClient(app)

    response = client.get("/api/v1/openapi.json")

    assert response.status_code == 200
    payload = response.json()
    paths = payload["paths"]
    schemas = payload["components"]["schemas"]

    assert any(path.startswith("/api/v1/projects") for path in paths)
    assert all("/items" not in path for path in paths)
    assert {"ProjectCreate", "ProjectPublic", "ProjectsPublic"}.issubset(schemas)
    assert all("Item" not in schema_name for schema_name in schemas)


def _client_with_temp_database() -> tuple[TestClient, Any]:
    try:
        import sqlmodel
    except ImportError as exc:
        pytest.fail(f"Project shell tests require SQLModel: {exc}")
    from sqlalchemy import create_engine

    try:
        from app import models as app_models
        from app.api import deps
        from app.core import security
    except ImportError as exc:
        pytest.fail(f"Project shell must expose app models and DB dependencies: {exc}")

    get_db = getattr(deps, "get_db", None)
    if get_db is None:
        pytest.fail("Project routes must depend on app.api.deps.get_db")

    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    sqlmodel.SQLModel.metadata.create_all(engine)
    _seed_superuser(sqlmodel.Session(engine), app_models, security)

    def override_get_db() -> Generator[Any, None, None]:
        with sqlmodel.Session(engine) as session:
            yield session

    app.dependency_overrides[get_db] = override_get_db

    def cleanup() -> None:
        app.dependency_overrides.pop(get_db, None)
        engine.dispose()

    return TestClient(app), cleanup


def _seed_superuser(session: Any, app_models: Any, security: Any) -> None:
    password_hash = getattr(security, "get_password_hash", lambda password: password)(
        settings.FIRST_SUPERUSER_PASSWORD
    )
    try:
        user = app_models.User(
            id=_SUPERUSER_ID,
            email=settings.FIRST_SUPERUSER,
            hashed_password=password_hash,
            is_active=True,
            is_superuser=True,
        )
        session.add(user)
        session.commit()
    finally:
        session.close()


def _login(client: TestClient) -> str:
    response = client.post(
        "/api/v1/login/access-token",
        data={
            "username": settings.FIRST_SUPERUSER,
            "password": settings.FIRST_SUPERUSER_PASSWORD,
        },
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["token_type"] == "bearer"
    return str(payload["access_token"])

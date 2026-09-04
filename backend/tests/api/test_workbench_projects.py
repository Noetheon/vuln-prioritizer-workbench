from __future__ import annotations

import uuid
from collections.abc import Generator
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import inspect
from sqlalchemy.pool import StaticPool
from utils.workbench_env import WorkbenchApiEnv, create_project_via_api, local_api_headers

from app.core.rate_limit import InMemoryRateLimiter
from app.main import app
from app.services.artifact_cleanup import (
    ProjectArtifactCleanupResult,
    cleanup_project_artifacts,
)


def test_workbench_project_migration_creates_single_user_project_tables_without_item(
    tmp_path: Path,
) -> None:
    script_location = Path(__file__).resolve().parents[2] / "app" / "alembic"
    assert script_location.exists(), "Workbench app Alembic migrations must live under app/alembic"
    assert (script_location / "env.py").exists()

    config = Config()
    config.set_main_option("script_location", str(script_location))
    config.set_main_option("sqlalchemy.url", f"sqlite:///{tmp_path / 'workbench.db'}")

    command.upgrade(config, "head")

    from sqlalchemy import create_engine

    engine = create_engine(f"sqlite:///{tmp_path / 'workbench.db'}")
    try:
        inspector = inspect(engine)
        tables = set(inspector.get_table_names())

        assert {"project", "audit_event"}.issubset(tables)
        assert {"user", "api_token", "auth_session"}.isdisjoint(tables)
        assert "item" not in tables

        project_columns = {column["name"] for column in inspector.get_columns("project")}
        assert {"id", "name", "description", "created_at", "updated_at"}.issubset(project_columns)
        assert "owner_id" not in project_columns
    finally:
        engine.dispose()


def test_local_single_user_can_create_list_and_read_projects() -> None:
    client, cleanup = _client_with_temp_database()
    try:
        create_response = client.post(
            "/api/v1/projects/",
            json={
                "name": "External Attack Surface",
                "description": "Internet-facing CVE prioritization workspace.",
            },
        )

        assert create_response.status_code == 200
        created = create_response.json()
        assert created["name"] == "External Attack Surface"
        assert created["description"] == "Internet-facing CVE prioritization workspace."
        assert "owner_id" not in created
        assert created["id"]

        list_response = client.get("/api/v1/projects/")
        read_response = client.get(f"/api/v1/projects/{created['id']}")

        assert list_response.status_code == 200
        assert list_response.json() == {"data": [created], "count": 1}
        assert read_response.status_code == 200
        assert read_response.json() == created
    finally:
        cleanup()


def test_project_delete_removes_managed_artifact_trees_and_writes_audit(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    client = workbench_api_env.client
    active_settings = client.app.state.workbench_settings
    upload_root = tmp_path / "uploads"
    report_root = tmp_path / "reports"
    client.app.state.workbench_settings = replace(
        active_settings,
        IMPORT_UPLOAD_DIR=str(upload_root),
        REPORT_DIR=str(report_root),
    )
    headers = local_api_headers(client)
    project = create_project_via_api(client, headers)
    project_id = project["id"]
    (upload_root / project_id / "run").mkdir(parents=True)
    (upload_root / project_id / "run" / "input.txt").write_text("CVE-2024-3094\n")
    (report_root / project_id / "run" / "report").mkdir(parents=True)
    (report_root / project_id / "run" / "report" / "report.md").write_text("report")

    response = client.delete(f"/api/v1/projects/{project_id}", headers=headers)
    events = client.get("/api/v1/audit/events", headers=headers).json()["data"]

    assert response.status_code == 204
    assert not (upload_root / project_id).exists()
    assert not (report_root / project_id).exists()
    delete_event = next(item for item in events if item["action"] == "project.delete")
    assert delete_event["resource_id"] == project_id
    assert len(delete_event["detail"]["removed_artifact_paths"]) == 2


def test_artifact_cleanup_deduplicates_roots_and_does_not_follow_project_symlinks(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    managed_root = tmp_path / "managed"
    outside_tree = tmp_path / "outside" / "evidence"
    outside_tree.mkdir(parents=True)
    outside_file = outside_tree / "report.md"
    outside_file.write_text("preserve", encoding="utf-8")
    project_id = uuid.uuid4()
    managed_root.mkdir()
    project_link = managed_root / str(project_id)
    project_link.symlink_to(outside_tree, target_is_directory=True)
    active_settings = replace(
        workbench_api_env.client.app.state.workbench_settings,
        IMPORT_UPLOAD_DIR=str(managed_root),
        REPORT_DIR=str(managed_root),
    )

    result = cleanup_project_artifacts(settings=active_settings, project_id=project_id)

    assert result.removed_paths == (str(project_link),)
    assert result.missing_paths == ()
    assert not project_link.exists()
    assert outside_file.read_text(encoding="utf-8") == "preserve"


def test_project_delete_preserves_artifacts_when_database_delete_fails(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = workbench_api_env.client
    active_settings = client.app.state.workbench_settings
    upload_root = tmp_path / "uploads"
    report_root = tmp_path / "reports"
    client.app.state.workbench_settings = replace(
        active_settings,
        IMPORT_UPLOAD_DIR=str(upload_root),
        REPORT_DIR=str(report_root),
    )
    headers = local_api_headers(client)
    project = create_project_via_api(client, headers)
    upload_artifact = upload_root / project["id"] / "run" / "input.txt"
    report_artifact = report_root / project["id"] / "run" / "report.md"
    upload_artifact.parent.mkdir(parents=True)
    report_artifact.parent.mkdir(parents=True)
    upload_artifact.write_text("CVE-2024-3094\n", encoding="utf-8")
    report_artifact.write_text("evidence", encoding="utf-8")

    def fail_database_delete(*args: Any, **kwargs: Any) -> None:
        del args, kwargs
        raise RuntimeError("simulated relational delete failure")

    monkeypatch.setattr(
        "app.services.project_deletion.ProjectRepository.delete_project",
        fail_database_delete,
    )
    with pytest.raises(RuntimeError, match="simulated relational delete failure"):
        client.delete(f"/api/v1/projects/{project['id']}", headers=headers)

    assert upload_artifact.read_text(encoding="utf-8") == "CVE-2024-3094\n"
    assert report_artifact.read_text(encoding="utf-8") == "evidence"
    assert client.get(f"/api/v1/projects/{project['id']}", headers=headers).status_code == 200


def test_project_delete_records_post_commit_artifact_cleanup_failure(
    file_backed_workbench_api_env: WorkbenchApiEnv,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = file_backed_workbench_api_env.client
    headers = local_api_headers(client)
    project = create_project_via_api(client, headers)
    cleanup_calls: list[bool] = []

    def fail_destructive_cleanup(*args: Any, **kwargs: Any) -> ProjectArtifactCleanupResult:
        del args
        dry_run = bool(kwargs.get("dry_run", False))
        cleanup_calls.append(dry_run)
        if dry_run:
            return ProjectArtifactCleanupResult(removed_paths=(), missing_paths=())
        raise OSError("simulated cleanup failure")

    monkeypatch.setattr(
        "app.services.project_deletion.cleanup_project_artifacts",
        fail_destructive_cleanup,
    )
    response = client.delete(f"/api/v1/projects/{project['id']}", headers=headers)

    assert response.status_code == 500
    assert cleanup_calls == [True, False]
    assert client.get(f"/api/v1/projects/{project['id']}", headers=headers).status_code == 404
    events = client.get("/api/v1/audit/events", headers=headers).json()["data"]
    delete_event = next(item for item in events if item["action"] == "project.delete")
    assert delete_event["status"] == "failure"
    assert delete_event["project_id"] is None
    assert delete_event["detail"]["artifact_cleanup_status"] == "failed"
    assert delete_event["detail"]["artifact_cleanup_error_type"] == "OSError"


def test_workbench_project_openapi_exposes_projects_without_items() -> None:
    client = TestClient(app)
    try:
        response = client.get("/api/v1/openapi.json")
    finally:
        client.close()

    assert response.status_code == 200
    payload = response.json()
    paths = payload["paths"]
    schemas = payload["components"]["schemas"]

    assert any(path.startswith("/api/v1/projects") for path in paths)
    assert all("/items" not in path for path in paths)
    assert {"ProjectCreate", "ProjectPublic", "ProjectsPublic"}.issubset(schemas)
    assert {"Item", "ItemCreate", "ItemPublic", "ItemsPublic", "ItemUpdate"}.isdisjoint(schemas)


def _client_with_temp_database() -> tuple[TestClient, Any]:
    try:
        import sqlmodel
    except ImportError as exc:
        pytest.fail(f"Project shell tests require SQLModel: {exc}")
    from sqlalchemy import create_engine

    try:
        from app import models as app_models
        from app.api import deps
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
    app_models.import_table_models()
    sqlmodel.SQLModel.metadata.create_all(engine)

    def override_get_db() -> Generator[Any, None, None]:
        with sqlmodel.Session(engine) as session:
            yield session

    app.dependency_overrides[get_db] = override_get_db
    app.state.rate_limiter = InMemoryRateLimiter()
    client = TestClient(app)

    def cleanup() -> None:
        client.close()
        app.dependency_overrides.pop(get_db, None)
        engine.dispose()

    return client, cleanup

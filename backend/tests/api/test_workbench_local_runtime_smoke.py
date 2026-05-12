from __future__ import annotations

from collections.abc import Generator
from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

from app.core.migration_bootstrap import ALEMBIC_HEAD
from app.core.rate_limit import InMemoryRateLimiter
from app.main import app


def _client(active_app: Any = app) -> TestClient:
    from app.api.deps import get_db

    active_app.dependency_overrides.clear()
    active_app.state.rate_limiter = InMemoryRateLimiter()
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL)"))
        connection.execute(
            text("INSERT INTO alembic_version (version_num) VALUES (:version_num)"),
            {"version_num": ALEMBIC_HEAD},
        )

    def override_get_db() -> Generator[Session, None, None]:
        with Session(engine) as session:
            yield session

    active_app.dependency_overrides[get_db] = override_get_db
    return TestClient(active_app)


def test_workbench_auth_user_session_and_api_token_routes_are_not_active() -> None:
    client = _client()

    openapi = client.get("/api/v1/openapi.json").json()
    paths = set(openapi["paths"])

    removed_paths = {
        "/api/v1/api-tokens/",
        "/api/v1/api-tokens/{token_id}",
        "/api/v1/audit/sessions",
        "/api/v1/login/access-token",
        "/api/v1/login/logout",
        "/api/v1/login/test-token",
        "/api/v1/users/me",
        "/api/v1/users/me/password",
    }
    assert paths.isdisjoint(removed_paths)

    assert client.post("/api/v1/login/access-token").status_code == 404
    assert client.post("/api/v1/login/test-token").status_code == 404
    assert client.post("/api/v1/login/logout").status_code == 404
    assert client.get("/api/v1/users/me").status_code == 404
    assert client.post("/api/v1/users/me/password").status_code == 404
    assert client.get("/api/v1/audit/sessions").status_code == 404
    assert client.get("/api/v1/api-tokens/").status_code == 404
    assert client.post("/api/v1/api-tokens/").status_code == 404


def test_workbench_local_single_user_api_accepts_browser_calls_without_login_or_csrf() -> None:
    client = _client()

    create_response = client.post(
        "/api/v1/projects/",
        json={"name": "Local Single User", "description": None},
    )
    bearer_response = client.get(
        "/api/v1/projects/",
        headers={"Authorization": "Bearer not-a-valid-token"},
    )

    assert create_response.status_code == 200, create_response.text
    assert create_response.json()["name"] == "Local Single User"
    assert bearer_response.status_code == 200, bearer_response.text
    assert bearer_response.json()["count"] == 1


def test_workbench_status_is_available_without_login_in_local_runtime() -> None:
    client = _client()

    health = client.get("/api/v1/utils/health-check/")
    status = client.get(
        "/api/v1/workbench/status",
        headers={"Authorization": "Bearer ignored-local-token"},
    )

    assert health.status_code == 200
    assert health.json() is True
    assert status.status_code == 200
    assert status.json()["status"] == "ready"
    assert status.json()["database_status"] == "ready"
    assert status.json()["schema_status"] == "ready"


def test_workbench_api_responses_include_security_headers() -> None:
    client = _client()

    ok = client.get("/api/v1/workbench/health")
    not_found = client.get("/api/v1/login/access-token")

    assert ok.status_code == 200
    assert not_found.status_code == 404
    for response in (ok, not_found):
        _assert_security_headers(response.headers)


def _assert_security_headers(headers: Any) -> None:
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["x-frame-options"] == "DENY"
    assert headers["referrer-policy"] == "same-origin"
    assert headers["cross-origin-opener-policy"] == "same-origin"
    assert "microphone=()" in headers["permissions-policy"]
    csp = headers["content-security-policy"]
    assert "default-src 'self'" in csp
    assert "object-src 'none'" in csp
    assert "frame-ancestors 'none'" in csp

from __future__ import annotations

import uuid
from collections.abc import Generator
from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

from app.core import security
from app.core.config import settings
from app.main import app


def _client() -> TestClient:
    from app.api.deps import get_db

    app.dependency_overrides.clear()
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)

    def override_get_db() -> Generator[Session, None, None]:
        with Session(engine) as session:
            yield session

    app.dependency_overrides[get_db] = override_get_db
    return TestClient(app)


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


def test_template_login_access_token_accepts_configured_superuser() -> None:
    client = _client()

    token = _login(client)

    decoded = security.decode_access_token(token)
    assert decoded["sub"] == settings.FIRST_SUPERUSER


def test_template_login_access_token_rejects_wrong_password() -> None:
    client = _client()

    response = client.post(
        "/api/v1/login/access-token",
        data={"username": settings.FIRST_SUPERUSER, "password": "wrong-password"},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Incorrect email or password"


def test_template_token_routes_return_current_configured_user() -> None:
    client = _client()
    token = _login(client)
    headers = {"Authorization": f"Bearer {token}"}

    test_token = client.post("/api/v1/login/test-token", headers=headers)
    user_me = client.get("/api/v1/users/me", headers=headers)

    expected_user_without_generated_fields = {
        "email": settings.FIRST_SUPERUSER,
        "is_active": True,
        "is_superuser": True,
        "full_name": None,
    }
    assert test_token.status_code == 200
    assert user_me.status_code == 200
    assert _without_generated_fields(test_token.json()) == expected_user_without_generated_fields
    assert _without_generated_fields(user_me.json()) == expected_user_without_generated_fields
    assert uuid.UUID(test_token.json()["id"])
    assert test_token.json()["created_at"]
    assert user_me.json()["id"] == test_token.json()["id"]
    assert user_me.json()["created_at"] == test_token.json()["created_at"]


def test_template_token_routes_reject_missing_or_invalid_token() -> None:
    client = _client()

    missing = client.get("/api/v1/users/me")
    invalid = client.post(
        "/api/v1/login/test-token",
        headers={"Authorization": "Bearer not-a-valid-token"},
    )

    assert missing.status_code == 401
    assert invalid.status_code == 403


def test_template_auth_smoke_keeps_workbench_status_available() -> None:
    client = _client()

    response = client.get("/api/v1/workbench/status")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def _without_generated_fields(payload: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in payload.items() if key not in {"id", "created_at"}}

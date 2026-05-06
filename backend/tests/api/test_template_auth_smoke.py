from __future__ import annotations

import uuid
from collections.abc import Generator
from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

from app.core import security
from app.core.config import Settings, settings
from app.core.rate_limit import InMemoryRateLimiter
from app.main import app, create_app


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

    def override_get_db() -> Generator[Session, None, None]:
        with Session(engine) as session:
            yield session

    active_app.dependency_overrides[get_db] = override_get_db
    return TestClient(active_app)


def _login_response(client: TestClient, *, password: str | None = None) -> Any:
    response = client.post(
        "/api/v1/login/access-token",
        data={
            "username": settings.FIRST_SUPERUSER,
            "password": password or settings.FIRST_SUPERUSER_PASSWORD,
        },
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["token_type"] == "bearer"
    return response


def _login(client: TestClient) -> str:
    response = _login_response(client)
    payload = response.json()
    return str(payload["access_token"])


def test_template_login_access_token_accepts_configured_superuser() -> None:
    client = _client()

    response = _login_response(client)
    token = str(response.json()["access_token"])

    decoded = security.decode_access_token(token)
    assert decoded["sub"] == settings.FIRST_SUPERUSER
    assert decoded["jti"]
    assert response.json()["csrf_token"]


def test_template_login_verifies_db_stored_password_hash(template_api_env: Any) -> None:
    client = template_api_env.client
    db_only_password = "db-only-password"
    with Session(template_api_env.engine) as db_session:
        statement = select(template_api_env.app_models.User).where(
            template_api_env.app_models.User.email == settings.FIRST_SUPERUSER
        )
        user = db_session.exec(statement).one()
        user.hashed_password = security.get_password_hash(db_only_password)
        db_session.add(user)
        db_session.commit()

    env_password = client.post(
        "/api/v1/login/access-token",
        data={
            "username": settings.FIRST_SUPERUSER,
            "password": settings.FIRST_SUPERUSER_PASSWORD,
        },
    )
    db_password = _login_response(client, password=db_only_password)

    assert env_password.status_code == 400
    assert db_password.status_code == 200


def test_template_login_sets_session_and_csrf_cookies() -> None:
    client = _client()

    response = _login_response(client)
    payload = response.json()
    set_cookie_headers = response.headers.get_list("set-cookie")
    session_cookie = next(
        header
        for header in set_cookie_headers
        if header.startswith(f"{security.SESSION_COOKIE_NAME}=")
    )

    assert response.cookies.get(security.SESSION_COOKIE_NAME) == payload["access_token"]
    assert response.cookies.get(security.CSRF_COOKIE_NAME) == payload["csrf_token"]
    assert "HttpOnly" in session_cookie
    assert "SameSite=lax" in session_cookie


def test_template_cookie_session_authenticates_safe_browser_requests() -> None:
    client = _client()
    _login_response(client)

    response = client.get("/api/v1/users/me")

    assert response.status_code == 200
    assert response.json()["email"] == settings.FIRST_SUPERUSER


def test_template_cookie_session_requires_csrf_for_unsafe_methods() -> None:
    client = _client()
    login = _login_response(client)
    csrf_token = str(login.json()["csrf_token"])

    missing_csrf = client.post(
        "/api/v1/projects/",
        json={"name": "Missing CSRF", "description": None},
    )
    valid_csrf = client.post(
        "/api/v1/projects/",
        headers={security.CSRF_HEADER_NAME: csrf_token},
        json={"name": "Valid CSRF", "description": None},
    )

    assert missing_csrf.status_code == 403
    assert missing_csrf.json()["detail"] == "CSRF token missing or invalid"
    assert valid_csrf.status_code == 200
    assert valid_csrf.json()["name"] == "Valid CSRF"


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


def test_template_logout_revokes_browser_session() -> None:
    client = _client()
    token = _login(client)
    headers = {"Authorization": f"Bearer {token}"}

    logout = client.post("/api/v1/login/logout", headers=headers)
    after_logout = client.get("/api/v1/users/me", headers=headers)

    assert logout.status_code == 200
    assert after_logout.status_code == 403
    assert after_logout.json()["detail"] == "Session is expired or revoked"


def test_template_logout_revokes_cookie_session_and_clears_cookies() -> None:
    client = _client()
    login = _login_response(client)
    payload = login.json()
    csrf_token = str(payload["csrf_token"])
    token = str(payload["access_token"])

    logout = client.post(
        "/api/v1/login/logout",
        headers={security.CSRF_HEADER_NAME: csrf_token},
    )
    cookie_after_logout = client.get("/api/v1/users/me")
    bearer_after_logout = client.get(
        "/api/v1/users/me",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert logout.status_code == 200
    assert security.SESSION_COOKIE_NAME not in client.cookies
    assert security.CSRF_COOKIE_NAME not in client.cookies
    assert cookie_after_logout.status_code == 401
    assert bearer_after_logout.status_code == 403
    assert bearer_after_logout.json()["detail"] == "Session is expired or revoked"


def test_template_login_rate_limit_blocks_repeated_attempts() -> None:
    selected_app = create_app(Settings(LOGIN_RATE_LIMIT_PER_MINUTE=2))
    client = _client(selected_app)

    attempts = [
        client.post(
            "/api/v1/login/access-token",
            data={"username": settings.FIRST_SUPERUSER, "password": "wrong-password"},
        )
        for _ in range(3)
    ]

    assert [attempt.status_code for attempt in attempts] == [400, 400, 429]
    assert attempts[-1].headers["retry-after"]


def test_template_audit_events_capture_login_lifecycle() -> None:
    client = _client()
    token = _login(client)
    headers = {"Authorization": f"Bearer {token}"}

    response = client.get("/api/v1/audit/events", headers=headers)

    assert response.status_code == 200
    actions = [item["action"] for item in response.json()["data"]]
    assert "login.success" in actions


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
    payload = response.json()
    assert payload["status"] == "ok"
    assert payload["database_status"] == "ready"
    assert payload["schema_status"] == "ready"


def test_template_api_responses_include_security_headers() -> None:
    client = _client()

    ok = client.get("/api/v1/workbench/status")
    not_found = client.get("/api/v1/does-not-exist")
    invalid_login = client.post(
        "/api/v1/login/access-token",
        data={"username": settings.FIRST_SUPERUSER, "password": "wrong-password"},
    )

    assert ok.status_code == 200
    assert not_found.status_code == 404
    assert invalid_login.status_code == 400
    for response in (ok, not_found, invalid_login):
        _assert_security_headers(response.headers)


def _without_generated_fields(payload: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in payload.items() if key not in {"id", "created_at"}}


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

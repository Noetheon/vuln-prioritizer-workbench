"""Team mode: a trusted login proxy asserts who is signed in."""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from dataclasses import replace

import pytest
from fastapi.testclient import TestClient
from starlette.datastructures import Headers
from starlette.websockets import WebSocketDisconnect
from utils.workbench_env import WorkbenchApiEnv

from app.core.config import Settings
from app.core.local_actor import local_actor_id
from app.core.proxy_identity import ProxyIdentityError, proxy_actor
from app.core.trusted_proxy import is_trusted_proxy_host
from app.main import app

PROXY_PEER = ("10.0.0.5", 50000)
USER = "alice@example.com"
SIGNED_IN = {"Remote-Email": USER, "Remote-Name": "Alice Example"}


@pytest.fixture
def team_mode(workbench_api_env: WorkbenchApiEnv) -> Iterator[TestClient]:
    base = app.state.workbench_settings
    app.state.workbench_settings = replace(
        base,
        AUTH_MODE="proxy",
        TRUSTED_PROXY_CIDRS=("10.0.0.0/24",),
        AUTH_PROXY_LOGOUT_URL="/oauth2/sign_out",
    )
    client = TestClient(app, client=PROXY_PEER)
    try:
        yield client
    finally:
        client.close()
        app.state.workbench_settings = base


def test_trusted_proxy_identity_becomes_the_session_user(team_mode: TestClient) -> None:
    response = team_mode.get("/api/v1/workbench/session", headers=SIGNED_IN)

    assert response.status_code == 200, response.text
    assert response.json() == {
        "auth_mode": "proxy",
        "user_id": str(local_actor_id(USER)),
        "user": USER,
        "display_name": "Alice Example",
        "logout_url": "/oauth2/sign_out",
    }
    unnamed = team_mode.get("/api/v1/workbench/session", headers={"Remote-Email": USER})
    assert unnamed.json()["display_name"] == USER


def test_requests_without_a_trusted_identity_are_rejected(
    team_mode: TestClient,
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    untrusted = workbench_api_env.client
    for client, headers in (
        (untrusted, SIGNED_IN),
        (team_mode, {}),
        (team_mode, {"Remote-Email": "  "}),
        (team_mode, {"Remote-Email": "a" * 321}),
    ):
        response = client.get("/api/v1/projects/", headers=headers)
        assert response.status_code == 401, (headers, response.text)
        assert "Sign-in required" in response.text

    # A proxy that appends its value to a client-supplied header must not let the client win.
    duplicated = team_mode.get(
        "/api/v1/projects/",
        headers=[("Remote-Email", "mallory@example.com"), ("Remote-Email", USER)],
    )
    assert duplicated.status_code == 401
    assert team_mode.post("/api/v1/projects/", json={"name": "Nope"}).status_code == 401

    for public_path in (
        "/api/v1/workbench/health",
        "/api/v1/utils/health-check/",
        "/api/v1/workbench/status",
    ):
        assert untrusted.get(public_path).status_code == 200, public_path


def test_team_mode_records_who_acted(team_mode: TestClient) -> None:
    created = team_mode.post("/api/v1/projects/", json={"name": "Team project"}, headers=SIGNED_IN)
    assert created.status_code in {200, 201}, created.text
    project_id = created.json()["id"]

    events = team_mode.get(
        f"/api/v1/audit/events?project_id={project_id}", headers=SIGNED_IN
    ).json()["data"]

    assert events
    assert {event["actor"] for event in events} == {USER}


def test_websocket_handshakes_require_the_same_identity(
    team_mode: TestClient,
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    url = f"/api/v1/workflows/{uuid.uuid4()}/stream"

    with pytest.raises(WebSocketDisconnect) as rejected:
        with team_mode.websocket_connect(url):
            pass
    assert rejected.value.code == 1008
    assert rejected.value.reason == "Sign-in required."

    previous_engine = getattr(app.state, "workbench_engine", None)
    app.state.workbench_engine = workbench_api_env.engine
    try:
        with team_mode.websocket_connect(url, headers=SIGNED_IN) as websocket:
            assert websocket.receive_json() == {"type": "error", "detail": "Workflow not found"}
    finally:
        if previous_engine is None:
            delattr(app.state, "workbench_engine")
        else:
            app.state.workbench_engine = previous_engine


def test_local_mode_session_reports_the_local_operator(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    session = workbench_api_env.client.get("/api/v1/workbench/session").json()
    local_email = app.state.workbench_settings.LOCAL_WORKBENCH_USER_EMAIL

    assert session["auth_mode"] == "local"
    assert session["user"] == local_email
    assert session["logout_url"] is None
    created = workbench_api_env.client.post("/api/v1/projects/", json={"name": "Local"})
    events = workbench_api_env.client.get(
        f"/api/v1/audit/events?project_id={created.json()['id']}"
    ).json()["data"]
    assert {event["actor"] for event in events} == {local_email}


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"AUTH_MODE": "proxy"}, "requires TRUSTED_PROXY_CIDRS"),
        ({"AUTH_MODE": "sso"}, "AUTH_MODE must be one of"),
        ({"AUTH_PROXY_USER_HEADER": "Remote Email"}, "HTTP header name"),
        ({"AUTH_PROXY_LOGOUT_URL": "javascript:alert(1)"}, "AUTH_PROXY_LOGOUT_URL"),
        ({"AUTH_PROXY_LOGOUT_URL": "//evil.example/logout"}, "AUTH_PROXY_LOGOUT_URL"),
    ],
)
def test_unsafe_team_mode_settings_are_refused(overrides: dict[str, str], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        Settings(**overrides)  # type: ignore[arg-type]


def test_team_mode_settings_normalize() -> None:
    configured = Settings(
        AUTH_MODE="PROXY",  # type: ignore[arg-type]
        TRUSTED_PROXY_CIDRS=("10.0.0.5",),
        AUTH_PROXY_NAME_HEADER="",
        AUTH_PROXY_LOGOUT_URL="https://auth.example.com/logout",
    )

    assert configured.AUTH_MODE == "proxy"
    assert configured.TRUSTED_PROXY_CIDRS == ("10.0.0.5/32",)
    assert configured.AUTH_PROXY_NAME_HEADER == ""
    assert configured.AUTH_PROXY_LOGOUT_URL == "https://auth.example.com/logout"


def test_proxy_identity_rejects_unsafe_values_and_trusts_mapped_ipv4_peers() -> None:
    configured = Settings(AUTH_MODE="proxy", TRUSTED_PROXY_CIDRS=("10.0.0.0/24",))

    assert is_trusted_proxy_host("::ffff:10.0.0.9", configured.TRUSTED_PROXY_CIDRS)
    assert not is_trusted_proxy_host("10.0.1.9", configured.TRUSTED_PROXY_CIDRS)
    assert proxy_actor(configured, "::ffff:10.0.0.9", Headers({"remote-email": USER})).email == USER
    for headers in ({"remote-email": "alice\x00@example.com"}, {"remote-email": "ali\nce"}):
        with pytest.raises(ProxyIdentityError):
            proxy_actor(configured, "10.0.0.9", Headers(headers))
    with pytest.raises(ProxyIdentityError, match="login proxy"):
        proxy_actor(configured, None, Headers({"remote-email": USER}))

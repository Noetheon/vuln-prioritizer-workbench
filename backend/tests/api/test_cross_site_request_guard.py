from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from starlette.datastructures import Headers
from starlette.websockets import WebSocketDisconnect

from app.core.config import Settings
from app.core.request_origin import CrossSiteRequestGuard
from app.main import create_app

LOCAL_ORIGIN = "http://127.0.0.1:8765"
UNKNOWN_WORKFLOW_STREAM = "/api/v1/workflows/00000000-0000-4000-8000-000000000001/stream"


@pytest.fixture()
def local_client(tmp_path: Path) -> Iterator[TestClient]:
    settings = Settings(
        SQLALCHEMY_DATABASE_URI=f"sqlite:///{tmp_path / 'workbench.db'}",
        FRONTEND_HOST="",
        BACKEND_CORS_ORIGINS=(),
        RATE_LIMIT_ENABLED=False,
    )
    with TestClient(create_app(settings), base_url=LOCAL_ORIGIN) as client:
        yield client


def test_state_changes_from_another_site_are_rejected(local_client: TestClient) -> None:
    for headers in (
        {"Origin": "https://attacker.example"},
        {"Origin": "null"},
        {"Origin": "http://127.0.0.1:9999"},
        {"Sec-Fetch-Site": "cross-site"},
    ):
        response = local_client.post("/api/v1/projects/", json={"name": "x"}, headers=headers)
        assert response.status_code == 403, headers
        assert response.json()["code"] == "cross_site_request_rejected"
        assert "frame-ancestors 'none'" in response.headers["content-security-policy"]


def test_cross_site_multipart_import_never_reaches_the_queue(local_client: TestClient) -> None:
    project = local_client.post("/api/v1/projects/", json={"name": "Guarded"}).json()

    rejected = local_client.post(
        f"/api/v1/projects/{project['id']}/imports",
        headers={"Origin": "https://attacker.example", "Sec-Fetch-Site": "cross-site"},
        data={"input_type": "cve-list"},
        files={"file": ("cves.txt", b"CVE-2024-3094\n", "text/plain")},
    )
    runs = local_client.get(f"/api/v1/projects/{project['id']}/runs/")

    assert rejected.status_code == 403
    assert runs.json()["count"] == 0


def test_same_origin_browsers_and_non_browser_clients_are_allowed(
    local_client: TestClient,
) -> None:
    for headers in (
        {},
        {"Origin": LOCAL_ORIGIN},
        {"Origin": LOCAL_ORIGIN, "Sec-Fetch-Site": "same-origin"},
        {"Sec-Fetch-Site": "same-origin"},
    ):
        response = local_client.post("/api/v1/projects/", json={"name": "ok"}, headers=headers)
        assert response.status_code == 200, headers

    read = local_client.get("/api/v1/projects/", headers={"Origin": "https://attacker.example"})
    assert read.status_code == 200


def test_cross_site_websocket_handshake_is_refused(local_client: TestClient) -> None:
    with pytest.raises(WebSocketDisconnect) as refused:
        with local_client.websocket_connect(
            UNKNOWN_WORKFLOW_STREAM, headers={"Origin": "https://attacker.example"}
        ):
            pass
    assert refused.value.code == 1008

    # Starlette's test WebSocket handshake always sends ``Host: testserver``.
    with local_client.websocket_connect(
        UNKNOWN_WORKFLOW_STREAM, headers={"Origin": "http://testserver"}
    ) as accepted:
        assert accepted.receive_json() == {"type": "error", "detail": "Workflow not found"}


def test_configured_frontend_origin_is_trusted(tmp_path: Path) -> None:
    settings = Settings(
        SQLALCHEMY_DATABASE_URI=f"sqlite:///{tmp_path / 'workbench.db'}",
        FRONTEND_HOST="http://localhost:5173",
        RATE_LIMIT_ENABLED=False,
    )
    with TestClient(create_app(settings), base_url="http://localhost:8000") as client:
        allowed = client.post(
            "/api/v1/projects/",
            json={"name": "dev"},
            headers={"Origin": "http://localhost:5173", "Sec-Fetch-Site": "same-site"},
        )
        rejected = client.post(
            "/api/v1/projects/",
            json={"name": "dev"},
            headers={"Origin": "http://localhost:5174"},
        )

    assert allowed.status_code == 200
    assert rejected.status_code == 403


@pytest.mark.parametrize(
    ("origin", "host", "expected"),
    [
        ("https://workbench.example", "workbench.example", True),
        ("https://workbench.example:443", "workbench.example", True),
        ("http://[::1]:8765", "[::1]:8765", True),
        ("http://LOCALHOST:8765", "localhost:8765", True),
        ("http://localhost:8765", "127.0.0.1:8765", False),
        ("ftp://localhost:8765", "localhost:8765", False),
        ("http://localhost:notaport", "localhost:8765", False),
    ],
)
def test_origin_matching_normalizes_scheme_default_ports_and_case(
    origin: str,
    host: str,
    expected: bool,
) -> None:
    guard = CrossSiteRequestGuard(app=lambda *_: None)  # type: ignore[arg-type]
    headers = Headers(headers={"origin": origin, "host": host})

    assert guard._request_is_same_site(headers) is expected

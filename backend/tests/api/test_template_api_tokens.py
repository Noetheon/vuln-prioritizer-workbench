from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from uuid import UUID

from fastapi.testclient import TestClient
from sqlmodel import Session
from utils.template_workbench import (
    TemplateApiEnv,
    auth_headers,
    create_project_via_api,
)

from app import models as app_models


def test_template_scoped_service_tokens_gate_import_report_admin_and_revoke(
    template_api_env: TemplateApiEnv,
    tmp_path: Path,
) -> None:
    _configure_template_dirs(template_api_env, tmp_path)
    client = template_api_env.client
    jwt_headers = auth_headers(client)
    project = create_project_via_api(client, jwt_headers)

    admin_token = _create_token(client, jwt_headers, name="token-admin", scopes=["admin"])
    admin_headers = _bearer_headers(admin_token["token"])
    read_token = _create_token(client, admin_headers, name="token-read", scopes=["read"])
    import_token = _create_token(client, admin_headers, name="token-import", scopes=["import"])
    report_token = _create_token(client, admin_headers, name="token-report", scopes=["report"])

    with Session(template_api_env.engine) as session:
        token_record = session.get(app_models.ApiToken, UUID(str(import_token["id"])))
        assert token_record is not None
        assert token_record.token_hash != import_token["token"]
        assert len(token_record.token_hash) == 64
        assert token_record.scopes == ["import"]

    listed = client.get("/api/v1/api-tokens/", headers=admin_headers)
    assert listed.status_code == 200, listed.text
    listed_payload = listed.json()
    assert listed_payload["count"] == 4
    assert '"token"' not in listed.text
    assert import_token["token"] not in listed.text
    assert {tuple(item["scopes"]) for item in listed_payload["data"]} == {
        ("admin",),
        ("read",),
        ("import",),
        ("report",),
    }

    read_projects = client.get("/api/v1/projects/", headers=_bearer_headers(read_token["token"]))
    assert read_projects.status_code == 200, read_projects.text

    read_import = _upload_cve_list(client, project["id"], token=read_token["token"])
    assert read_import.status_code == 403
    assert "import scope" in read_import.text

    imported = _upload_cve_list(client, project["id"], token=import_token["token"])
    assert imported.status_code == 200, imported.text
    run_id = imported.json()["id"]

    import_report = client.post(
        f"/api/v1/runs/{run_id}/reports",
        headers=_bearer_headers(import_token["token"]),
        json={"format": "json"},
    )
    assert import_report.status_code == 403
    assert "report scope" in import_report.text

    report = client.post(
        f"/api/v1/runs/{run_id}/reports",
        headers=_bearer_headers(report_token["token"]),
        json={"format": "json"},
    )
    assert report.status_code == 200, report.text
    download = client.get(
        report.json()["download_url"],
        headers=_bearer_headers(report_token["token"]),
    )
    assert download.status_code == 200, download.text

    listed_after_use = client.get("/api/v1/api-tokens/", headers=admin_headers).json()["data"]
    import_row = next(item for item in listed_after_use if item["id"] == import_token["id"])
    report_row = next(item for item in listed_after_use if item["id"] == report_token["id"])
    assert import_row["last_used_at"] is not None
    assert report_row["last_used_at"] is not None

    revoke = client.delete(f"/api/v1/api-tokens/{import_token['id']}", headers=admin_headers)
    assert revoke.status_code == 200, revoke.text
    assert revoke.json()["active"] is False
    revoked_import = _upload_cve_list(client, project["id"], token=import_token["token"])
    assert revoked_import.status_code == 403

    read_list_tokens = client.get(
        "/api/v1/api-tokens/",
        headers=_bearer_headers(read_token["token"]),
    )
    assert read_list_tokens.status_code == 403


def test_template_api_token_creation_rejects_empty_or_unknown_scopes(
    template_api_env: TemplateApiEnv,
) -> None:
    headers = auth_headers(template_api_env.client)

    empty = template_api_env.client.post(
        "/api/v1/api-tokens/",
        headers=headers,
        json={"name": "empty", "scopes": []},
    )
    unknown = template_api_env.client.post(
        "/api/v1/api-tokens/",
        headers=headers,
        json={"name": "unknown", "scopes": ["read", "owner"]},
    )

    assert empty.status_code == 422
    assert unknown.status_code == 422


def _create_token(
    client: TestClient,
    headers: dict[str, str],
    *,
    name: str,
    scopes: list[str],
) -> dict[str, object]:
    response = client.post(
        "/api/v1/api-tokens/",
        headers=headers,
        json={"name": name, "scopes": scopes},
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["token"].startswith("vpr_")
    assert payload["token"] not in payload["id"]
    assert payload["scopes"] == scopes
    return payload


def _upload_cve_list(client: TestClient, project_id: str, *, token: str) -> object:
    return client.post(
        f"/api/v1/projects/{project_id}/imports",
        headers=_bearer_headers(token),
        data={"input_type": "cve-list"},
        files={"file": ("known-cves.txt", b"CVE-2024-3094\n", "text/plain")},
    )


def _bearer_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _configure_template_dirs(template_api_env: TemplateApiEnv, tmp_path: Path) -> None:
    active_settings = template_api_env.client.app.state.template_settings
    template_api_env.client.app.state.template_settings = replace(
        active_settings,
        IMPORT_UPLOAD_DIR=str((tmp_path / "template-uploads").resolve(strict=False)),
        REPORT_DIR=str((tmp_path / "template-reports").resolve(strict=False)),
    )

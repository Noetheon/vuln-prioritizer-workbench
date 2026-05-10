from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, select
from utils.template_workbench import (
    TemplateApiEnv,
    auth_headers,
    create_project_via_api,
)

from app import models as app_models
from app.core.rate_limit import InMemoryRateLimiter

PROJECT_ROOT = Path(__file__).resolve().parents[3]


def test_template_scoped_service_tokens_gate_import_report_admin_and_revoke(
    template_api_env: TemplateApiEnv,
    tmp_path: Path,
) -> None:
    _configure_template_dirs(template_api_env, tmp_path)
    client = template_api_env.client
    jwt_headers = auth_headers(client)
    project = create_project_via_api(client, jwt_headers)
    other_project = create_project_via_api(client, jwt_headers, name="Other Project")

    admin_token = _create_token(client, jwt_headers, name="token-admin", scopes=["admin"])
    admin_headers = _bearer_headers(admin_token["token"])
    read_token = _create_token(
        client,
        admin_headers,
        name="token-read",
        scopes=["read"],
        project_id=project["id"],
    )
    write_token = _create_token(
        client,
        admin_headers,
        name="token-write",
        scopes=["write"],
        project_id=project["id"],
    )
    import_token = _create_token(
        client,
        admin_headers,
        name="token-import",
        scopes=["import"],
        project_id=project["id"],
    )
    report_token = _create_token(
        client,
        admin_headers,
        name="token-report",
        scopes=["report"],
        project_id=project["id"],
    )

    with Session(template_api_env.engine) as session:
        token_record = session.get(app_models.ApiToken, UUID(str(import_token["id"])))
        assert token_record is not None
        assert token_record.token_hash != import_token["token"]
        assert len(token_record.token_hash) == 64
        assert token_record.scopes == ["import"]
        assert token_record.project_id == UUID(project["id"])

    listed = client.get("/api/v1/api-tokens/", headers=admin_headers)
    assert listed.status_code == 200, listed.text
    listed_payload = listed.json()
    assert listed_payload["count"] == 5
    assert '"token"' not in listed.text
    assert import_token["token"] not in listed.text
    assert {tuple(item["scopes"]) for item in listed_payload["data"]} == {
        ("admin",),
        ("read",),
        ("write",),
        ("import",),
        ("report",),
    }
    assert (
        next(item for item in listed_payload["data"] if item["id"] == admin_token["id"])[
            "project_id"
        ]
        is None
    )
    assert (
        next(item for item in listed_payload["data"] if item["id"] == read_token["id"])[
            "project_id"
        ]
        == project["id"]
    )

    read_projects = client.get("/api/v1/projects/", headers=_bearer_headers(read_token["token"]))
    assert read_projects.status_code == 200, read_projects.text
    assert read_projects.json()["count"] == 1
    assert read_projects.json()["data"][0]["id"] == project["id"]

    admin_read_projects = client.get("/api/v1/projects/", headers=admin_headers)
    assert admin_read_projects.status_code == 200, admin_read_projects.text
    assert {item["id"] for item in admin_read_projects.json()["data"]} == {
        project["id"],
        other_project["id"],
    }

    admin_created_project = client.post(
        "/api/v1/projects/",
        headers=admin_headers,
        json={"name": "Admin Token Project"},
    )
    assert admin_created_project.status_code == 200, admin_created_project.text
    admin_project_delete = client.delete(
        f"/api/v1/projects/{admin_created_project.json()['id']}",
        headers=admin_headers,
    )
    assert admin_project_delete.status_code == 204, admin_project_delete.text

    read_project_update = client.patch(
        f"/api/v1/projects/{project['id']}",
        headers=_bearer_headers(read_token["token"]),
        json={"description": "Read tokens must not mutate projects."},
    )
    assert read_project_update.status_code == 403
    assert "write scope" in read_project_update.text

    write_project_update = client.patch(
        f"/api/v1/projects/{project['id']}",
        headers=_bearer_headers(write_token["token"]),
        json={"description": "Updated by project-scoped automation."},
    )
    assert write_project_update.status_code == 200, write_project_update.text
    assert write_project_update.json()["description"] == "Updated by project-scoped automation."

    cross_project_update = client.patch(
        f"/api/v1/projects/{other_project['id']}",
        headers=_bearer_headers(write_token["token"]),
        json={"description": "Wrong project."},
    )
    assert cross_project_update.status_code == 403
    assert "not scoped to this project" in cross_project_update.text

    write_project_delete = client.delete(
        f"/api/v1/projects/{project['id']}",
        headers=_bearer_headers(write_token["token"]),
    )
    assert write_project_delete.status_code == 403
    assert "admin scope" in write_project_delete.text

    read_asset_create = client.post(
        f"/api/v1/projects/{project['id']}/assets/",
        headers=_bearer_headers(read_token["token"]),
        json=_asset_payload("read-denied"),
    )
    assert read_asset_create.status_code == 403
    assert "write scope" in read_asset_create.text

    cross_project_asset_create = client.post(
        f"/api/v1/projects/{other_project['id']}/assets/",
        headers=_bearer_headers(write_token["token"]),
        json=_asset_payload("cross-denied"),
    )
    assert cross_project_asset_create.status_code == 403
    assert "not scoped to this project" in cross_project_asset_create.text

    created_asset = client.post(
        f"/api/v1/projects/{project['id']}/assets/",
        headers=_bearer_headers(write_token["token"]),
        json=_asset_payload("payments-api"),
    )
    assert created_asset.status_code == 200, created_asset.text
    asset_id = created_asset.json()["id"]

    read_asset_update = client.patch(
        f"/api/v1/assets/{asset_id}",
        headers=_bearer_headers(read_token["token"]),
        json={"name": "Denied Update"},
    )
    assert read_asset_update.status_code == 403
    assert "write scope" in read_asset_update.text

    asset_update = client.patch(
        f"/api/v1/assets/{asset_id}",
        headers=_bearer_headers(write_token["token"]),
        json={"name": "Payments API Cluster", "criticality": "high"},
    )
    assert asset_update.status_code == 200, asset_update.text
    assert asset_update.json()["name"] == "Payments API Cluster"
    assert asset_update.json()["criticality"] == "high"

    read_waivers = client.get(
        f"/api/v1/projects/{project['id']}/waivers/",
        headers=_bearer_headers(read_token["token"]),
    )
    assert read_waivers.status_code == 200, read_waivers.text
    assert read_waivers.json()["count"] == 0

    read_waiver_create = client.post(
        f"/api/v1/projects/{project['id']}/waivers/",
        headers=_bearer_headers(read_token["token"]),
        json=_waiver_payload(),
    )
    assert read_waiver_create.status_code == 403
    assert "write scope" in read_waiver_create.text

    created_waiver = client.post(
        f"/api/v1/projects/{project['id']}/waivers/",
        headers=_bearer_headers(write_token["token"]),
        json=_waiver_payload(),
    )
    assert created_waiver.status_code == 200, created_waiver.text
    assert created_waiver.json()["owner"] == "risk-owner"

    cross_project_waiver_create = client.post(
        f"/api/v1/projects/{other_project['id']}/waivers/",
        headers=_bearer_headers(write_token["token"]),
        json=_waiver_payload(),
    )
    assert cross_project_waiver_create.status_code == 403
    assert "not scoped to this project" in cross_project_waiver_create.text

    listed_waivers = client.get(
        f"/api/v1/projects/{project['id']}/waivers/",
        headers=_bearer_headers(read_token["token"]),
    )
    assert listed_waivers.status_code == 200, listed_waivers.text
    assert listed_waivers.json()["count"] == 1

    read_import = _upload_cve_list(client, project["id"], token=read_token["token"])
    assert read_import.status_code == 403
    assert "import scope" in read_import.text

    cross_project_import = _upload_cve_list(
        client, other_project["id"], token=import_token["token"]
    )
    assert cross_project_import.status_code == 403
    assert "not scoped to this project" in cross_project_import.text

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


def test_template_service_tokens_fail_closed_for_inactive_configured_user(
    template_api_env: TemplateApiEnv,
    tmp_path: Path,
) -> None:
    _configure_template_dirs(template_api_env, tmp_path)
    client = template_api_env.client
    jwt_headers = auth_headers(client)
    project = create_project_via_api(client, jwt_headers)

    imported = client.post(
        f"/api/v1/projects/{project['id']}/imports",
        headers=jwt_headers,
        data={"input_type": "cve-list"},
        files={"file": ("known-cves.txt", b"CVE-2024-3094\n", "text/plain")},
    )
    assert imported.status_code == 200, imported.text
    run_id = imported.json()["id"]

    service_tokens = {
        "read": _create_token(
            client,
            jwt_headers,
            name="inactive-read",
            scopes=["read"],
            project_id=project["id"],
        ),
        "write": _create_token(
            client,
            jwt_headers,
            name="inactive-write",
            scopes=["write"],
            project_id=project["id"],
        ),
        "import": _create_token(
            client,
            jwt_headers,
            name="inactive-import",
            scopes=["import"],
            project_id=project["id"],
        ),
        "report": _create_token(
            client,
            jwt_headers,
            name="inactive-report",
            scopes=["report"],
            project_id=project["id"],
        ),
        "admin": _create_token(
            client,
            jwt_headers,
            name="inactive-admin",
            scopes=["admin"],
        ),
    }

    with Session(template_api_env.engine) as session:
        active_settings = template_api_env.client.app.state.workbench_settings
        user = session.exec(
            select(app_models.User).where(app_models.User.email == active_settings.FIRST_SUPERUSER)
        ).one()
        user.is_active = False
        session.add(user)
        session.commit()

    responses = {
        "read": client.get(
            "/api/v1/projects/",
            headers=_bearer_headers(str(service_tokens["read"]["token"])),
        ),
        "write": client.patch(
            f"/api/v1/projects/{project['id']}",
            headers=_bearer_headers(str(service_tokens["write"]["token"])),
            json={"description": "inactive service token must not mutate"},
        ),
        "import": _upload_cve_list(
            client,
            project["id"],
            token=str(service_tokens["import"]["token"]),
        ),
        "report": client.post(
            f"/api/v1/runs/{run_id}/reports",
            headers=_bearer_headers(str(service_tokens["report"]["token"])),
            json={"format": "json"},
        ),
        "admin": client.get(
            "/api/v1/api-tokens/",
            headers=_bearer_headers(str(service_tokens["admin"]["token"])),
        ),
    }

    for scope, response in responses.items():
        assert response.status_code == 403, (scope, response.text)
        assert "Inactive user" in response.text
        assert str(service_tokens[scope]["token"]) not in response.text

    with Session(template_api_env.engine) as session:
        token_records = session.exec(select(app_models.ApiToken)).all()
        inactive_token_ids = {UUID(str(token["id"])) for token in service_tokens.values()}
        inactive_records = [token for token in token_records if token.id in inactive_token_ids]
        failure_events = session.exec(
            select(app_models.AuditEvent).where(
                app_models.AuditEvent.action == "api_token.auth.failure"
            )
        ).all()

    assert {record.name for record in inactive_records} == {
        "inactive-read",
        "inactive-write",
        "inactive-import",
        "inactive-report",
        "inactive-admin",
    }
    assert all(record.last_used_at is None for record in inactive_records)
    assert len(failure_events) == len(service_tokens)
    assert {event.resource_id for event in failure_events} == {
        str(token["id"]) for token in service_tokens.values()
    }
    assert {event.status for event in failure_events} == {"failure"}
    assert all(event.detail_json["reason"] == "inactive_user" for event in failure_events)
    assert all(
        str(token["token"]) not in str(event.detail_json)
        for token in service_tokens.values()
        for event in failure_events
    )


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


def test_template_api_token_creation_requires_project_scope_for_non_admin_tokens(
    template_api_env: TemplateApiEnv,
) -> None:
    client = template_api_env.client
    headers = auth_headers(client)
    project = create_project_via_api(client, headers)

    missing_project = client.post(
        "/api/v1/api-tokens/",
        headers=headers,
        json={"name": "read-global", "scopes": ["read"]},
    )
    admin_with_project = client.post(
        "/api/v1/api-tokens/",
        headers=headers,
        json={"name": "admin-project", "scopes": ["admin"], "project_id": project["id"]},
    )

    assert missing_project.status_code == 422
    assert "project_id" in missing_project.text
    assert admin_with_project.status_code == 422
    assert "Admin API tokens must not be project-scoped" in admin_with_project.text


def test_template_api_tokens_expose_expiry_and_reject_expired_tokens(
    template_api_env: TemplateApiEnv,
) -> None:
    client = template_api_env.client
    headers = auth_headers(client)
    project = create_project_via_api(client, headers)
    explicit_expiry = (datetime.now(UTC) + timedelta(days=7)).replace(microsecond=0)

    token = _create_token(
        client,
        headers,
        name="short-lived-read",
        scopes=["read"],
        project_id=project["id"],
        expires_at=explicit_expiry.isoformat(),
    )

    assert datetime.fromisoformat(str(token["expires_at"])) == explicit_expiry
    assert token["active"] is True

    listed = client.get("/api/v1/api-tokens/", headers=headers)
    assert listed.status_code == 200, listed.text
    listed_token = next(item for item in listed.json()["data"] if item["id"] == token["id"])
    assert listed_token["expires_at"] == token["expires_at"]
    assert listed_token["active"] is True

    with Session(template_api_env.engine) as session:
        token_record = session.get(app_models.ApiToken, UUID(str(token["id"])))
        assert token_record is not None
        token_record.expires_at = datetime.now(UTC) - timedelta(minutes=1)
        session.add(token_record)
        session.commit()

    expired = client.get("/api/v1/projects/", headers=_bearer_headers(str(token["token"])))
    assert expired.status_code == 403

    listed_after_expiry = client.get("/api/v1/api-tokens/", headers=headers)
    listed_expired = next(
        item for item in listed_after_expiry.json()["data"] if item["id"] == token["id"]
    )
    assert listed_expired["active"] is False


def test_template_api_token_creation_rejects_past_expiry(
    template_api_env: TemplateApiEnv,
) -> None:
    headers = auth_headers(template_api_env.client)
    response = template_api_env.client.post(
        "/api/v1/api-tokens/",
        headers=headers,
        json={
            "name": "already-expired",
            "scopes": ["admin"],
            "expires_at": (datetime.now(UTC) - timedelta(days=1)).isoformat(),
        },
    )

    assert response.status_code == 422
    assert "expires_at must be in the future" in response.text


def test_template_malformed_bearer_token_does_not_run_api_token_digest(
    template_api_env: TemplateApiEnv,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_digest(_raw_token: str) -> str:
        raise AssertionError("malformed bearer token reached API-token PBKDF2 digest")

    monkeypatch.setattr("app.api.deps.api_token_digest", fail_digest)

    response = template_api_env.client.get(
        "/api/v1/projects/",
        headers={"Authorization": "Bearer not-a-valid-token"},
    )

    assert response.status_code == 403


def test_template_token_failure_rate_limit_runs_before_service_token_digest(
    template_api_env: TemplateApiEnv,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = template_api_env.client
    old_settings = client.app.state.workbench_settings
    old_limiter = client.app.state.rate_limiter
    client.app.state.workbench_settings = replace(
        old_settings,
        RATE_LIMIT_ENABLED=True,
        TOKEN_FAILURE_RATE_LIMIT_PER_MINUTE=1,
    )
    client.app.state.rate_limiter = InMemoryRateLimiter()

    try:
        first_failure = client.get(
            "/api/v1/projects/",
            headers={"Authorization": "Bearer not-a-valid-token"},
        )
        assert first_failure.status_code == 403

        def fail_digest(_raw_token: str) -> str:
            raise AssertionError("rate-limited service token reached API-token digest")

        monkeypatch.setattr("app.api.deps.api_token_digest", fail_digest)

        rate_limited = client.get(
            "/api/v1/projects/",
            headers={"Authorization": f"Bearer vpr_{'A' * 40}"},
        )
    finally:
        client.app.state.workbench_settings = old_settings
        client.app.state.rate_limiter = old_limiter

    assert rate_limited.status_code == 429


def _create_token(
    client: TestClient,
    headers: dict[str, str],
    *,
    name: str,
    scopes: list[str],
    project_id: str | None = None,
    expires_at: str | None = None,
) -> dict[str, object]:
    body: dict[str, object] = {"name": name, "scopes": scopes}
    if project_id is not None:
        body["project_id"] = project_id
    if expires_at is not None:
        body["expires_at"] = expires_at
    response = client.post(
        "/api/v1/api-tokens/",
        headers=headers,
        json=body,
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["token"].startswith("vpr_")
    assert payload["token"] not in payload["id"]
    assert payload["scopes"] == scopes
    assert payload["project_id"] == project_id
    assert payload["expires_at"]
    return payload


def _upload_cve_list(client: TestClient, project_id: str, *, token: str) -> object:
    return client.post(
        f"/api/v1/projects/{project_id}/imports",
        headers=_bearer_headers(token),
        data={"input_type": "cve-list"},
        files={"file": ("known-cves.txt", b"CVE-2024-3094\n", "text/plain")},
    )


def _asset_payload(asset_key: str) -> dict[str, object]:
    return {
        "asset_key": asset_key,
        "name": asset_key.replace("-", " ").title(),
        "target_ref": f"registry.example.test/{asset_key}:2026.05.06",
        "owner": "platform",
        "business_service": "payments",
        "environment": "production",
        "exposure": "internal",
        "criticality": "critical",
    }


def _waiver_payload() -> dict[str, object]:
    return {
        "cve_id": "CVE-2024-3094",
        "owner": "risk-owner",
        "reason": "Accepted during automation window.",
        "expires_at": "2099-12-31",
        "approval_ref": "CAB-TOKEN",
    }


def _bearer_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _configure_template_dirs(template_api_env: TemplateApiEnv, tmp_path: Path) -> None:
    active_settings = template_api_env.client.app.state.workbench_settings
    template_api_env.client.app.state.workbench_settings = replace(
        active_settings,
        IMPORT_UPLOAD_DIR=str((tmp_path / "template-uploads").resolve(strict=False)),
        REPORT_DIR=str((tmp_path / "template-reports").resolve(strict=False)),
        PROVIDER_SNAPSHOT_DIR=str(PROJECT_ROOT / "data"),
        DEMO_PROVIDER_SNAPSHOT_ENABLED=True,
    )

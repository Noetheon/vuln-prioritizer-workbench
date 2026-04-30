from __future__ import annotations

from typing import Any
from uuid import UUID

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session
from utils.template_workbench import (
    TemplateApiEnv,
    auth_headers,
    create_project_via_api,
    seed_finding_pair,
)

from app import models as app_models


def test_template_github_issue_preview_selected_findings_markdown_redacts_secrets(
    template_api_env: TemplateApiEnv,
) -> None:
    client = template_api_env.client
    headers = auth_headers(client)
    project = create_project_via_api(client, headers)
    seeded = seed_finding_pair(
        template_api_env.engine,
        template_api_env.app_models,
        template_api_env.repositories,
        project_id=UUID(project["id"]),
    )
    selected_id = seeded["finding_ids"][0]
    unselected_id = seeded["finding_ids"][1]

    with Session(template_api_env.engine) as session:
        finding = session.get(app_models.Finding, selected_id)
        assert finding is not None
        finding.rationale = (
            "EPSS and KEV make this urgent. token=ghp_secretshouldnotleak "
            "and source /Users/alice/private/sbom.json"
        )
        finding.recommended_action = "Upgrade log4j-core and rotate api_key=super-secret-value."
        finding.risk_score = 98.6
        finding.epss = 0.9442
        finding.evidence_json = {
            "report_url": "https://github.com/acme/app/security/advisories/GHSA-demo",
            "token": "ghp_hiddenvalue",
            "artifact": "evidence-bundle.zip",
        }
        session.add(finding)
        session.commit()

    response = client.post(
        f"/api/v1/projects/{project['id']}/github/issues/preview",
        headers=headers,
        json={
            "finding_ids": [str(selected_id), str(unselected_id), str(selected_id)],
            "label_prefix": "vpw",
            "milestone": 12,
        },
    )

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["dry_run"] is True
    assert payload["count"] == 2
    assert [item["finding_id"] for item in payload["data"]] == [
        str(selected_id),
        str(unselected_id),
    ]
    issue = payload["data"][0]
    body = issue["body"]
    assert issue["title"].startswith("CVE-2021-44228: Critical priority remediation")
    assert issue["labels"] == ["vpw", "vpw:priority-critical", "security", "vpw:kev"]
    assert issue["milestone"] == 12
    assert "## Workbench Finding" in body
    assert "## Why This Should Be Prioritized" in body
    assert "## Recommended Remediation" in body
    assert "## Evidence References" in body
    assert f"/api/v1/findings/{selected_id}" in body
    assert "https://nvd.nist.gov/vuln/detail/CVE-2021-44228" in body
    assert "https://github.com/acme/app/security/advisories/GHSA-demo" in body
    assert "evidence-bundle.zip" in body
    assert "ghp_secretshouldnotleak" not in body
    assert "ghp_hiddenvalue" not in body
    assert "super-secret-value" not in body
    assert "/Users/alice/private/sbom.json" not in body
    assert "[REDACTED-PATH]" in body
    assert "vuln-prioritizer duplicate_key" in body


def test_template_github_issue_export_requires_explicit_token_and_skips_duplicates(
    template_api_env: TemplateApiEnv,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = template_api_env.client
    headers = auth_headers(client)
    project = create_project_via_api(client, headers)
    seeded = seed_finding_pair(
        template_api_env.engine,
        template_api_env.app_models,
        template_api_env.repositories,
        project_id=UUID(project["id"]),
    )
    selected_id = seeded["finding_ids"][0]

    dry_run = client.post(
        f"/api/v1/projects/{project['id']}/github/issues/export",
        headers=headers,
        json={
            "repository": "acme/workbench-triage",
            "finding_ids": [str(selected_id)],
            "dry_run": True,
        },
    )
    assert dry_run.status_code == 200, dry_run.text
    assert dry_run.json()["created_count"] == 0
    assert dry_run.json()["data"][0]["status"] == "preview"

    implicit_token = client.post(
        f"/api/v1/projects/{project['id']}/github/issues/export",
        headers=headers,
        json={
            "repository": "acme/workbench-triage",
            "finding_ids": [str(selected_id)],
            "dry_run": False,
        },
    )
    assert implicit_token.status_code == 422
    assert "token_env is required when dry_run is false" in implicit_token.text

    missing_token = client.post(
        f"/api/v1/projects/{project['id']}/github/issues/export",
        headers=headers,
        json={
            "repository": "acme/workbench-triage",
            "finding_ids": [str(selected_id)],
            "dry_run": False,
            "token_env": "VPW_GITHUB_TOKEN",
        },
    )
    assert missing_token.status_code == 422
    assert "VPW_GITHUB_TOKEN is not configured" in missing_token.text

    posted_payloads: list[dict[str, Any]] = []

    class FakeGitHubResponse:
        status_code = 201

        def json(self) -> dict[str, Any]:
            return {"html_url": "https://github.com/acme/workbench-triage/issues/42", "number": 42}

    def fake_post(*args: Any, **kwargs: Any) -> FakeGitHubResponse:
        assert args == ("https://api.github.com/repos/acme/workbench-triage/issues",)
        assert kwargs["headers"]["Authorization"] == "Bearer ghp_test_value"
        assert "ghp_test_value" not in kwargs["json"]["body"]
        assert "vuln-prioritizer duplicate_key" in kwargs["json"]["body"]
        posted_payloads.append(kwargs["json"])
        return FakeGitHubResponse()

    monkeypatch.setenv("VPW_GITHUB_TOKEN", "ghp_test_value")
    monkeypatch.setattr("app.services.github_issues.requests.post", fake_post)

    created = client.post(
        f"/api/v1/projects/{project['id']}/github/issues/export",
        headers=headers,
        json={
            "repository": "acme/workbench-triage",
            "finding_ids": [str(selected_id)],
            "dry_run": False,
            "token_env": "VPW_GITHUB_TOKEN",
        },
    )
    assert created.status_code == 200, created.text
    created_payload = created.json()
    assert created_payload["created_count"] == 1
    assert created_payload["data"][0]["status"] == "created"
    assert created_payload["data"][0]["issue_url"].endswith("/issues/42")
    assert len(posted_payloads) == 1

    duplicate = client.post(
        f"/api/v1/projects/{project['id']}/github/issues/export",
        headers=headers,
        json={
            "repository": "acme/workbench-triage",
            "finding_ids": [str(selected_id)],
            "dry_run": False,
            "token_env": "VPW_GITHUB_TOKEN",
        },
    )
    assert duplicate.status_code == 200, duplicate.text
    duplicate_payload = duplicate.json()
    assert duplicate_payload["created_count"] == 0
    assert duplicate_payload["skipped_count"] == 1
    assert duplicate_payload["data"][0]["status"] == "skipped_duplicate"
    assert len(posted_payloads) == 1


def test_template_github_issue_export_uses_report_scope(
    template_api_env: TemplateApiEnv,
) -> None:
    client = template_api_env.client
    jwt_headers = auth_headers(client)
    project = create_project_via_api(client, jwt_headers)
    seed_finding_pair(
        template_api_env.engine,
        template_api_env.app_models,
        template_api_env.repositories,
        project_id=UUID(project["id"]),
    )
    report_token = _create_token(client, jwt_headers, name="report-github", scopes=["report"])
    read_token = _create_token(client, jwt_headers, name="read-github", scopes=["read"])

    allowed = client.post(
        f"/api/v1/projects/{project['id']}/github/issues/preview",
        headers=_bearer_headers(str(report_token["token"])),
        json={"limit": 1},
    )
    denied = client.post(
        f"/api/v1/projects/{project['id']}/github/issues/preview",
        headers=_bearer_headers(str(read_token["token"])),
        json={"limit": 1},
    )

    assert allowed.status_code == 200, allowed.text
    assert allowed.json()["count"] == 1
    assert denied.status_code == 403
    assert "report scope" in denied.text


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
    return response.json()


def _bearer_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}

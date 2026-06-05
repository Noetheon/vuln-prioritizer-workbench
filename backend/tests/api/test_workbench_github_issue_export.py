from __future__ import annotations

import json
from typing import Any
from uuid import UUID

import pytest
import requests
from fastapi import HTTPException
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, select
from utils.workbench_env import (
    WorkbenchApiEnv,
    create_project_via_api,
    local_api_headers,
    seed_finding_pair,
)

from app import models as app_models
from app.contracts.decision_evidence import FindingDecisionEvidenceV2


def test_workbench_github_issue_preview_selected_findings_markdown_redacts_secrets(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    client = workbench_api_env.client
    headers = local_api_headers(client)
    project = create_project_via_api(client, headers)
    seeded = seed_finding_pair(
        workbench_api_env.engine,
        workbench_api_env.app_models,
        workbench_api_env.repositories,
        project_id=UUID(project["id"]),
        with_decision_evidence=True,
    )
    selected_id = seeded["finding_ids"][0]
    unselected_id = seeded["finding_ids"][1]

    with Session(workbench_api_env.engine) as session:
        evidence_repo = workbench_api_env.repositories.EvidenceRepository(session)
        evidence_record = evidence_repo.latest_finding_decision_evidence_record(selected_id)
        assert evidence_record is not None
        evidence = FindingDecisionEvidenceV2.model_validate(evidence_record.payload_json)
        evidence_record.payload_json = evidence.model_copy(
            update={
                "rationale": (
                    "EPSS and KEV make this urgent. token=ghp_secretshouldnotleak "
                    "and source /Users/alice/private/sbom.json"
                ),
                "recommended_action": ("Upgrade log4j-core and rotate api_key=super-secret-value."),
                "risk_score": 98.6,
                "epss": 0.9442,
            }
        ).to_jsonable()
        session.add(evidence_record)
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
    assert "ghp_secretshouldnotleak" not in body
    assert "ghp_hiddenvalue" not in body
    assert "super-secret-value" not in body
    assert "/Users/alice/private/sbom.json" not in body
    assert "[REDACTED-PATH]" in body
    assert "vuln-prioritizer-workbench duplicate_key" in body
    audit_events = _audit_payloads(workbench_api_env, action="github_issue.preview")
    assert audit_events[-1]["status"] == "success"
    assert audit_events[-1]["detail"]["count"] == 2
    assert audit_events[-1]["detail"]["requested_finding_count"] == 2
    serialized_audit = json.dumps(audit_events[-1]["detail"], sort_keys=True)
    assert "ghp_secretshouldnotleak" not in serialized_audit
    assert "ghp_hiddenvalue" not in serialized_audit
    assert "/Users/alice/private/sbom.json" not in serialized_audit
    assert "body" not in audit_events[-1]["detail"]


def test_workbench_github_issue_export_requires_explicit_token_and_skips_duplicates(
    workbench_api_env: WorkbenchApiEnv,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = workbench_api_env.client
    headers = local_api_headers(client)
    project = create_project_via_api(client, headers)
    seeded = seed_finding_pair(
        workbench_api_env.engine,
        workbench_api_env.app_models,
        workbench_api_env.repositories,
        project_id=UUID(project["id"]),
        with_decision_evidence=True,
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
        assert "vuln-prioritizer-workbench duplicate_key" in kwargs["json"]["body"]
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
    audit_events = _audit_payloads(workbench_api_env, action="github_issue.export")
    failure_kinds = {
        event["detail"].get("failure_kind")
        for event in audit_events
        if event["status"] == "failure"
    }
    assert {"token_env_required", "token_not_configured"}.issubset(failure_kinds)
    dry_run_event = next(
        event for event in audit_events if event["detail"]["status_counts"] == {"preview": 1}
    )
    assert dry_run_event["status"] == "success"
    assert dry_run_event["detail"]["dry_run"] is True
    created_event = next(event for event in audit_events if event["detail"]["created_count"] == 1)
    assert created_event["detail"]["status_counts"] == {"created": 1}
    duplicate_event = next(event for event in audit_events if event["detail"]["skipped_count"] == 1)
    assert duplicate_event["detail"]["status_counts"] == {"skipped_duplicate": 1}
    serialized_audit = json.dumps(audit_events, sort_keys=True)
    assert "ghp_test_value" not in serialized_audit
    assert "Bearer" not in serialized_audit
    assert "body" not in serialized_audit


def test_workbench_github_issue_export_audits_partial_network_failure_and_retry(
    workbench_api_env: WorkbenchApiEnv,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = workbench_api_env.client
    headers = local_api_headers(client)
    project = create_project_via_api(client, headers)
    seeded = seed_finding_pair(
        workbench_api_env.engine,
        workbench_api_env.app_models,
        workbench_api_env.repositories,
        project_id=UUID(project["id"]),
        with_decision_evidence=True,
    )
    first_id, second_id = seeded["finding_ids"]

    class FakeGitHubResponse:
        status_code = 201

        def __init__(self, number: int) -> None:
            self.number = number

        def json(self) -> dict[str, Any]:
            return {
                "html_url": f"https://github.com/acme/workbench-triage/issues/{self.number}",
                "number": self.number,
            }

    post_attempts = 0

    def flaky_post(*args: Any, **kwargs: Any) -> FakeGitHubResponse:
        nonlocal post_attempts
        post_attempts += 1
        assert kwargs["headers"]["Authorization"] == "Bearer ghp_test_value"
        if post_attempts == 1:
            return FakeGitHubResponse(42)
        raise requests.Timeout("ghp_shouldnotleak from /Users/alice/private/sbom.json")

    monkeypatch.setenv("VPW_GITHUB_TOKEN", "ghp_test_value")
    monkeypatch.setattr("app.services.github_issues.requests.post", flaky_post)

    failed = client.post(
        f"/api/v1/projects/{project['id']}/github/issues/export",
        headers=headers,
        json={
            "repository": "acme/workbench-triage",
            "finding_ids": [str(first_id), str(second_id)],
            "dry_run": False,
            "token_env": "VPW_GITHUB_TOKEN",
        },
    )
    assert failed.status_code == 502
    assert post_attempts == 2
    with Session(workbench_api_env.engine) as session:
        exports = session.exec(select(app_models.GitHubIssueExport)).all()
    assert len(exports) == 1
    assert exports[0].finding_id == first_id
    assert exports[0].issue_url is not None
    assert exports[0].issue_url.endswith("/issues/42")

    failure_event = next(
        event
        for event in reversed(_audit_payloads(workbench_api_env, action="github_issue.export"))
        if event["status"] == "failure" and event["detail"].get("failure_kind") == "network_error"
    )
    assert failure_event["detail"]["created_count"] == 1
    assert failure_event["detail"]["failed_count"] == 1
    assert failure_event["detail"]["failed_finding_id"] == str(second_id)
    assert failure_event["detail"]["http_status_code"] == 502
    serialized_failure = json.dumps(failure_event, sort_keys=True)
    assert "ghp_test_value" not in serialized_failure
    assert "ghp_shouldnotleak" not in serialized_failure
    assert "/Users/alice/private/sbom.json" not in serialized_failure
    assert "body" not in serialized_failure

    def retry_post(*args: Any, **kwargs: Any) -> FakeGitHubResponse:
        nonlocal post_attempts
        post_attempts += 1
        return FakeGitHubResponse(43)

    monkeypatch.setattr("app.services.github_issues.requests.post", retry_post)
    retry = client.post(
        f"/api/v1/projects/{project['id']}/github/issues/export",
        headers=headers,
        json={
            "repository": "acme/workbench-triage",
            "finding_ids": [str(second_id)],
            "dry_run": False,
            "token_env": "VPW_GITHUB_TOKEN",
        },
    )
    assert retry.status_code == 200, retry.text
    assert retry.json()["created_count"] == 1
    assert post_attempts == 3
    with Session(workbench_api_env.engine) as session:
        exports = session.exec(select(app_models.GitHubIssueExport)).all()
    assert len(exports) == 2
    assert all(export.issue_url for export in exports)
    assert all(export.issue_number for export in exports)


def test_workbench_github_issue_export_audits_upstream_status_failure(
    workbench_api_env: WorkbenchApiEnv,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = workbench_api_env.client
    headers = local_api_headers(client)
    project = create_project_via_api(client, headers)
    seeded = seed_finding_pair(
        workbench_api_env.engine,
        workbench_api_env.app_models,
        workbench_api_env.repositories,
        project_id=UUID(project["id"]),
        with_decision_evidence=True,
    )
    selected_id = seeded["finding_ids"][0]

    class FakeGitHubResponse:
        status_code = 503

        def json(self) -> dict[str, Any]:
            return {"message": "ghp_shouldnotleak"}

    def fake_post(*args: Any, **kwargs: Any) -> FakeGitHubResponse:
        return FakeGitHubResponse()

    monkeypatch.setenv("VPW_GITHUB_TOKEN", "ghp_test_value")
    monkeypatch.setattr("app.services.github_issues.requests.post", fake_post)

    response = client.post(
        f"/api/v1/projects/{project['id']}/github/issues/export",
        headers=headers,
        json={
            "repository": "acme/workbench-triage",
            "finding_ids": [str(selected_id)],
            "dry_run": False,
            "token_env": "VPW_GITHUB_TOKEN",
        },
    )

    assert response.status_code == 502
    failure_event = next(
        event
        for event in reversed(_audit_payloads(workbench_api_env, action="github_issue.export"))
        if event["status"] == "failure" and event["detail"].get("failure_kind") == "upstream_status"
    )
    assert failure_event["detail"]["upstream_status_code"] == 503
    assert failure_event["detail"]["failed_finding_id"] == str(selected_id)
    serialized_failure = json.dumps(failure_event, sort_keys=True)
    assert "ghp_test_value" not in serialized_failure
    assert "ghp_shouldnotleak" not in serialized_failure
    with Session(workbench_api_env.engine) as session:
        exports = session.exec(select(app_models.GitHubIssueExport)).all()
    assert exports == []


def test_workbench_github_issue_export_retries_past_stale_empty_reservation(
    workbench_api_env: WorkbenchApiEnv,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = workbench_api_env.client
    headers = local_api_headers(client)
    project = create_project_via_api(client, headers)
    seeded = seed_finding_pair(
        workbench_api_env.engine,
        workbench_api_env.app_models,
        workbench_api_env.repositories,
        project_id=UUID(project["id"]),
        with_decision_evidence=True,
    )
    selected_id = seeded["finding_ids"][0]
    preview = client.post(
        f"/api/v1/projects/{project['id']}/github/issues/preview",
        headers=headers,
        json={"finding_ids": [str(selected_id)]},
    )
    assert preview.status_code == 200, preview.text
    preview_item = preview.json()["data"][0]
    with Session(workbench_api_env.engine) as session:
        session.add(
            app_models.GitHubIssueExport(
                project_id=UUID(project["id"]),
                finding_id=selected_id,
                repository="acme/workbench-triage",
                duplicate_key=preview_item["duplicate_key"],
                title=preview_item["title"],
                issue_url=None,
                issue_number=None,
            )
        )
        session.commit()

    class FakeGitHubResponse:
        status_code = 201

        def json(self) -> dict[str, Any]:
            return {"html_url": "https://github.com/acme/workbench-triage/issues/77", "number": 77}

    def fake_post(*args: Any, **kwargs: Any) -> FakeGitHubResponse:
        return FakeGitHubResponse()

    monkeypatch.setenv("VPW_GITHUB_TOKEN", "ghp_test_value")
    monkeypatch.setattr("app.services.github_issues.requests.post", fake_post)

    response = client.post(
        f"/api/v1/projects/{project['id']}/github/issues/export",
        headers=headers,
        json={
            "repository": "acme/workbench-triage",
            "finding_ids": [str(selected_id)],
            "dry_run": False,
            "token_env": "VPW_GITHUB_TOKEN",
        },
    )

    assert response.status_code == 200, response.text
    assert response.json()["created_count"] == 1
    with Session(workbench_api_env.engine) as session:
        exports = session.exec(select(app_models.GitHubIssueExport)).all()
    assert len(exports) == 1
    assert exports[0].issue_url == "https://github.com/acme/workbench-triage/issues/77"
    created_event = next(
        event
        for event in reversed(_audit_payloads(workbench_api_env, action="github_issue.export"))
        if event["status"] == "success" and event["detail"]["created_count"] == 1
    )
    assert created_event["detail"]["stale_reservation_count"] == 1


def test_workbench_github_issue_preview_and_export_use_local_single_user_access(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    client = workbench_api_env.client
    headers = local_api_headers(client)
    project = create_project_via_api(client, headers)
    seed_finding_pair(
        workbench_api_env.engine,
        workbench_api_env.app_models,
        workbench_api_env.repositories,
        project_id=UUID(project["id"]),
        with_decision_evidence=True,
    )

    allowed = client.post(
        f"/api/v1/projects/{project['id']}/github/issues/preview",
        headers={"Authorization": f"Bearer vpr_{'A' * 40}"},
        json={"limit": 1},
    )
    export = client.post(
        f"/api/v1/projects/{project['id']}/github/issues/export",
        headers={"Authorization": "Bearer not-a-token"},
        json={
            "repository": "acme/workbench-triage",
            "dry_run": True,
            "limit": 1,
        },
    )

    assert allowed.status_code == 200, allowed.text
    assert allowed.json()["count"] == 1
    assert export.status_code == 200, export.text
    assert export.json()["count"] == 1


def test_workbench_github_issue_preview_audits_missing_selected_finding(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    client = workbench_api_env.client
    headers = local_api_headers(client)
    project = create_project_via_api(client, headers)

    response = client.post(
        f"/api/v1/projects/{project['id']}/github/issues/preview",
        headers=headers,
        json={"finding_ids": ["11111111-1111-1111-1111-111111111111"]},
    )

    assert response.status_code == 404
    failure_event = _audit_payloads(workbench_api_env, action="github_issue.preview")[-1]
    assert failure_event["status"] == "failure"
    assert failure_event["detail"]["failure_kind"] == "http_404"
    assert failure_event["detail"]["http_status_code"] == 404
    assert failure_event["detail"]["count"] == 0


def test_workbench_github_issue_export_audits_selection_failure(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    client = workbench_api_env.client
    headers = local_api_headers(client)
    project = create_project_via_api(client, headers)

    response = client.post(
        f"/api/v1/projects/{project['id']}/github/issues/export",
        headers=headers,
        json={
            "repository": "acme/workbench-triage",
            "finding_ids": ["22222222-2222-2222-2222-222222222222"],
            "dry_run": True,
        },
    )

    assert response.status_code == 404
    failure_event = _audit_payloads(workbench_api_env, action="github_issue.export")[-1]
    assert failure_event["status"] == "failure"
    assert failure_event["detail"]["failure_kind"] == "http_404"
    assert failure_event["detail"]["http_status_code"] == 404
    assert failure_event["detail"]["created_count"] == 0
    assert failure_event["detail"]["skipped_count"] == 0


def test_workbench_github_issue_export_audits_generic_token_http_failure(
    workbench_api_env: WorkbenchApiEnv,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = workbench_api_env.client
    headers = local_api_headers(client)
    project = create_project_via_api(client, headers)
    seeded = seed_finding_pair(
        workbench_api_env.engine,
        workbench_api_env.app_models,
        workbench_api_env.repositories,
        project_id=UUID(project["id"]),
        with_decision_evidence=True,
    )

    def fake_github_export_token(token_env: str | None) -> str:
        assert token_env == "VPW_GITHUB_TOKEN"
        raise HTTPException(status_code=409, detail="operator token policy denied")

    monkeypatch.setattr(
        "app.api.routes.github_issues.github_export_token",
        fake_github_export_token,
    )

    response = client.post(
        f"/api/v1/projects/{project['id']}/github/issues/export",
        headers=headers,
        json={
            "repository": "acme/workbench-triage",
            "finding_ids": [str(seeded["finding_ids"][0])],
            "dry_run": False,
            "token_env": "VPW_GITHUB_TOKEN",
        },
    )

    assert response.status_code == 409
    failure_event = _audit_payloads(workbench_api_env, action="github_issue.export")[-1]
    assert failure_event["status"] == "failure"
    assert failure_event["detail"]["failure_kind"] == "http_409"
    assert failure_event["detail"]["http_status_code"] == 409


def test_workbench_github_issue_export_skips_integrity_race_duplicate(
    workbench_api_env: WorkbenchApiEnv,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = workbench_api_env.client
    headers = local_api_headers(client)
    project = create_project_via_api(client, headers)
    seeded = seed_finding_pair(
        workbench_api_env.engine,
        workbench_api_env.app_models,
        workbench_api_env.repositories,
        project_id=UUID(project["id"]),
        with_decision_evidence=True,
    )

    class RacingExportRepository:
        def __init__(self, session: Session) -> None:
            self.session = session

        def export_exists(
            self,
            *,
            project_id: UUID,
            repository: str,
            duplicate_key: str,
        ) -> bool:
            return False

        def delete_incomplete_export(
            self,
            *,
            project_id: UUID,
            repository: str,
            duplicate_key: str,
        ) -> int:
            return 0

        def create_export(self, **kwargs: Any) -> app_models.GitHubIssueExport:
            raise IntegrityError("insert", {}, RuntimeError("duplicate"))

    def forbidden_create_github_issue(*args: Any, **kwargs: Any) -> dict[str, Any]:
        raise AssertionError("Integrity duplicates must not call GitHub")

    monkeypatch.setenv("VPW_GITHUB_TOKEN", "ghp_test_value")
    monkeypatch.setattr(
        "app.api.routes.github_issues.GitHubIssueExportRepository",
        RacingExportRepository,
    )
    monkeypatch.setattr(
        "app.api.routes.github_issues.create_github_issue",
        forbidden_create_github_issue,
    )

    response = client.post(
        f"/api/v1/projects/{project['id']}/github/issues/export",
        headers=headers,
        json={
            "repository": "acme/workbench-triage",
            "finding_ids": [str(seeded["finding_ids"][0])],
            "dry_run": False,
            "token_env": "VPW_GITHUB_TOKEN",
        },
    )

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["created_count"] == 0
    assert payload["skipped_count"] == 1
    assert payload["data"][0]["status"] == "skipped_duplicate"
    success_event = _audit_payloads(workbench_api_env, action="github_issue.export")[-1]
    assert success_event["status"] == "success"
    assert success_event["detail"]["status_counts"] == {"skipped_duplicate": 1}


def test_workbench_github_issue_export_audits_generic_create_http_failure(
    workbench_api_env: WorkbenchApiEnv,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = workbench_api_env.client
    headers = local_api_headers(client)
    project = create_project_via_api(client, headers)
    seeded = seed_finding_pair(
        workbench_api_env.engine,
        workbench_api_env.app_models,
        workbench_api_env.repositories,
        project_id=UUID(project["id"]),
        with_decision_evidence=True,
    )

    def fake_create_github_issue(*args: Any, **kwargs: Any) -> dict[str, Any]:
        raise HTTPException(status_code=418, detail="generic HTTP failure")

    monkeypatch.setenv("VPW_GITHUB_TOKEN", "ghp_test_value")
    monkeypatch.setattr(
        "app.api.routes.github_issues.create_github_issue",
        fake_create_github_issue,
    )

    response = client.post(
        f"/api/v1/projects/{project['id']}/github/issues/export",
        headers=headers,
        json={
            "repository": "acme/workbench-triage",
            "finding_ids": [str(seeded["finding_ids"][0])],
            "dry_run": False,
            "token_env": "VPW_GITHUB_TOKEN",
        },
    )

    assert response.status_code == 418
    failure_event = _audit_payloads(workbench_api_env, action="github_issue.export")[-1]
    assert failure_event["status"] == "failure"
    assert failure_event["detail"]["failure_kind"] == "http_418"
    assert failure_event["detail"]["http_status_code"] == 418
    assert failure_event["detail"]["failed_finding_id"] == str(seeded["finding_ids"][0])


def _audit_payloads(
    workbench_api_env: WorkbenchApiEnv,
    *,
    action: str,
) -> list[dict[str, Any]]:
    with Session(workbench_api_env.engine) as session:
        events = session.exec(
            select(app_models.AuditEvent)
            .where(app_models.AuditEvent.action == action)
            .order_by(app_models.AuditEvent.created_at)
        ).all()
    return [{"status": event.status, "detail": dict(event.detail_json or {})} for event in events]

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
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
from app.repositories.github_issues import GitHubIssueExportRepository
from app.services.demo_workspace import (
    DEMO_PROJECT_ID,
    DEMO_PROJECT_NAME,
    DEMO_WORKSPACE_MARKER,
)


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
        projection_repository = workbench_api_env.repositories.FindingCurrentProjectionRepository(
            session
        )
        evidence = projection_repository.get_evidence(selected_id)
        assert evidence is not None
        projection_repository.update_current_payload(
            selected_id,
            evidence.model_copy(
                update={
                    "rationale": (
                        "EPSS and KEV make this urgent. token=ghp_secretshouldnotleak "
                        "and source /Users/alice/private/sbom.json"
                    ),
                    "recommended_action": (
                        "Upgrade log4j-core and rotate api_key=super-secret-value."
                    ),
                    "risk_score": 98.6,
                    "epss": 0.9442,
                }
            ).to_jsonable(),
        )
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
            "repository": "Acme/Workbench-Triage",
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
    with Session(workbench_api_env.engine) as session:
        persisted_export = session.exec(select(app_models.GitHubIssueExport)).one()
        assert persisted_export.repository == "acme/workbench-triage"

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


def test_project_delete_blocks_inflight_export_then_cascades_completed_history(
    file_backed_workbench_api_env: WorkbenchApiEnv,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    client = file_backed_workbench_api_env.client
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
    project_id = UUID(project["id"])
    selected_id = seed_finding_pair(
        file_backed_workbench_api_env.engine,
        file_backed_workbench_api_env.app_models,
        file_backed_workbench_api_env.repositories,
        project_id=project_id,
        with_decision_evidence=True,
    )["finding_ids"][0]
    upload_artifact = upload_root / str(project_id) / "run" / "input.txt"
    report_artifact = report_root / str(project_id) / "run" / "report.md"
    upload_artifact.parent.mkdir(parents=True)
    report_artifact.parent.mkdir(parents=True)
    upload_artifact.write_text("CVE-2021-44228\n", encoding="utf-8")
    report_artifact.write_text("evidence", encoding="utf-8")

    delete_during_post_statuses: list[int] = []

    class FakeGitHubResponse:
        status_code = 201

        def json(self) -> dict[str, Any]:
            return {
                "html_url": "https://github.com/acme/workbench-triage/issues/91",
                "number": 91,
            }

    def fake_post(*args: Any, **kwargs: Any) -> FakeGitHubResponse:
        del args, kwargs
        concurrent_delete = client.delete(
            f"/api/v1/projects/{project_id}",
            headers=headers,
        )
        delete_during_post_statuses.append(concurrent_delete.status_code)
        assert concurrent_delete.status_code == 409, concurrent_delete.text
        assert upload_artifact.exists()
        assert report_artifact.exists()
        return FakeGitHubResponse()

    monkeypatch.setenv("VPW_GITHUB_TOKEN", "ghp_test_value")
    monkeypatch.setattr("app.services.github_issues.requests.post", fake_post)
    exported = client.post(
        f"/api/v1/projects/{project_id}/github/issues/export",
        headers=headers,
        json={
            "repository": "acme/workbench-triage",
            "finding_ids": [str(selected_id)],
            "dry_run": False,
            "token_env": "VPW_GITHUB_TOKEN",
        },
    )
    assert exported.status_code == 200, exported.text
    assert exported.json()["created_count"] == 1
    assert delete_during_post_statuses == [409]

    completed_delete = client.delete(
        f"/api/v1/projects/{project_id}",
        headers=headers,
    )
    assert completed_delete.status_code == 204, completed_delete.text
    assert not upload_artifact.exists()
    assert not report_artifact.exists()
    with Session(file_backed_workbench_api_env.engine) as session:
        assert session.get(app_models.Project, project_id) is None
        assert (
            session.exec(
                select(app_models.GitHubIssueExport).where(
                    app_models.GitHubIssueExport.project_id == project_id
                )
            ).all()
            == []
        )
        delete_events = session.exec(
            select(app_models.AuditEvent).where(
                app_models.AuditEvent.action == "project.delete",
                app_models.AuditEvent.resource_id == str(project_id),
            )
        ).all()
        assert [event.status for event in delete_events] == ["failure", "success"]
        assert delete_events[0].detail_json["artifact_cleanup_status"] == "not_started"
        assert delete_events[1].detail_json["artifact_cleanup_status"] == "completed"


@pytest.mark.parametrize(
    ("demo_method", "demo_payload"),
    [
        pytest.param("DELETE", None, id="delete"),
        pytest.param("POST", {"reset": True}, id="reset"),
    ],
)
def test_demo_mutation_blocks_inflight_export_before_remote_result_is_persisted(
    file_backed_workbench_api_env: WorkbenchApiEnv,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    demo_method: str,
    demo_payload: dict[str, bool] | None,
) -> None:
    client = file_backed_workbench_api_env.client
    upload_root = tmp_path / "uploads"
    report_root = tmp_path / "reports"
    client.app.state.workbench_settings = replace(
        client.app.state.workbench_settings,
        DEMO_WORKSPACE_ENABLED=True,
        ENVIRONMENT="local",
        IMPORT_UPLOAD_DIR=str(upload_root),
        REPORT_DIR=str(report_root),
    )
    headers = local_api_headers(client)
    with Session(file_backed_workbench_api_env.engine) as session:
        session.add(
            app_models.Project(
                id=DEMO_PROJECT_ID,
                name=DEMO_PROJECT_NAME,
                description=f"Managed marker: {DEMO_WORKSPACE_MARKER}.",
            )
        )
        session.commit()
    selected_id = seed_finding_pair(
        file_backed_workbench_api_env.engine,
        file_backed_workbench_api_env.app_models,
        file_backed_workbench_api_env.repositories,
        project_id=DEMO_PROJECT_ID,
        with_decision_evidence=True,
    )["finding_ids"][0]
    upload_artifact = upload_root / str(DEMO_PROJECT_ID) / "run" / "input.txt"
    report_artifact = report_root / str(DEMO_PROJECT_ID) / "run" / "report.md"
    upload_artifact.parent.mkdir(parents=True)
    report_artifact.parent.mkdir(parents=True)
    upload_artifact.write_text("CVE-2021-44228\n", encoding="utf-8")
    report_artifact.write_text("evidence", encoding="utf-8")

    nested_statuses: list[int] = []

    class FakeGitHubResponse:
        status_code = 201

        def json(self) -> dict[str, Any]:
            return {
                "html_url": "https://github.com/acme/workbench-triage/issues/92",
                "number": 92,
            }

    def fake_post(*args: Any, **kwargs: Any) -> FakeGitHubResponse:
        del args, kwargs
        nested = client.request(
            demo_method,
            "/api/v1/workbench/demo",
            headers=headers,
            json=demo_payload,
        )
        nested_statuses.append(nested.status_code)
        assert nested.status_code == 409, nested.text
        assert upload_artifact.exists()
        assert report_artifact.exists()
        return FakeGitHubResponse()

    monkeypatch.setenv("VPW_GITHUB_TOKEN", "ghp_test_value")
    monkeypatch.setattr("app.services.github_issues.requests.post", fake_post)
    exported = client.post(
        f"/api/v1/projects/{DEMO_PROJECT_ID}/github/issues/export",
        headers=headers,
        json={
            "repository": "acme/workbench-triage",
            "finding_ids": [str(selected_id)],
            "dry_run": False,
            "token_env": "VPW_GITHUB_TOKEN",
        },
    )

    assert exported.status_code == 200, exported.text
    assert exported.json()["created_count"] == 1
    assert nested_statuses == [409]
    with Session(file_backed_workbench_api_env.engine) as session:
        project = session.get(app_models.Project, DEMO_PROJECT_ID)
        export = session.exec(
            select(app_models.GitHubIssueExport).where(
                app_models.GitHubIssueExport.project_id == DEMO_PROJECT_ID
            )
        ).one()
        assert project is not None
        assert export.issue_number == 92
        assert export.issue_url == "https://github.com/acme/workbench-triage/issues/92"

    completed_delete = client.delete("/api/v1/workbench/demo", headers=headers)
    assert completed_delete.status_code == 204, completed_delete.text
    assert not upload_artifact.exists()
    assert not report_artifact.exists()


def test_workbench_github_issue_export_retains_ambiguous_network_reservation_and_blocks_retry(
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
    assert len(exports) == 2
    exports_by_finding = {export.finding_id: export for export in exports}
    assert exports_by_finding[first_id].issue_url is not None
    assert exports_by_finding[first_id].issue_url.endswith("/issues/42")
    assert exports_by_finding[second_id].issue_url is None
    assert exports_by_finding[second_id].issue_number is None

    failure_event = next(
        event
        for event in reversed(_audit_payloads(workbench_api_env, action="github_issue.export"))
        if event["status"] == "failure" and event["detail"].get("failure_kind") == "network_error"
    )
    assert failure_event["detail"]["created_count"] == 1
    assert failure_event["detail"]["failed_count"] == 1
    assert failure_event["detail"]["failed_finding_id"] == str(second_id)
    assert failure_event["detail"]["http_status_code"] == 502
    assert failure_event["detail"]["reservation_outcome"] == "retained_unresolved"
    serialized_failure = json.dumps(failure_event, sort_keys=True)
    assert "ghp_test_value" not in serialized_failure
    assert "ghp_shouldnotleak" not in serialized_failure
    assert "/Users/alice/private/sbom.json" not in serialized_failure
    assert "body" not in serialized_failure

    def forbidden_retry_post(*args: Any, **kwargs: Any) -> FakeGitHubResponse:
        raise AssertionError("An unresolved reservation must block another GitHub POST")

    monkeypatch.setattr("app.services.github_issues.requests.post", forbidden_retry_post)
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
    assert retry.status_code == 409, retry.text
    assert "outcome is unresolved" in retry.json()["detail"]
    assert post_attempts == 2
    with Session(workbench_api_env.engine) as session:
        exports = session.exec(select(app_models.GitHubIssueExport)).all()
    assert len(exports) == 2
    unresolved_event = _audit_payloads(workbench_api_env, action="github_issue.export")[-1]
    assert unresolved_event["status"] == "failure"
    assert unresolved_event["detail"]["failure_kind"] == "reservation_unresolved"
    assert unresolved_event["detail"]["reservation_outcome"] == "blocked_unresolved"


def test_workbench_github_issue_export_commits_reservation_before_result_persistence(
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
        status_code = 201

        def json(self) -> dict[str, Any]:
            return {
                "html_url": "https://github.com/acme/workbench-triage/issues/81",
                "number": 81,
            }

    monkeypatch.setenv("VPW_GITHUB_TOKEN", "ghp_test_value")
    monkeypatch.setattr(
        "app.services.github_issues.requests.post",
        lambda *args, **kwargs: FakeGitHubResponse(),
    )
    with monkeypatch.context() as crash:
        crash.setattr(
            "app.api.routes.github_issues.GitHubIssueExportRepository.update_export_result",
            lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("simulated crash")),
        )
        with pytest.raises(RuntimeError, match="simulated crash"):
            client.post(
                f"/api/v1/projects/{project['id']}/github/issues/export",
                headers=headers,
                json={
                    "repository": "acme/workbench-triage",
                    "finding_ids": [str(selected_id)],
                    "dry_run": False,
                    "token_env": "VPW_GITHUB_TOKEN",
                },
            )

    with Session(workbench_api_env.engine) as session:
        reservation = session.exec(select(app_models.GitHubIssueExport)).one()
    assert reservation.finding_id == selected_id
    assert reservation.issue_url is None
    assert reservation.issue_number is None

    monkeypatch.setattr(
        "app.services.github_issues.requests.post",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("A crash-surviving reservation must prevent another POST")
        ),
    )
    retry = client.post(
        f"/api/v1/projects/{project['id']}/github/issues/export",
        headers=headers,
        json={
            "repository": "acme/workbench-triage",
            "finding_ids": [str(selected_id)],
            "dry_run": False,
            "token_env": "VPW_GITHUB_TOKEN",
        },
    )
    assert retry.status_code == 409, retry.text


def test_workbench_github_issue_export_matches_completed_finding_after_key_drift(
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
    current_key = preview_item["duplicate_key"]
    legacy_component_key = f"{current_key.rsplit(':', maxsplit=1)[0]}:{UUID(int=999)}"
    assert legacy_component_key != current_key

    with Session(workbench_api_env.engine) as session:
        session.add(
            app_models.GitHubIssueExport(
                project_id=UUID(project["id"]),
                finding_id=selected_id,
                repository="acme/workbench-triage",
                duplicate_key=legacy_component_key,
                title=preview_item["title"],
                issue_url="https://github.com/acme/workbench-triage/issues/91",
                issue_number=91,
            )
        )
        session.commit()

    def forbidden_create_github_issue(*args: Any, **kwargs: Any) -> dict[str, Any]:
        raise AssertionError("A completed issue for the same finding must remain idempotent")

    monkeypatch.setenv("VPW_GITHUB_TOKEN", "ghp_test_value")
    monkeypatch.setattr(
        "app.api.routes.github_issues.create_github_issue",
        forbidden_create_github_issue,
    )

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
    assert response.json()["created_count"] == 0
    assert response.json()["skipped_count"] == 1
    assert response.json()["data"][0]["status"] == "skipped_duplicate"
    with Session(workbench_api_env.engine) as session:
        exports = session.exec(select(app_models.GitHubIssueExport)).all()
    assert len(exports) == 1
    assert exports[0].duplicate_key == legacy_component_key
    assert exports[0].issue_number == 91


def test_github_export_reservation_is_unique_by_stable_finding_across_key_drift(
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
    finding_id = seeded["finding_ids"][0]

    with Session(workbench_api_env.engine) as session:
        repository = GitHubIssueExportRepository(session)
        repository.create_export(
            project_id=UUID(project["id"]),
            repository="acme/workbench-triage",
            duplicate_key="before-identity-rebind",
            title="Original reservation",
            finding_id=finding_id,
            issue_url=None,
            issue_number=None,
        )

        with pytest.raises(IntegrityError):
            repository.create_export(
                project_id=UUID(project["id"]),
                repository="acme/workbench-triage",
                duplicate_key="after-identity-rebind",
                title="Drifted reservation",
                finding_id=finding_id,
                issue_url=None,
                issue_number=None,
            )


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

    post_attempts = 0

    def fake_post(*args: Any, **kwargs: Any) -> FakeGitHubResponse:
        nonlocal post_attempts
        post_attempts += 1
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
    assert len(exports) == 1
    assert exports[0].issue_url is None
    assert exports[0].issue_number is None
    assert failure_event["detail"]["reservation_outcome"] == "retained_unresolved"

    monkeypatch.setattr(
        "app.services.github_issues.requests.post",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("An ambiguous 5xx outcome must block another GitHub POST")
        ),
    )
    retry = client.post(
        f"/api/v1/projects/{project['id']}/github/issues/export",
        headers=headers,
        json={
            "repository": "acme/workbench-triage",
            "finding_ids": [str(selected_id)],
            "dry_run": False,
            "token_env": "VPW_GITHUB_TOKEN",
        },
    )
    assert retry.status_code == 409, retry.text
    assert post_attempts == 1


@pytest.mark.parametrize("upstream_status", [401, 422])
def test_workbench_github_issue_export_releases_definitive_client_failure_reservation(
    workbench_api_env: WorkbenchApiEnv,
    monkeypatch: pytest.MonkeyPatch,
    upstream_status: int,
) -> None:
    client = workbench_api_env.client
    headers = local_api_headers(client)
    project = create_project_via_api(client, headers)
    selected_id = seed_finding_pair(
        workbench_api_env.engine,
        workbench_api_env.app_models,
        workbench_api_env.repositories,
        project_id=UUID(project["id"]),
        with_decision_evidence=True,
    )["finding_ids"][0]

    class ClientFailureResponse:
        status_code = upstream_status

    class SuccessfulRetryResponse:
        status_code = 201

        def json(self) -> dict[str, Any]:
            return {
                "html_url": "https://github.com/acme/workbench-triage/issues/82",
                "number": 82,
            }

    responses = iter([ClientFailureResponse(), SuccessfulRetryResponse()])
    monkeypatch.setenv("VPW_GITHUB_TOKEN", "ghp_test_value")
    monkeypatch.setattr(
        "app.services.github_issues.requests.post",
        lambda *args, **kwargs: next(responses),
    )
    request = {
        "repository": "acme/workbench-triage",
        "finding_ids": [str(selected_id)],
        "dry_run": False,
        "token_env": "VPW_GITHUB_TOKEN",
    }

    failed = client.post(
        f"/api/v1/projects/{project['id']}/github/issues/export",
        headers=headers,
        json=request,
    )
    assert failed.status_code == 502, failed.text
    with Session(workbench_api_env.engine) as session:
        assert session.exec(select(app_models.GitHubIssueExport)).all() == []

    retry = client.post(
        f"/api/v1/projects/{project['id']}/github/issues/export",
        headers=headers,
        json=request,
    )
    assert retry.status_code == 200, retry.text
    assert retry.json()["created_count"] == 1


@pytest.mark.parametrize("response_mode", ["empty-object", "invalid-json"])
def test_workbench_github_issue_export_retains_invalid_201_response_as_unresolved(
    workbench_api_env: WorkbenchApiEnv,
    monkeypatch: pytest.MonkeyPatch,
    response_mode: str,
) -> None:
    client = workbench_api_env.client
    headers = local_api_headers(client)
    project = create_project_via_api(client, headers)
    selected_id = seed_finding_pair(
        workbench_api_env.engine,
        workbench_api_env.app_models,
        workbench_api_env.repositories,
        project_id=UUID(project["id"]),
        with_decision_evidence=True,
    )["finding_ids"][0]
    post_attempts = 0

    class InvalidCreatedResponse:
        status_code = 201

        def json(self) -> dict[str, Any]:
            if response_mode == "invalid-json":
                raise ValueError("malformed upstream JSON")
            return {}

    def invalid_post(*args: Any, **kwargs: Any) -> InvalidCreatedResponse:
        nonlocal post_attempts
        _ = args, kwargs
        post_attempts += 1
        return InvalidCreatedResponse()

    monkeypatch.setenv("VPW_GITHUB_TOKEN", "ghp_test_value")
    monkeypatch.setattr("app.services.github_issues.requests.post", invalid_post)
    failed = client.post(
        f"/api/v1/projects/{project['id']}/github/issues/export",
        headers=headers,
        json={
            "repository": "acme/workbench-triage",
            "finding_ids": [str(selected_id)],
            "dry_run": False,
            "token_env": "VPW_GITHUB_TOKEN",
        },
    )

    assert failed.status_code == 502, failed.text
    assert post_attempts == 1
    with Session(workbench_api_env.engine) as session:
        reservation = session.exec(select(app_models.GitHubIssueExport)).one()
        assert reservation.issue_url is None
        assert reservation.issue_number is None
    failure_event = _audit_payloads(workbench_api_env, action="github_issue.export")[-1]
    assert failure_event["status"] == "failure"
    assert failure_event["detail"]["failure_kind"] == "invalid_response"
    assert failure_event["detail"]["reservation_outcome"] == "retained_unresolved"

    monkeypatch.setattr(
        "app.services.github_issues.requests.post",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("An invalid-response reservation must prevent another POST")
        ),
    )
    retry = client.post(
        f"/api/v1/projects/{project['id']}/github/issues/export",
        headers=headers,
        json={
            "repository": "ACME/WORKBENCH-TRIAGE",
            "finding_ids": [str(selected_id)],
            "dry_run": False,
            "token_env": "VPW_GITHUB_TOKEN",
        },
    )
    assert retry.status_code == 409, retry.text
    assert post_attempts == 1


def test_workbench_github_issue_export_blocks_unresolved_empty_reservation(
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
    current_key = preview_item["duplicate_key"]
    stale_component_key = f"{current_key.rsplit(':', maxsplit=1)[0]}:{UUID(int=998)}"
    assert stale_component_key != current_key
    with Session(workbench_api_env.engine) as session:
        session.add(
            app_models.GitHubIssueExport(
                project_id=UUID(project["id"]),
                finding_id=selected_id,
                repository="acme/workbench-triage",
                duplicate_key=stale_component_key,
                title=preview_item["title"],
                issue_url="",
                issue_number=0,
            )
        )
        session.commit()

    def forbidden_post(*args: Any, **kwargs: Any) -> dict[str, Any]:
        raise AssertionError("An unresolved reservation must block another GitHub POST")

    monkeypatch.setenv("VPW_GITHUB_TOKEN", "ghp_test_value")
    monkeypatch.setattr("app.services.github_issues.requests.post", forbidden_post)

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

    assert response.status_code == 409, response.text
    with Session(workbench_api_env.engine) as session:
        exports = session.exec(select(app_models.GitHubIssueExport)).all()
    assert len(exports) == 1
    assert exports[0].issue_url == ""
    assert exports[0].issue_number == 0
    assert exports[0].duplicate_key == stale_component_key
    blocked_event = _audit_payloads(workbench_api_env, action="github_issue.export")[-1]
    assert blocked_event["status"] == "failure"
    assert blocked_event["detail"]["failure_kind"] == "reservation_unresolved"


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


@pytest.mark.parametrize(
    ("winner_state", "expected_status"),
    [("completed", 200), ("incomplete", 409), ("missing", 409)],
)
def test_workbench_github_issue_export_resolves_integrity_race_from_winner_state(
    workbench_api_env: WorkbenchApiEnv,
    monkeypatch: pytest.MonkeyPatch,
    winner_state: str,
    expected_status: int,
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
            self.conflicted = False

        def export_exists(
            self,
            *,
            project_id: UUID,
            repository: str,
            duplicate_key: str,
            finding_id: UUID | None = None,
        ) -> bool:
            return self.conflicted and winner_state == "completed"

        def incomplete_export_exists(
            self,
            *,
            project_id: UUID,
            repository: str,
            duplicate_key: str,
            finding_id: UUID | None = None,
        ) -> bool:
            return self.conflicted and winner_state == "incomplete"

        def create_export(self, **kwargs: Any) -> app_models.GitHubIssueExport:
            self.conflicted = True
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

    assert response.status_code == expected_status, response.text
    event = _audit_payloads(workbench_api_env, action="github_issue.export")[-1]
    if winner_state == "completed":
        payload = response.json()
        assert payload["created_count"] == 0
        assert payload["skipped_count"] == 1
        assert payload["data"][0]["status"] == "skipped_duplicate"
        assert event["status"] == "success"
        assert event["detail"]["status_counts"] == {"skipped_duplicate": 1}
    else:
        assert event["status"] == "failure"
        assert event["detail"]["failure_kind"] == (
            "reservation_unresolved" if winner_state == "incomplete" else "reservation_conflict"
        )


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

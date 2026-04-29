from __future__ import annotations

import hashlib
import uuid
from dataclasses import replace
from pathlib import Path

import pytest
from sqlmodel import Session, select
from utils.template_workbench import (
    TemplateApiEnv,
    auth_headers,
    create_project_via_api,
)

from app import models as app_models


def test_valid_cve_list_upload_creates_analysis_run_and_stores_sha256(
    template_api_env: TemplateApiEnv,
    tmp_path: Path,
) -> None:
    upload_dir = _configure_upload_dir(template_api_env, tmp_path)
    headers = auth_headers(template_api_env.client)
    project = create_project_via_api(template_api_env.client, headers)
    content = b"CVE-2024-3094\nCVE-2021-44228\n"
    expected_sha256 = hashlib.sha256(content).hexdigest()

    response = template_api_env.client.post(
        f"/api/v1/projects/{project['id']}/imports",
        headers=headers,
        data={"input_type": "cve-list"},
        files={"file": ("Team Scan (prod).txt", content, "text/plain")},
    )

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["project_id"] == project["id"]
    assert payload["input_type"] == "cve-list"
    assert payload["filename"] == "Team_Scan__prod_.txt"
    assert payload["status"] == "succeeded"
    assert payload["summary_json"]["input_sha256"] == expected_sha256
    assert payload["summary_json"]["occurrence_count"] == 2
    assert payload["summary_json"]["finding_count"] == 2
    assert payload["summary_json"]["dedup_summary"]["created_findings"] == 2
    assert payload["summary_json"]["dedup_summary"]["reused_findings"] == 0
    assert payload["summary_json"]["input_upload"]["sha256"] == expected_sha256
    assert payload["summary_json"]["input_upload"]["original_filename"] == "Team Scan (prod).txt"
    assert payload["summary_json"]["input_upload"]["stored_filename"] == "Team_Scan__prod_.txt"
    assert payload["summary_json"]["input_upload"]["path"].startswith(str(upload_dir))
    assert Path(payload["summary_json"]["input_upload"]["path"]).read_bytes() == content
    assert payload["summary_json"]["import_job"]["status"] == "succeeded"
    assert [item["status"] for item in payload["summary_json"]["import_job"]["status_history"]] == [
        "pending",
        "running",
        "succeeded",
    ]
    assert payload["summary_json"]["parse_errors"] == []

    runs = template_api_env.client.get(
        f"/api/v1/projects/{project['id']}/runs/",
        headers=headers,
    )
    assert runs.status_code == 200
    assert runs.json()["count"] == 1
    assert runs.json()["data"][0]["id"] == payload["id"]
    assert runs.json()["data"][0]["status"] == "succeeded"

    findings = template_api_env.client.get(
        f"/api/v1/projects/{project['id']}/findings/",
        headers=headers,
    )
    assert findings.status_code == 200
    assert findings.json()["count"] == 2


def test_double_import_deduplicates_findings_and_appends_occurrences(
    template_api_env: TemplateApiEnv,
    tmp_path: Path,
) -> None:
    _configure_upload_dir(template_api_env, tmp_path)
    headers = auth_headers(template_api_env.client)
    project = create_project_via_api(template_api_env.client, headers)
    project_id = uuid.UUID(project["id"])
    content = "\n".join(
        [
            "cve_id,asset_ref,component,version,purl,severity",
            "CVE-2024-3094,build-host-1,xz,5.6.0,pkg:apk/alpine/xz@5.6.0-r0,CRITICAL",
            "CVE-2024-4577,web-tier,php-cgi,8.3.7,pkg:deb/debian/php-cgi@8.3.7,HIGH",
            "",
        ]
    ).encode()

    first = template_api_env.client.post(
        f"/api/v1/projects/{project['id']}/imports",
        headers=headers,
        data={"input_type": "generic-occurrence-csv"},
        files={"file": ("occurrences.csv", content, "text/csv")},
    )
    assert first.status_code == 200, first.text
    first_payload = first.json()
    assert first_payload["summary_json"]["dedup_summary"]["created_findings"] == 2
    assert first_payload["summary_json"]["dedup_summary"]["reused_findings"] == 0
    assert {
        item["action"] for item in first_payload["summary_json"]["dedup_summary"]["decisions"]
    } == {"created"}

    first_findings, first_occurrence_count = _finding_state(template_api_env, project_id)
    first_seen = {finding.cve_id: finding.first_seen_at for finding in first_findings}
    first_last_seen = {finding.cve_id: finding.last_seen_at for finding in first_findings}
    first_dedup_keys = {finding.cve_id: finding.dedup_key for finding in first_findings}

    second = template_api_env.client.post(
        f"/api/v1/projects/{project['id']}/imports",
        headers=headers,
        data={"input_type": "generic-occurrence-csv"},
        files={"file": ("occurrences.csv", content, "text/csv")},
    )
    assert second.status_code == 200, second.text
    second_payload = second.json()
    dedup_summary = second_payload["summary_json"]["dedup_summary"]
    assert second_payload["summary_json"]["occurrence_count"] == 2
    assert second_payload["summary_json"]["finding_count"] == 2
    assert dedup_summary["created_findings"] == 0
    assert dedup_summary["reused_findings"] == 2
    assert dedup_summary["decision_count"] == 2
    assert {item["action"] for item in dedup_summary["decisions"]} == {"reused"}
    assert all(item["dedup_key"].startswith("vpw019:") for item in dedup_summary["decisions"])
    assert all(
        item["asset_ref"] in {"build-host-1", "web-tier"} for item in dedup_summary["decisions"]
    )

    second_findings, second_occurrence_count = _finding_state(template_api_env, project_id)
    assert len(first_findings) == 2
    assert first_occurrence_count == 2
    assert len(second_findings) == 2
    assert second_occurrence_count == 4
    assert {finding.cve_id: finding.first_seen_at for finding in second_findings} == first_seen
    assert {finding.cve_id: finding.dedup_key for finding in second_findings} == first_dedup_keys
    assert all(
        finding.last_seen_at > first_last_seen[finding.cve_id] for finding in second_findings
    )

    findings = template_api_env.client.get(
        f"/api/v1/projects/{project['id']}/findings/",
        headers=headers,
    )
    assert findings.status_code == 200
    assert findings.json()["count"] == 2


def test_same_cve_on_different_assets_creates_distinct_findings(
    template_api_env: TemplateApiEnv,
    tmp_path: Path,
) -> None:
    _configure_upload_dir(template_api_env, tmp_path)
    headers = auth_headers(template_api_env.client)
    project = create_project_via_api(template_api_env.client, headers)
    project_id = uuid.UUID(project["id"])
    content = "\n".join(
        [
            "cve_id,asset_ref,component,version,purl,severity",
            "CVE-2024-3094,build-host-1,xz,5.6.0,pkg:apk/alpine/xz@5.6.0-r0,CRITICAL",
            "CVE-2024-3094,build-host-2,xz,5.6.0,pkg:apk/alpine/xz@5.6.0-r0,CRITICAL",
            "",
        ]
    ).encode()

    response = template_api_env.client.post(
        f"/api/v1/projects/{project['id']}/imports",
        headers=headers,
        data={"input_type": "generic-occurrence-csv"},
        files={"file": ("same-cve-assets.csv", content, "text/csv")},
    )

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["summary_json"]["finding_count"] == 2
    assert payload["summary_json"]["dedup_summary"]["created_findings"] == 2
    assert {
        item["asset_ref"] for item in payload["summary_json"]["dedup_summary"]["decisions"]
    } == {"build-host-1", "build-host-2"}

    findings, occurrence_count = _finding_state(template_api_env, project_id)
    assert len(findings) == 2
    assert occurrence_count == 2
    assert len({finding.dedup_key for finding in findings}) == 2


@pytest.mark.parametrize(
    ("input_type", "filename", "content_type", "detail"),
    [
        ("unknown", "scan.txt", "text/plain", "Unsupported input type"),
        ("cve-list", "scan.json", "text/plain", "File extension does not match input type"),
        (
            "cve-list",
            "scan.txt",
            "application/json",
            "Upload content type does not match input type",
        ),
    ],
)
def test_upload_rejects_unknown_input_type_bad_extension_and_mime(
    template_api_env: TemplateApiEnv,
    tmp_path: Path,
    input_type: str,
    filename: str,
    content_type: str,
    detail: str,
) -> None:
    _configure_upload_dir(template_api_env, tmp_path)
    headers = auth_headers(template_api_env.client)
    project = create_project_via_api(template_api_env.client, headers)

    response = template_api_env.client.post(
        f"/api/v1/projects/{project['id']}/imports",
        headers=headers,
        data={"input_type": input_type},
        files={"file": (filename, b"CVE-2024-3094\n", content_type)},
    )

    assert response.status_code == 422
    assert detail in response.text
    assert _run_count(template_api_env, uuid.UUID(project["id"])) == 0


def test_upload_rejects_oversized_file_without_persisting_run_or_file(
    template_api_env: TemplateApiEnv,
    tmp_path: Path,
) -> None:
    upload_dir = _configure_upload_dir(template_api_env, tmp_path, max_upload_mb=1)
    headers = auth_headers(template_api_env.client)
    project = create_project_via_api(template_api_env.client, headers)

    response = template_api_env.client.post(
        f"/api/v1/projects/{project['id']}/imports",
        headers=headers,
        data={"input_type": "cve-list"},
        files={"file": ("large.txt", b"A" * (1024 * 1024 + 1), "text/plain")},
    )

    assert response.status_code == 413
    assert "Upload exceeds configured limit" in response.text
    assert _run_count(template_api_env, uuid.UUID(project["id"])) == 0
    assert not upload_dir.exists()


def test_upload_rejects_path_traversal_filename(
    template_api_env: TemplateApiEnv,
    tmp_path: Path,
) -> None:
    upload_dir = _configure_upload_dir(template_api_env, tmp_path)
    headers = auth_headers(template_api_env.client)
    project = create_project_via_api(template_api_env.client, headers)
    outside = tmp_path / "evil.txt"

    response = template_api_env.client.post(
        f"/api/v1/projects/{project['id']}/imports",
        headers=headers,
        data={"input_type": "cve-list"},
        files={"file": ("../../evil.txt", b"CVE-2024-3094\n", "text/plain")},
    )

    assert response.status_code == 422
    assert "Upload filename is not allowed" in response.text
    assert _run_count(template_api_env, uuid.UUID(project["id"])) == 0
    assert not outside.exists()
    assert not upload_dir.exists()


def test_parse_errors_are_structured_and_failed_run_is_persisted(
    template_api_env: TemplateApiEnv,
    tmp_path: Path,
) -> None:
    upload_dir = _configure_upload_dir(template_api_env, tmp_path)
    headers = auth_headers(template_api_env.client)
    project = create_project_via_api(template_api_env.client, headers)
    content = b"CVE-2024-3094\nnot-a-cve\n"
    expected_sha256 = hashlib.sha256(content).hexdigest()

    response = template_api_env.client.post(
        f"/api/v1/projects/{project['id']}/imports",
        headers=headers,
        data={"input_type": "cve-list"},
        files={"file": ("bad.txt", content, "text/plain")},
    )

    assert response.status_code == 422
    detail = response.json()["detail"]
    assert detail["message"] == "Import parsing failed."
    assert detail["analysis_run_id"]
    assert detail["parse_errors"][0]["input_type"] == "cve-list"
    assert detail["parse_errors"][0]["filename"] == "bad.txt"
    assert "line 2" in detail["parse_errors"][0]["message"]
    assert "not-a-cve" in detail["parse_errors"][0]["message"]

    run = template_api_env.client.get(
        f"/api/v1/runs/{detail['analysis_run_id']}",
        headers=headers,
    )
    assert run.status_code == 200
    payload = run.json()
    assert payload["status"] == "failed"
    assert [item["status"] for item in payload["error_json"]["import_job"]["status_history"]] == [
        "pending",
        "running",
        "failed",
    ]
    assert payload["error_json"]["parse_errors"] == detail["parse_errors"]
    assert payload["summary_json"]["parse_errors"] == detail["parse_errors"]
    assert payload["summary_json"]["input_upload"]["sha256"] == expected_sha256
    assert Path(payload["summary_json"]["input_upload"]["path"]).is_relative_to(upload_dir)
    assert Path(payload["summary_json"]["input_upload"]["path"]).read_bytes() == content


def _configure_upload_dir(
    template_api_env: TemplateApiEnv,
    tmp_path: Path,
    *,
    max_upload_mb: int = 25,
) -> Path:
    upload_dir = tmp_path / "template-import-uploads"
    active_settings = template_api_env.client.app.state.template_settings
    template_api_env.client.app.state.template_settings = replace(
        active_settings,
        IMPORT_UPLOAD_DIR=str(upload_dir),
        MAX_UPLOAD_MB=max_upload_mb,
    )
    return upload_dir.resolve(strict=False)


def _run_count(template_api_env: TemplateApiEnv, project_id: uuid.UUID) -> int:
    with Session(template_api_env.engine) as session:
        return len(
            template_api_env.repositories.RunRepository(session).list_analysis_runs(project_id)
        )


def _finding_state(
    template_api_env: TemplateApiEnv,
    project_id: uuid.UUID,
) -> tuple[list[app_models.Finding], int]:
    with Session(template_api_env.engine) as session:
        findings = list(
            session.exec(
                select(app_models.Finding)
                .where(app_models.Finding.project_id == project_id)
                .order_by(app_models.Finding.cve_id)
            )
        )
        occurrence_count = len(
            session.exec(
                select(app_models.FindingOccurrence)
                .join(app_models.Finding)
                .where(app_models.Finding.project_id == project_id)
            ).all()
        )
        return findings, occurrence_count

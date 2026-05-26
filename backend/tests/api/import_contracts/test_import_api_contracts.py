from __future__ import annotations

import hashlib
import uuid
from pathlib import Path

import pytest
from sqlmodel import Session, select
from utils.import_contracts import (
    configure_upload_dir as _configure_upload_dir,
)
from utils.import_contracts import (
    run_count as _run_count,
)
from utils.workbench_env import (
    WorkbenchApiEnv,
    create_project_via_api,
    local_api_headers,
)

from app import models as app_models


def test_valid_cve_list_upload_creates_analysis_run_and_stores_sha256(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    upload_dir = _configure_upload_dir(workbench_api_env, tmp_path)
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    content = b"CVE-2024-3094\nCVE-2021-44228\n"
    expected_sha256 = hashlib.sha256(content).hexdigest()

    response = workbench_api_env.client.post(
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
    assert payload["provider_snapshot_id"]
    assert payload["summary_json"]["provider_snapshot_id"] == payload["provider_snapshot_id"]
    assert payload["summary_json"]["analysis_service"]["pipeline"] == (
        "parse-persist-enrich-score-explain"
    )
    assert payload["summary_json"]["counts_by_priority"] == {
        "Critical": 2,
        "High": 0,
        "Medium": 0,
        "Low": 0,
    }
    assert payload["summary_json"]["kev_hits"] >= 1
    assert payload["summary_json"]["created_findings"] == 2
    assert payload["summary_json"]["updated_findings"] == 0
    assert payload["summary_json"]["ignored_lines"] == 0
    assert payload["summary_json"]["input_upload"]["sha256"] == expected_sha256
    assert payload["summary_json"]["input_upload"]["original_filename"] == "Team Scan (prod).txt"
    assert payload["summary_json"]["input_upload"]["stored_filename"] == "Team_Scan__prod_.txt"
    stored_ref = payload["summary_json"]["input_upload"]["path"]
    assert stored_ref == f"{project['id']}/{payload['id']}/Team_Scan__prod_.txt"
    assert payload["summary_json"]["input_upload"]["storage_ref"] == stored_ref
    assert not Path(stored_ref).is_absolute()
    stored_path = upload_dir / stored_ref
    assert stored_path == upload_dir / project["id"] / payload["id"] / "Team_Scan__prod_.txt"
    assert stored_path.read_bytes() == content
    assert payload["summary_json"]["import_job"]["status"] == "succeeded"
    assert payload["summary_json"]["import_job"]["execution_mode"] == "request"
    assert [item["status"] for item in payload["summary_json"]["import_job"]["status_history"]] == [
        "pending",
        "running",
        "succeeded",
    ]
    assert payload["summary_json"]["parse_errors"] == []

    runs = workbench_api_env.client.get(
        f"/api/v1/projects/{project['id']}/runs/",
        headers=headers,
    )
    assert runs.status_code == 200
    assert runs.json()["count"] == 1
    assert runs.json()["data"][0]["id"] == payload["id"]
    assert runs.json()["data"][0]["status"] == "succeeded"
    with Session(workbench_api_env.engine) as session:
        import_event = session.exec(
            select(app_models.AuditEvent).where(
                app_models.AuditEvent.action == "import.run",
                app_models.AuditEvent.resource_id == payload["id"],
            )
        ).one()
    assert import_event.status == "success"
    assert import_event.project_id == uuid.UUID(project["id"])
    assert import_event.detail_json == {"stage": "succeeded", "input_type": "cve-list"}

    findings = workbench_api_env.client.get(
        f"/api/v1/projects/{project['id']}/findings/",
        headers=headers,
    )
    assert findings.status_code == 200
    finding_payloads = findings.json()["data"]
    assert findings.json()["count"] == 2
    assert {item["priority"] for item in finding_payloads} == {"critical"}
    assert all(item["risk_score"] is not None for item in finding_payloads)
    assert all(item["operational_rank"] > 0 for item in finding_payloads)
    assert all(item["explanation_json"]["explanation"]["reasons"] for item in finding_payloads)
    assert all(
        item["explanation_json"]["decision_guidance"]["decision_statement"]
        for item in finding_payloads
    )

    summary = workbench_api_env.client.get(
        f"/api/v1/runs/{payload['id']}/summary",
        headers=headers,
    )
    assert summary.status_code == 200
    summary_payload = summary.json()
    assert summary_payload["id"] == payload["id"]
    assert summary_payload["project_id"] == project["id"]
    assert summary_payload["status"] == "succeeded"
    assert summary_payload["created_findings"] == 2
    assert summary_payload["updated_findings"] == 0
    assert summary_payload["ignored_lines"] == 0
    assert summary_payload["occurrence_count"] == 2
    assert summary_payload["finding_count"] == 2
    assert summary_payload["provider_snapshot_id"] == payload["provider_snapshot_id"]
    assert summary_payload["counts_by_priority"] == payload["summary_json"]["counts_by_priority"]
    assert summary_payload["kev_hits"] == payload["summary_json"]["kev_hits"]
    assert summary_payload["parse_errors"] == []
    assert summary_payload["input_upload"]["sha256"] == expected_sha256


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
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
    input_type: str,
    filename: str,
    content_type: str,
    detail: str,
) -> None:
    _configure_upload_dir(workbench_api_env, tmp_path)
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)

    response = workbench_api_env.client.post(
        f"/api/v1/projects/{project['id']}/imports",
        headers=headers,
        data={"input_type": input_type},
        files={"file": (filename, b"CVE-2024-3094\n", content_type)},
    )

    assert response.status_code == 422
    assert detail in response.text
    assert _run_count(workbench_api_env, uuid.UUID(project["id"])) == 0


def test_summary_tracks_ignored_cve_list_lines(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    _configure_upload_dir(workbench_api_env, tmp_path)
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    content = b"# comment\n\nCVE-2024-3094\n"

    response = workbench_api_env.client.post(
        f"/api/v1/projects/{project['id']}/imports",
        headers=headers,
        data={"input_type": "cve-list"},
        files={"file": ("with-ignored-lines.txt", content, "text/plain")},
    )

    assert response.status_code == 200, response.text
    run_id = response.json()["id"]
    summary = workbench_api_env.client.get(f"/api/v1/runs/{run_id}/summary", headers=headers)
    assert summary.status_code == 200
    summary_payload = summary.json()
    assert summary_payload["ignored_lines"] == 2
    assert summary_payload["created_findings"] == 1
    assert summary_payload["updated_findings"] == 0
    assert summary_payload["parse_errors"] == []

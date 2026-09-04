from __future__ import annotations

import hashlib
import uuid
from pathlib import Path

import pytest
from sqlmodel import Session, select
from utils.import_contracts import (
    completed_run_payload as _completed_run_payload,
)
from utils.import_contracts import (
    completed_run_summary as _completed_run_summary,
)
from utils.import_contracts import (
    configure_upload_dir as _configure_upload_dir,
)
from utils.import_contracts import (
    public_run_aliases as _public_run_aliases,
)
from utils.import_contracts import (
    run_count as _run_count,
)
from utils.workbench_env import (
    WorkbenchApiEnv,
    create_project_via_api,
    local_api_headers,
)
from utils.workbench_workflow_contracts import workflow_metadata

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
    assert response.json()["workflow"]["status"] == "pending"
    payload = _completed_run_payload(workbench_api_env, response, headers=headers)
    assert payload["project_id"] == project["id"]
    assert payload["input_type"] == "cve-list"
    assert payload["filename"] == "Team_Scan__prod_.txt"
    assert payload["status"] == "succeeded"
    assert payload["workflow_schema_version"] == "analysis-evidence.v2"
    assert payload["evidence"]["schema_version"] == "analysis-evidence.v2"
    assert payload["evidence"]["analysis_evidence_id"]
    assert payload["input_sha256"] == expected_sha256
    assert payload["occurrence_count"] == 2
    assert payload["finding_count"] == 2
    assert payload["created_findings"] == 2
    assert payload["updated_findings"] == 0
    assert payload["ignored_lines"] == 0
    assert payload["input_upload"]["sha256"] == expected_sha256
    assert payload["input_upload"]["storage_ref"] == (
        f"{project['id']}/{payload['id']}/Team_Scan__prod_.txt"
    )
    assert payload["dedup_summary"]["created_findings"] == 2
    assert payload["dedup_summary"]["reused_findings"] == 0
    assert payload["provider_snapshot_id"]
    assert payload["counts_by_priority"] == {
        "Critical": 2,
        "High": 0,
        "Medium": 0,
        "Low": 0,
    }
    assert payload["kev_hits"] >= 1
    assert payload["input_upload"]["sha256"] == expected_sha256
    assert payload["input_upload"]["original_filename"] == "Team Scan (prod).txt"
    assert payload["input_upload"]["stored_filename"] == "Team_Scan__prod_.txt"
    stored_ref = payload["input_upload"]["path"]
    assert stored_ref == f"{project['id']}/{payload['id']}/Team_Scan__prod_.txt"
    assert payload["input_upload"]["storage_ref"] == stored_ref
    assert not Path(stored_ref).is_absolute()
    stored_path = upload_dir / stored_ref
    assert stored_path == upload_dir / project["id"] / payload["id"] / "Team_Scan__prod_.txt"
    assert stored_path.read_bytes() == content
    assert "import_job" not in payload
    assert "execution_mode" not in payload["workflow"]

    runs = workbench_api_env.client.get(
        f"/api/v1/projects/{project['id']}/runs/",
        headers=headers,
    )
    assert runs.status_code == 200
    listed_run = _public_run_aliases(runs.json()["data"][0])
    assert runs.json()["count"] == 1
    assert listed_run["id"] == payload["id"]
    assert listed_run["status"] == "succeeded"
    assert listed_run["workflow_schema_version"] == "analysis-evidence.v2"
    assert listed_run["input_upload"]["sha256"] == expected_sha256
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
    assert all(
        item["evidence"]["schema_version"] == "finding-decision-evidence.v2"
        for item in finding_payloads
    )
    assert all(item["evidence"]["priority_evidence"]["explanation"] for item in finding_payloads)
    assert all(item["evidence"]["remediation"]["decision_statement"] for item in finding_payloads)

    summary = workbench_api_env.client.get(
        f"/api/v1/runs/{payload['id']}/summary",
        headers=headers,
    )
    assert summary.status_code == 200
    summary_payload = _public_run_aliases(summary.json())
    assert summary_payload["id"] == payload["id"]
    assert summary_payload["project_id"] == project["id"]
    assert summary_payload["status"] == "succeeded"
    assert summary_payload["created_findings"] == 2
    assert summary_payload["updated_findings"] == 0
    assert summary_payload["ignored_lines"] == 0
    assert summary_payload["occurrence_count"] == 2
    assert summary_payload["finding_count"] == 2
    assert summary_payload["provider_snapshot_id"] == payload["provider_snapshot_id"]
    assert summary_payload["counts_by_priority"] == payload["counts_by_priority"]
    assert summary_payload["kev_hits"] == payload["kev_hits"]
    assert summary_payload["parse_errors"] == []
    assert summary_payload["workflow_schema_version"] == "analysis-evidence.v2"
    assert summary_payload["input_upload"]["sha256"] == expected_sha256
    assert "import_job" not in summary_payload
    assert summary_payload["dedup_summary"]["reused_findings"] == 0

    metadata_payload = workflow_metadata(workbench_api_env, payload["id"], headers=headers)
    assert metadata_payload["summary"]["schema_version"] == "analysis-evidence.v2"
    assert (
        metadata_payload["summary"]["provider"]["provider_snapshot_id"]
        == payload["provider_snapshot_id"]
    )
    assert metadata_payload["summary"]["analysis_service"]["pipeline"] == (
        "parse-enrich-scope-evaluate-persist"
    )
    assert metadata_payload["error"] is None


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
    summary_payload = _completed_run_summary(workbench_api_env, response, headers=headers)
    assert summary_payload["ignored_lines"] == 2
    assert summary_payload["created_findings"] == 1
    assert summary_payload["updated_findings"] == 0
    assert summary_payload["parse_errors"] == []

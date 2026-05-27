from __future__ import annotations

import json
import uuid
from pathlib import Path

import pytest
from pydantic import ValidationError
from sqlmodel import Session
from utils.workbench_env import (
    WorkbenchApiEnv,
    create_project_via_api,
    local_api_headers,
)
from utils.workbench_workflow_contracts import (
    assert_no_raw_workflow_fields,
    workflow_metadata,
)

from app import models as app_models
from app.services.run_workflow_metadata import workflow_summary_payload


def test_legacy_workflow_metadata_projects_typed_fields_and_preserves_additive_raw(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    with Session(workbench_api_env.engine) as session:
        run_repo = workbench_api_env.repositories.RunRepository(session)
        snapshot = run_repo.get_or_create_provider_snapshot(
            content_hash="sha256:workflow-hardening-legacy",
            nvd_last_sync="2026-04-28T10:15:00Z",
            epss_date="2026-04-28",
            kev_catalog_version="2026-04-28",
            source_hashes_json={"provider_snapshot": "sha256:workflow-hardening-legacy"},
        )
        run = run_repo.create_analysis_run(
            project_id=uuid.UUID(project["id"]),
            provider_snapshot_id=snapshot.id,
            input_type="cve-list",
            filename="legacy-cves.txt",
            status=app_models.AnalysisRunStatus.FAILED,
            summary_json={
                "created_findings": 3,
                "updated_findings": 1,
                "finding_count": 3,
                "provider_snapshot_id": str(snapshot.id),
                "provider_extension": {"imported_by": "legacy-fixture"},
            },
            error_json={
                "analysis_error": {
                    "message": "Provider cache replay failed.",
                    "stage": "provider_update",
                    "error_type": "ProviderUpdateError",
                },
                "provider_error_code": "cache-replay-failed",
            },
        )
        run_id = str(run.id)
        session.commit()

    detail_response = workbench_api_env.client.get(f"/api/v1/runs/{run_id}", headers=headers)
    assert detail_response.status_code == 200, detail_response.text
    detail = detail_response.json()
    assert_no_raw_workflow_fields(detail)
    assert detail["workflow_schema_version"] == "run-workflow-summary.v1"
    assert detail["workflow_error_schema_version"] == "run-workflow-error.v1"
    assert detail["created_findings"] == 3
    assert detail["workflow_error"]["analysis_error"]["stage"] == "provider_update"

    list_response = workbench_api_env.client.get(
        f"/api/v1/projects/{project['id']}/runs/",
        headers=headers,
    )
    assert list_response.status_code == 200, list_response.text
    assert_no_raw_workflow_fields(list_response.json())

    summary_response = workbench_api_env.client.get(
        f"/api/v1/runs/{run_id}/summary",
        headers=headers,
    )
    assert summary_response.status_code == 200, summary_response.text
    summary = summary_response.json()
    assert_no_raw_workflow_fields(summary)
    assert summary["workflow_schema_version"] == "run-workflow-summary.v1"
    assert summary["workflow_error_schema_version"] == "run-workflow-error.v1"
    assert summary["created_findings"] == 3

    metadata = workflow_metadata(workbench_api_env, run_id, headers=headers)
    assert metadata["summary"]["schema_version"] == "run-workflow-summary.v1"
    assert metadata["error"]["schema_version"] == "run-workflow-error.v1"
    assert metadata["raw_summary"]["provider_extension"] == {"imported_by": "legacy-fixture"}
    assert metadata["raw_error"]["provider_error_code"] == "cache-replay-failed"


def test_workflow_metadata_diagnostics_redacts_typed_and_raw_payloads(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    private_upload = tmp_path / "private" / "upload.csv"
    private_log = tmp_path / "private" / "workflow-error.log"
    with Session(workbench_api_env.engine) as session:
        run_repo = workbench_api_env.repositories.RunRepository(session)
        run = run_repo.create_analysis_run(
            project_id=uuid.UUID(project["id"]),
            input_type="cve-list",
            filename="secret-cves.txt",
            status=app_models.AnalysisRunStatus.FAILED,
            summary_json={
                "input_upload": {
                    "input_type": "cve-list",
                    "path": str(private_upload),
                    "sha256": "sha256:redacted-input",
                },
                "token": "Bearer summary-secret-token",
            },
            error_json={
                "background_error": {
                    "message": f"background import failed at {private_log}",
                    "stage": "background_import",
                    "error_type": "RuntimeError",
                },
                "authorization": "Bearer error-secret-token",
            },
        )
        run_id = str(run.id)
        session.commit()

    metadata = workflow_metadata(workbench_api_env, run_id, headers=headers)
    serialized = json.dumps(metadata)
    assert str(tmp_path) not in serialized
    assert "summary-secret-token" not in serialized
    assert "error-secret-token" not in serialized
    assert metadata["summary"]["input_upload"]["path"] == "[REDACTED]"
    assert metadata["summary"]["token"] == "[REDACTED]"
    assert metadata["error"]["background_error"]["message"] == "[REDACTED]"
    assert metadata["raw_summary"]["input_upload"]["path"] == "[REDACTED]"
    assert metadata["raw_error"]["authorization"] == "[REDACTED]"


def test_workflow_metadata_access_layer_rejects_invalid_persisted_summary() -> None:
    run = app_models.AnalysisRun(
        project_id=uuid.uuid4(),
        input_type="cve-list",
        filename="invalid-cves.txt",
        summary_json={"created_findings": {"not": "an integer"}},
        error_json={},
    )

    with pytest.raises(ValidationError):
        workflow_summary_payload(run)

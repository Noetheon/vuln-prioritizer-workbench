from __future__ import annotations

import uuid
from dataclasses import replace
from pathlib import Path

import pytest
from sqlmodel import Session, select
from utils.import_contracts import (
    assert_no_sensitive_path_leak as _assert_no_sensitive_path_leak,
)
from utils.import_contracts import (
    completed_run_payload as _completed_run_payload,
)
from utils.import_contracts import (
    configure_upload_dir as _configure_upload_dir,
)
from utils.workbench_env import (
    WorkbenchApiEnv,
    create_project_via_api,
    local_api_headers,
)

from app import models as app_models
from app.services import WorkbenchAnalysisError


def test_non_local_synchronous_import_audit_uses_local_actor(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    _configure_upload_dir(workbench_api_env, tmp_path)
    client = workbench_api_env.client
    headers = local_api_headers(client)
    project = create_project_via_api(client, headers)
    old_settings = client.app.state.workbench_settings
    old_engine = client.app.state.workbench_engine
    background_settings = replace(
        old_settings,
        ENVIRONMENT="staging",
        SECRET_KEY="s" * 32,
        FRONTEND_HOST="https://workbench.example.test",
    )

    client.app.state.workbench_settings = background_settings
    client.app.state.workbench_engine = workbench_api_env.engine
    try:
        response = client.post(
            f"/api/v1/projects/{project['id']}/imports",
            headers=headers,
            data={
                "input_type": "cve-list",
                "provider_snapshot_file": "demo_provider_snapshot.json",
                "locked_provider_data": "true",
            },
            files={"file": ("background-cves.txt", b"CVE-2024-3094\n", "text/plain")},
        )
    finally:
        client.app.state.workbench_settings = old_settings
        client.app.state.workbench_engine = old_engine

    assert response.status_code == 200, response.text
    payload = _completed_run_payload(workbench_api_env, response, headers=headers)
    run_id = uuid.UUID(payload["id"])
    assert "result" not in payload
    assert "import_job" not in payload
    assert "execution_mode" not in (payload.get("workflow") or {})

    with Session(workbench_api_env.engine) as session:
        run = session.get(app_models.AnalysisRun, run_id)
        import_event = session.exec(
            select(app_models.AuditEvent)
            .where(app_models.AuditEvent.action == "import.run")
            .where(app_models.AuditEvent.resource_id == str(run_id))
        ).one()

    assert run is not None
    assert run.status == app_models.AnalysisRunStatus.SUCCEEDED
    assert import_event.status == "success"
    assert import_event.project_id == uuid.UUID(project["id"])
    assert import_event.detail_json == {"stage": "succeeded", "input_type": "cve-list"}


def test_analysis_failure_persists_failed_run_without_partial_findings(
    monkeypatch: pytest.MonkeyPatch,
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    upload_dir = _configure_upload_dir(workbench_api_env, tmp_path)
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)

    def _fail_analysis(*args: object, **kwargs: object) -> object:
        raise WorkbenchAnalysisError(f"scoring failed for {upload_dir / 'private.json'}")

    monkeypatch.setattr(
        "app.services.import_execution.AnalysisService.analyze_import",
        _fail_analysis,
    )

    response = workbench_api_env.client.post(
        f"/api/v1/projects/{project['id']}/imports",
        headers=headers,
        data={"input_type": "cve-list"},
        files={"file": ("sample.txt", b"CVE-2024-3094\n", "text/plain")},
    )

    assert response.status_code == 200
    run_payload = _completed_run_payload(workbench_api_env, response, headers=headers)
    assert run_payload["status"] == "failed"
    detail = {**run_payload["diagnostics"], "analysis_run_id": run_payload["id"]}
    assert detail["message"] == "Import analysis failed."
    assert detail["analysis_error"]["stage"] == "enrich_score_explain"
    assert "scoring failed" in detail["analysis_error"]["message"]
    assert "uploaded file" in detail["analysis_error"]["message"]
    _assert_no_sensitive_path_leak(detail["analysis_error"], tmp_path, upload_dir)

    diagnostics = run_payload["diagnostics"]
    assert diagnostics["analysis_error"]["stage"] == "enrich_score_explain"
    _assert_no_sensitive_path_leak(
        diagnostics["analysis_error"],
        tmp_path,
        upload_dir,
    )
    assert run_payload["counts"]["created_findings"] == 0
    assert run_payload["counts"]["updated_findings"] == 0

    findings = workbench_api_env.client.get(
        f"/api/v1/projects/{project['id']}/findings/",
        headers=headers,
    )
    assert findings.status_code == 200
    assert findings.json()["count"] == 0

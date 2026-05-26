from __future__ import annotations

import asyncio
import uuid
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import pytest
from sqlmodel import Session, select
from utils.import_contracts import (
    assert_no_sensitive_path_leak as _assert_no_sensitive_path_leak,
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
from app.core.local_actor import configured_local_actor
from app.models.base import get_datetime_utc
from app.services import WorkbenchAnalysisError
from app.services.import_background import reconcile_stale_background_import_runs
from app.services.import_execution import (
    ImportUploadContent,
    ProjectImportUploadRequest,
    execute_project_import_upload,
)


def test_import_upload_service_can_defer_and_resume_background_execution(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    upload_dir = _configure_upload_dir(workbench_api_env, tmp_path)
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    active_settings = workbench_api_env.client.app.state.workbench_settings
    upload = ProjectImportUploadRequest(
        input_type="cve-list",
        file=ImportUploadContent(
            filename="background-cves.txt",
            content_type="text/plain",
            content=b"CVE-2024-3094\n",
        ),
    )

    with Session(workbench_api_env.engine) as session:
        local_actor = configured_local_actor(active_settings)
        deferred_run = asyncio.run(
            execute_project_import_upload(
                project_id=uuid.UUID(project["id"]),
                session=session,
                local_actor=local_actor,
                settings=active_settings,
                upload=upload,
                defer_execution=True,
                execution_mode="background",
            )
        )
        deferred_summary = deferred_run.summary_json

        assert deferred_run.status == app_models.AnalysisRunStatus.PENDING
        assert deferred_summary["import_job"]["status"] == "pending"
        assert deferred_summary["import_job"]["execution_mode"] == "background"
        assert [item["status"] for item in deferred_summary["import_job"]["status_history"]] == [
            "pending"
        ]
        stored_ref = deferred_summary["input_upload"]["storage_ref"]
        assert (upload_dir / stored_ref).read_bytes() == b"CVE-2024-3094\n"

        resumed_run = asyncio.run(
            execute_project_import_upload(
                project_id=uuid.UUID(project["id"]),
                session=session,
                local_actor=local_actor,
                settings=active_settings,
                upload=upload,
                existing_run_id=deferred_run.id,
                execution_mode="background",
            )
        )

        assert resumed_run.id == deferred_run.id
        assert resumed_run.status == app_models.AnalysisRunStatus.SUCCEEDED
        assert resumed_run.summary_json["import_job"]["execution_mode"] == "background"
        assert [
            item["status"] for item in resumed_run.summary_json["import_job"]["status_history"]
        ] == ["pending", "running", "succeeded"]
        assert resumed_run.summary_json["created_findings"] == 1


def test_background_import_reconciliation_fails_stale_deferred_runs(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    _configure_upload_dir(workbench_api_env, tmp_path)
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    active_settings = replace(
        workbench_api_env.client.app.state.workbench_settings,
        BACKGROUND_IMPORT_STALE_MINUTES=1,
    )
    upload = ProjectImportUploadRequest(
        input_type="cve-list",
        file=ImportUploadContent(
            filename="stale-background-cves.txt",
            content_type="text/plain",
            content=b"CVE-2024-3094\n",
        ),
    )

    with Session(workbench_api_env.engine) as session:
        local_actor = configured_local_actor(active_settings)
        deferred_run = asyncio.run(
            execute_project_import_upload(
                project_id=uuid.UUID(project["id"]),
                session=session,
                local_actor=local_actor,
                settings=active_settings,
                upload=upload,
                defer_execution=True,
                execution_mode="background",
            )
        )
        deferred_run.started_at = get_datetime_utc() - timedelta(minutes=5)
        session.add(deferred_run)
        session.commit()
        run_id = deferred_run.id

    reconciled = reconcile_stale_background_import_runs(
        engine=workbench_api_env.engine,
        settings=active_settings,
    )

    assert reconciled == 1
    with Session(workbench_api_env.engine) as session:
        run = session.get(app_models.AnalysisRun, run_id)
        assert run is not None
        assert run.status == app_models.AnalysisRunStatus.FAILED
        assert run.finished_at is not None
        assert run.summary_json["import_job"]["status"] == "failed"
        assert run.summary_json["background_error"]["stage"] == "background_import"


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
    payload = response.json()
    run_id = uuid.UUID(payload["id"])
    assert payload["import_job"]["execution_mode"] == "request"

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

    assert response.status_code == 422
    assert response.json()["code"] == "import_analysis_failed"
    assert response.json()["details"]["analysis_run_id"]
    detail = response.json()["detail"]
    assert detail["message"] == "Import analysis failed."
    assert detail["analysis_error"]["stage"] == "enrich_score_explain"
    assert "scoring failed" in detail["analysis_error"]["message"]
    assert "uploaded file" in detail["analysis_error"]["message"]
    _assert_no_sensitive_path_leak(detail["analysis_error"], tmp_path, upload_dir)

    run = workbench_api_env.client.get(
        f"/api/v1/runs/{detail['analysis_run_id']}",
        headers=headers,
    )
    assert run.status_code == 200
    run_payload = run.json()
    assert run_payload["status"] == "failed"
    assert run_payload["analysis_error"]["stage"] == "enrich_score_explain"
    assert run_payload["workflow_error"]["analysis_error"]["stage"] == "enrich_score_explain"
    _assert_no_sensitive_path_leak(
        run_payload["analysis_error"],
        tmp_path,
        upload_dir,
    )
    _assert_no_sensitive_path_leak(
        run_payload["workflow_error"]["analysis_error"],
        tmp_path,
        upload_dir,
    )
    assert run_payload["created_findings"] == 0
    assert run_payload["updated_findings"] == 0

    findings = workbench_api_env.client.get(
        f"/api/v1/projects/{project['id']}/findings/",
        headers=headers,
    )
    assert findings.status_code == 200
    assert findings.json()["count"] == 0

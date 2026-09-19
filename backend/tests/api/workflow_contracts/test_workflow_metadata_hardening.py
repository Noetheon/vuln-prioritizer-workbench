from __future__ import annotations

import json
import uuid
from pathlib import Path

from sqlmodel import Session
from utils.workbench_env import (
    WorkbenchApiEnv,
    create_project_via_api,
    local_api_headers,
)
from utils.workbench_workflow_contracts import assert_no_raw_workflow_fields

from app import models as app_models
from app.services.run_workflow_metadata import (
    merge_error_payload,
    merge_summary_payload,
    public_workflow_fields,
    redacted_workflow_error_payload,
    redacted_workflow_summary_payload,
)
from app.services.workflow_execution import (
    WorkflowExecutionContext,
)
from app.services.workflows import latest_analysis_workflow_public, latest_report_workflow_public


def test_workflow_public_projection_hides_internal_result_and_diagnostics(
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
        )
        workflow_repo = workbench_api_env.repositories.WorkflowRepository(session)
        workflow = workflow_repo.create_workflow_run(
            kind=app_models.WorkflowRunKind.IMPORT,
            title="Import cve-list",
            handler="app.services.import_execution.execute_project_import_upload",
            project_id=run.project_id,
            analysis_run_id=run.id,
            current_stage="queued",
        )
        workflow_repo.finish_workflow(
            workflow.id,
            status=app_models.WorkflowRunStatus.FAILED,
            stage="parse_upload",
            message="Import failed.",
            result_ref_json={
                "schema_version": "workflow-result-ref.v2",
                "path": str(private_upload),
                "token": "Bearer result-secret-token",
            },
            diagnostics_json={
                "stage": "parse_upload",
                "message": f"failed at {private_log}",
                "authorization": "Bearer diagnostics-secret-token",
            },
            terminal_code="parse_failed",
        )
        run_id = str(run.id)
        session.commit()

    response = workbench_api_env.client.get(f"/api/v1/runs/{run_id}", headers=headers)
    assert response.status_code == 200, response.text
    payload = response.json()
    assert_no_raw_workflow_fields(payload)
    assert "result" not in payload
    assert payload["evidence"] is None
    assert payload["workflow"]["status"] == "failed"
    assert "execution_mode" not in payload["workflow"]
    assert "diagnostics" not in payload["workflow"]
    assert "error_details" not in payload["workflow"]
    serialized = json.dumps(payload)
    assert str(tmp_path) not in serialized
    assert "result-secret-token" not in serialized
    assert "diagnostics-secret-token" not in serialized


def test_run_workflow_metadata_helpers_only_merge_and_redact_internal_payloads(
    tmp_path: Path,
) -> None:
    private_upload = tmp_path / "private" / "upload.csv"
    private_log = tmp_path / "private" / "workflow-error.log"
    result = merge_summary_payload(
        {"created_findings": 1},
        input_upload={
            "input_type": "cve-list",
            "path": str(private_upload),
            "sha256": "sha256:input",
        },
        token="Bearer summary-secret-token",
    )
    diagnostics = merge_error_payload(
        None,
        analysis_error={
            "message": f"Failed while reading {private_log}",
            "stage": "analysis",
            "error_type": "RuntimeError",
        },
        authorization="Bearer error-secret-token",
    )

    assert result["created_findings"] == 1
    assert redacted_workflow_summary_payload(result)["input_upload"]["path"] == "[REDACTED]"
    redacted_error = redacted_workflow_error_payload(diagnostics)
    assert redacted_error["analysis_error"]["message"] == "[REDACTED]"
    assert redacted_error["authorization"] == "[REDACTED]"
    public_fields = public_workflow_fields(result, diagnostics)
    assert public_fields["result"]["token"] == "[REDACTED]"
    assert public_fields["diagnostics"]["analysis_error"]["message"] == "[REDACTED]"


def test_latest_workflow_public_helpers_return_none_without_workflow(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    with Session(workbench_api_env.engine) as session:
        assert latest_analysis_workflow_public(session, analysis_run_id=uuid.uuid4()) is None
        assert latest_report_workflow_public(session, report_id=uuid.uuid4()) is None


def test_workflow_execution_context_publishes_control_then_atomic_result(
    file_backed_workbench_api_env: WorkbenchApiEnv,
) -> None:
    env = file_backed_workbench_api_env
    with Session(env.engine) as session:
        repository = env.repositories.WorkflowRepository(session)
        workflow = repository.create_workflow_run(
            kind=app_models.WorkflowRunKind.IMPORT,
            title="Import cve-list",
            handler="test",
        )
        workflow_id = workflow.id
        session.commit()
        repository.claim_due_workflows(worker_id="worker-1")
        session.commit()
        context = WorkflowExecutionContext.for_workflow(
            repository, workflow_id, worker_id="worker-1", lease_seconds=300
        )
        context.begin_compute()
        context.progress(
            stage="parse_upload",
            message="Parsing upload.",
            progress_current=1,
            progress_total=3,
        )
        with Session(env.engine) as reader:
            visible = reader.get(app_models.WorkflowRun, workflow_id)
            assert visible.current_stage == "parse_upload"
            assert visible.progress_current == 1
        context.begin_publication()
        context.output(result={"schema_version": "workflow-result-ref.v2"})
        context.artifact(artifact_kind="upload", artifact_id="upload-1")
        context.succeed(result={"schema_version": "workflow-result-ref.v2"})
        with Session(env.engine) as reader:
            assert reader.get(app_models.WorkflowRun, workflow_id).status == "running"
        session.commit()
        with Session(env.engine) as reader:
            visible = reader.get(app_models.WorkflowRun, workflow_id)
            assert visible.status == "succeeded"
            assert visible.result_ref_json == {"schema_version": "workflow-result-ref.v2"}
            assert visible.artifact_refs_json == [{"kind": "upload", "id": "upload-1"}]

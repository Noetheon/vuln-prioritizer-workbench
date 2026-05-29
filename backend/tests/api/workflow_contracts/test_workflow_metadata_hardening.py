from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any

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
from app.services.run_workflow_metadata import (
    merge_error_payload,
    merge_summary_payload,
    public_workflow_fields,
    redacted_workflow_error_or_none,
    redacted_workflow_error_payload,
    redacted_workflow_summary,
    redacted_workflow_summary_payload,
    set_workflow_error,
    set_workflow_summary,
    update_workflow_error,
    update_workflow_summary,
    workflow_error_or_none,
    workflow_error_payload,
    workflow_error_payload_or_empty,
    workflow_import_job,
    workflow_import_job_payload,
    workflow_summary_payload,
    workflow_summary_payload_or_empty,
)
from app.services.workflow_execution import (
    WorkflowCancellationRequested,
    WorkflowExecutionContext,
)
from app.services.workflows import latest_analysis_workflow_public, latest_report_workflow_public


def test_v2_workflow_metadata_projects_typed_result_and_diagnostics(
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
            filename="workflow-v2-cves.txt",
            status=app_models.AnalysisRunStatus.FAILED,
        )
        workflow_repo = workbench_api_env.repositories.WorkflowRepository(session)
        workflow = workflow_repo.create_workflow_run(
            kind=app_models.WorkflowRunKind.IMPORT,
            title="Import cve-list",
            handler="app.services.import_execution.execute_project_import_upload",
            project_id=run.project_id,
            analysis_run_id=run.id,
            execution_mode="worker",
            current_stage="queued",
        )
        workflow_repo.finish_workflow(
            workflow.id,
            status=app_models.WorkflowRunStatus.FAILED,
            stage="provider_update",
            message="Provider cache replay failed.",
            result_json={
                "schema_version": "workflow-run-v2",
                "created_findings": 3,
                "updated_findings": 1,
                "finding_count": 3,
                "provider_snapshot_id": str(snapshot.id),
            },
            diagnostics_json={
                "analysis_error": {
                    "message": "Provider cache replay failed.",
                    "stage": "provider_update",
                    "error_type": "ProviderUpdateError",
                },
                "provider_error_code": "cache-replay-failed",
            },
            terminal_code="provider_update_failed",
        )
        run_id = str(run.id)
        session.commit()

    detail_response = workbench_api_env.client.get(f"/api/v1/runs/{run_id}", headers=headers)
    assert detail_response.status_code == 200, detail_response.text
    detail = detail_response.json()
    assert_no_raw_workflow_fields(detail)
    assert detail["workflow"]["status"] == "failed"
    assert detail["result"]["schema_version"] == "workflow-run-v2"
    assert detail["counts"]["created_findings"] == 3
    assert detail["diagnostics"]["analysis_error"]["stage"] == "provider_update"

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
    assert summary["workflow"]["status"] == "failed"
    assert summary["result"]["schema_version"] == "workflow-run-v2"
    assert summary["result"]["created_findings"] == 3

    metadata = workflow_metadata(workbench_api_env, run_id, headers=headers)
    assert metadata["summary"]["schema_version"] == "workflow-run-v2"
    assert metadata["error"]["provider_error_code"] == "cache-replay-failed"
    assert "raw_summary" not in metadata
    assert "raw_error" not in metadata


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
        )
        workflow_repo = workbench_api_env.repositories.WorkflowRepository(session)
        workflow = workflow_repo.create_workflow_run(
            kind=app_models.WorkflowRunKind.IMPORT,
            title="Import cve-list",
            handler="app.services.import_execution.execute_project_import_upload",
            project_id=run.project_id,
            analysis_run_id=run.id,
            execution_mode="worker",
            current_stage="queued",
        )
        workflow_repo.finish_workflow(
            workflow.id,
            status=app_models.WorkflowRunStatus.FAILED,
            stage="background_import",
            message="Background import failed.",
            result_json={
                "input_upload": {
                    "input_type": "cve-list",
                    "path": str(private_upload),
                    "sha256": "sha256:redacted-input",
                },
                "token": "Bearer summary-secret-token",
            },
            diagnostics_json={
                "background_error": {
                    "message": f"background import failed at {private_log}",
                    "stage": "background_import",
                    "error_type": "RuntimeError",
                },
                "authorization": "Bearer error-secret-token",
            },
            terminal_code="background_failed",
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
    assert metadata["error"]["authorization"] == "[REDACTED]"
    assert "raw_summary" not in metadata
    assert "raw_error" not in metadata


def test_workflow_metadata_access_layer_rejects_invalid_persisted_summary() -> None:
    with pytest.raises(ValidationError):
        workflow_summary_payload({"created_findings": {"not": "an integer"}})


def test_latest_workflow_public_helpers_return_none_without_workflow(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    with Session(workbench_api_env.engine) as session:
        assert latest_analysis_workflow_public(session, analysis_run_id=uuid.uuid4()) is None
        assert latest_report_workflow_public(session, report_id=uuid.uuid4()) is None


def test_run_workflow_metadata_helpers_project_v2_payloads(tmp_path: Path) -> None:
    private_upload = tmp_path / "private" / "upload.csv"
    private_log = tmp_path / "private" / "workflow-error.log"
    import_job = {
        "id": "job-1",
        "status": "failed",
        "execution_mode": "worker",
        "updated_at": "2026-05-29T09:00:00Z",
        "status_history": [{"status": "queued", "created_at": "2026-05-29T08:59:00Z"}],
    }
    result = {
        "input_upload": {
            "input_type": "cve-list",
            "path": str(private_upload),
            "sha256": "sha256:input",
        },
        "import_job": import_job,
        "created_findings": 2,
        "parse_errors": [
            {
                "input_type": "cve-list",
                "filename": "cves.txt",
                "message": "Invalid CVE row.",
                "error_type": "ImporterParseError",
            },
        ],
    }
    diagnostics = {
        "import_job": {**import_job, "status": "failed"},
        "analysis_error": {
            "message": f"Failed while reading {private_log}",
            "stage": "analysis",
            "error_type": "RuntimeError",
        },
        "ignored_lines": 1,
    }

    assert workflow_summary_payload_or_empty(None) == {}
    assert workflow_error_payload_or_empty(None) == {}
    assert workflow_error_or_none(None) is None
    assert workflow_summary_payload(result)["created_findings"] == 2
    assert workflow_error_payload(diagnostics)["analysis_error"]["stage"] == "analysis"
    assert workflow_error_payload_or_empty(diagnostics)["ignored_lines"] == 1

    assert workflow_import_job(result).id == "job-1"
    assert workflow_import_job(None, diagnostics).status == "failed"
    assert workflow_import_job_payload(None, diagnostics)["status"] == "failed"
    assert workflow_import_job_payload(None, None) is None
    public_fields = public_workflow_fields(result, diagnostics)
    assert public_fields["import_job"].id == "job-1"
    assert public_fields["analysis_error"].stage == "analysis"

    assert redacted_workflow_summary(result).input_upload.path == "[REDACTED]"
    assert redacted_workflow_summary_payload(result)["input_upload"]["path"] == "[REDACTED]"
    redacted_error = redacted_workflow_error_or_none(diagnostics)
    assert redacted_error is not None
    assert redacted_error.analysis_error is not None
    assert redacted_error.analysis_error.message == "[REDACTED]"
    assert redacted_workflow_error_payload(diagnostics)["analysis_error"]["message"] == "[REDACTED]"

    assert set_workflow_summary(None, created_findings=4)["created_findings"] == 4
    assert update_workflow_summary(result, ignored_lines=3)["ignored_lines"] == 3
    assert merge_summary_payload(result, updated_findings=5)["updated_findings"] == 5
    assert set_workflow_error(None, created_findings=1)["created_findings"] == 1
    assert update_workflow_error(diagnostics, updated_findings=2)["updated_findings"] == 2
    assert merge_error_payload(diagnostics, ignored_lines=4)["ignored_lines"] == 4


def test_workflow_execution_context_covers_v2_lifecycle_edges() -> None:
    workflow = _workflow(status=app_models.WorkflowRunStatus.RUNNING, locked_by="worker-1")
    repository = _FakeWorkflowRepository(workflow)
    context = WorkflowExecutionContext.for_workflow(
        repository,
        workflow.id,
        worker_id="worker-1",
        lease_seconds=0,
    )

    assert (
        context.progress(
            stage="parse_upload",
            message="Parsing upload.",
            progress_current=1,
            progress_total=3,
            details={"input_type": "cve-list"},
        ).stage
        == "parse_upload"
    )
    assert repository.heartbeat_lease_seconds == [1]
    assert context.output(
        result={"created_findings": 2},
        diagnostics={"warning": "partial"},
        artifact_refs=[{"kind": "upload", "id": "upload-1"}],
        details={"checkpoint": "parsed"},
    ).result_json == {"created_findings": 2}
    assert (
        context.artifact(
            artifact_kind="report",
            artifact_id="report-1",
            report_id=uuid.uuid4(),
            details={"format": "markdown"},
        ).artifact_kind
        == "report"
    )
    assert (
        context.succeed(
            stage="succeeded",
            message="Done.",
            progress_current=3,
            progress_total=3,
            result={"created_findings": 2},
            diagnostics={"warning": "partial"},
            details={"finished": True},
            terminal_code="import_succeeded",
        ).terminal_code
        == "import_succeeded"
    )

    no_worker_context = WorkflowExecutionContext.for_workflow(repository, workflow.id)
    assert no_worker_context.heartbeat() is None
    workflow.status = app_models.WorkflowRunStatus.RUNNING
    workflow.locked_by = "other-worker"
    assert context.heartbeat() is None

    cancellable = _workflow(
        status=app_models.WorkflowRunStatus.RUNNING,
        locked_by="worker-2",
        current_stage="provider_update",
        cancellation_requested=True,
    )
    cancellation_repository = _FakeWorkflowRepository(cancellable)
    cancellation_context = WorkflowExecutionContext.for_workflow(
        cancellation_repository,
        cancellable.id,
        worker_id="worker-2",
    )
    with pytest.raises(WorkflowCancellationRequested):
        cancellation_context.check_cancelled()
    assert cancellable.status == app_models.WorkflowRunStatus.CANCELLED
    assert cancellable.terminal_code == "cancelled"
    assert cancellable.diagnostics_json["stage"] == "provider_update"

    requested = _workflow(status=app_models.WorkflowRunStatus.RUNNING, locked_by="worker-3")
    cancel_repository = _FakeWorkflowRepository(requested)
    cancel_context = WorkflowExecutionContext.for_workflow(
        cancel_repository,
        requested.id,
        worker_id="worker-3",
    )
    assert (
        cancel_context.cancel(message="Stop requested.").status
        == app_models.WorkflowRunStatus.CANCELLED
    )
    assert cancel_context.cancel(message="Stop requested.") is requested


def _workflow(
    *,
    status: app_models.WorkflowRunStatus,
    locked_by: str | None = None,
    current_stage: str | None = None,
    cancellation_requested: bool = False,
) -> app_models.WorkflowRun:
    return app_models.WorkflowRun(
        id=uuid.uuid4(),
        kind=app_models.WorkflowRunKind.IMPORT,
        status=status,
        title="Import cve-list",
        handler="app.services.import_execution.execute_project_import_upload",
        execution_mode="worker",
        locked_by=locked_by,
        current_stage=current_stage,
        cancellation_requested=cancellation_requested,
    )


class _FakeWorkflowRepository:
    def __init__(self, workflow: app_models.WorkflowRun) -> None:
        self.workflow = workflow
        self.events: list[app_models.WorkflowEvent] = []
        self.heartbeat_lease_seconds: list[int] = []

    def require_workflow(self, workflow_id: uuid.UUID) -> app_models.WorkflowRun:
        assert workflow_id == self.workflow.id
        return self.workflow

    def record_worker_heartbeat(
        self,
        workflow_id: uuid.UUID,
        *,
        worker_id: str,
        lease_seconds: int,
    ) -> app_models.WorkflowRun:
        assert workflow_id == self.workflow.id
        assert worker_id == self.workflow.locked_by
        self.heartbeat_lease_seconds.append(lease_seconds)
        return self.workflow

    def record_stage(
        self,
        workflow_id: uuid.UUID,
        *,
        stage: str,
        message: str,
        progress_current: int | None,
        progress_total: int | None,
        metadata_json: dict[str, Any] | None,
    ) -> app_models.WorkflowEvent:
        assert workflow_id == self.workflow.id
        self.workflow.current_stage = stage
        self.workflow.progress_current = progress_current or 0
        self.workflow.progress_total = progress_total
        self.workflow.metadata_json.update(metadata_json or {})
        return self._event(
            app_models.WorkflowEventType.STAGE,
            stage=stage,
            message=message,
            progress_current=progress_current,
            progress_total=progress_total,
            metadata_json=metadata_json,
        )

    def attach_artifact(
        self,
        workflow_id: uuid.UUID,
        *,
        artifact_kind: str,
        artifact_id: str,
        report_id: uuid.UUID | None,
        metadata_json: dict[str, Any] | None,
    ) -> app_models.WorkflowEvent:
        assert workflow_id == self.workflow.id
        self.workflow.report_id = report_id
        self.workflow.artifact_refs_json.append({"kind": artifact_kind, "id": artifact_id})
        return self._event(
            app_models.WorkflowEventType.ARTIFACT,
            artifact_kind=artifact_kind,
            artifact_id=artifact_id,
            metadata_json=metadata_json,
        )

    def set_workflow_output(
        self,
        workflow_id: uuid.UUID,
        *,
        result_json: dict[str, Any] | None,
        diagnostics_json: dict[str, Any] | None,
        artifact_refs_json: list[dict[str, Any]] | None,
        metadata_json: dict[str, Any] | None,
    ) -> app_models.WorkflowRun:
        assert workflow_id == self.workflow.id
        self.workflow.result_json = result_json or {}
        self.workflow.diagnostics_json = diagnostics_json or {}
        self.workflow.artifact_refs_json = artifact_refs_json or []
        self.workflow.metadata_json.update(metadata_json or {})
        return self.workflow

    def finish_workflow(
        self,
        workflow_id: uuid.UUID,
        *,
        status: app_models.WorkflowRunStatus,
        stage: str,
        message: str | None,
        progress_current: int | None = None,
        progress_total: int | None = None,
        result_json: dict[str, Any] | None = None,
        diagnostics_json: dict[str, Any] | None = None,
        error_message: str | None = None,
        error_json: dict[str, Any] | None = None,
        terminal_code: str | None = None,
        metadata_json: dict[str, Any] | None = None,
    ) -> app_models.WorkflowRun:
        assert workflow_id == self.workflow.id
        self.workflow.status = status
        self.workflow.current_stage = stage
        self.workflow.progress_current = progress_current or self.workflow.progress_current
        self.workflow.progress_total = progress_total
        self.workflow.result_json = result_json or self.workflow.result_json
        self.workflow.diagnostics_json = (
            diagnostics_json or error_json or self.workflow.diagnostics_json
        )
        self.workflow.error_message = error_message or message
        self.workflow.terminal_code = terminal_code
        self.workflow.metadata_json.update(metadata_json or {})
        return self.workflow

    def request_cancel(self, workflow_id: uuid.UUID, *, message: str) -> app_models.WorkflowRun:
        assert workflow_id == self.workflow.id
        if self.workflow.status != app_models.WorkflowRunStatus.CANCELLED:
            self.workflow.cancellation_requested = True
            self.workflow.error_message = message
        return self.workflow

    def cancel_if_requested(
        self, workflow_id: uuid.UUID, *, message: str
    ) -> app_models.WorkflowRun | None:
        assert workflow_id == self.workflow.id
        if not self.workflow.cancellation_requested:
            return None
        return self.finish_workflow(
            workflow_id,
            status=app_models.WorkflowRunStatus.CANCELLED,
            stage="cancelled",
            message=message,
            diagnostics_json={"stage": self.workflow.current_stage or "cancelled"},
            terminal_code="cancelled",
        )

    def _event(
        self,
        event_type: app_models.WorkflowEventType,
        *,
        stage: str | None = None,
        message: str | None = None,
        progress_current: int | None = None,
        progress_total: int | None = None,
        artifact_kind: str | None = None,
        artifact_id: str | None = None,
        metadata_json: dict[str, Any] | None = None,
    ) -> app_models.WorkflowEvent:
        event = app_models.WorkflowEvent(
            workflow_run_id=self.workflow.id,
            sequence=len(self.events) + 1,
            event_type=event_type,
            status=self.workflow.status,
            stage=stage,
            message=message,
            progress_current=progress_current,
            progress_total=progress_total,
            artifact_kind=artifact_kind,
            artifact_id=artifact_id,
            metadata_json=metadata_json or {},
        )
        self.events.append(event)
        return event

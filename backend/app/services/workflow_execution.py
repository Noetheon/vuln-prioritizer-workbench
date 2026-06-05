"""Central execution context for v2 durable Workbench workflows."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any

from app.models import WorkflowEvent, WorkflowRun, WorkflowRunStatus
from app.repositories import WorkflowRepository


class WorkflowCancellationRequested(RuntimeError):
    """Raised when cooperative workflow cancellation has been requested."""


@dataclass(slots=True)
class WorkflowExecutionContext:
    """Small v2 API used by workflow handlers and long-running services."""

    repository: WorkflowRepository
    workflow_id: uuid.UUID
    worker_id: str | None = None
    lease_seconds: int = 300

    @classmethod
    def for_workflow(
        cls,
        repository: WorkflowRepository,
        workflow_id: uuid.UUID,
        *,
        worker_id: str | None = None,
        lease_seconds: int = 300,
    ) -> WorkflowExecutionContext:
        """Construct a context for one persisted workflow."""
        return cls(
            repository=repository,
            workflow_id=workflow_id,
            worker_id=worker_id,
            lease_seconds=max(1, lease_seconds),
        )

    def workflow(self) -> WorkflowRun:
        """Return the current workflow row."""
        return self.repository.require_workflow(self.workflow_id)

    def start(
        self,
        *,
        stage: str,
        message: str | None = None,
        progress_current: int | None = None,
        progress_total: int | None = None,
        details: dict[str, Any] | None = None,
    ) -> WorkflowRun:
        """Start the workflow and extend the lease first when worker-owned."""
        self.heartbeat()
        workflow = self.repository.start_workflow(
            self.workflow_id,
            stage=stage,
            message=message,
            progress_current=progress_current,
            progress_total=progress_total,
            metadata_json=details,
        )
        self.check_cancelled()
        return workflow

    def stage(
        self,
        stage: str,
        message: str,
        *,
        progress_current: int | None = None,
        progress_total: int | None = None,
        details: dict[str, Any] | None = None,
    ) -> WorkflowEvent:
        """Record a stage transition and check cancellation."""
        self.heartbeat()
        event = self.repository.record_stage(
            self.workflow_id,
            stage=stage,
            message=message,
            progress_current=progress_current,
            progress_total=progress_total,
            metadata_json=details,
        )
        self.check_cancelled()
        return event

    def progress(
        self,
        *,
        stage: str,
        message: str,
        progress_current: int,
        progress_total: int | None = None,
        details: dict[str, Any] | None = None,
    ) -> WorkflowEvent:
        """Record progress without a separate feature-level status path."""
        return self.stage(
            stage,
            message,
            progress_current=progress_current,
            progress_total=progress_total,
            details=details,
        )

    def heartbeat(self) -> WorkflowRun | None:
        """Renew the worker lease when this context owns one."""
        if self.worker_id is None:
            return None
        workflow = self.workflow()
        if workflow.locked_by != self.worker_id or workflow.status != WorkflowRunStatus.RUNNING:
            return None
        return self.repository.record_worker_heartbeat(
            self.workflow_id,
            worker_id=self.worker_id,
            lease_seconds=self.lease_seconds,
        )

    def check_cancelled(self) -> None:
        """Raise after making cancellation terminal when requested."""
        workflow = self.workflow()
        if not workflow.cancellation_requested:
            return
        self.repository.finish_workflow(
            self.workflow_id,
            status=WorkflowRunStatus.CANCELLED,
            stage="cancelled",
            message="Workflow cancelled by user request.",
            diagnostics_json={
                "stage": workflow.current_stage or "cancelled",
                "error_type": "WorkflowCancellationRequested",
            },
            terminal_code="cancelled",
            metadata_json={"cooperative_cancel": True},
        )
        raise WorkflowCancellationRequested("Workflow cancelled by user request.")

    def artifact(
        self,
        *,
        artifact_kind: str,
        artifact_id: str,
        report_id: uuid.UUID | None = None,
        details: dict[str, Any] | None = None,
    ) -> WorkflowEvent:
        """Record an artifact and keep v2 artifact refs in sync."""
        self.heartbeat()
        event = self.repository.attach_artifact(
            self.workflow_id,
            artifact_kind=artifact_kind,
            artifact_id=artifact_id,
            report_id=report_id,
            metadata_json=details,
        )
        self.check_cancelled()
        return event

    def output(
        self,
        *,
        result: dict[str, Any] | None = None,
        diagnostics: dict[str, Any] | None = None,
        artifact_refs: list[dict[str, Any]] | None = None,
        details: dict[str, Any] | None = None,
    ) -> WorkflowRun:
        """Persist non-terminal v2 workflow output fields."""
        self.heartbeat()
        workflow = self.repository.set_workflow_output(
            self.workflow_id,
            result_ref_json=result,
            diagnostics_json=diagnostics,
            artifact_refs_json=artifact_refs,
            metadata_json=details,
        )
        self.check_cancelled()
        return workflow

    def succeed(
        self,
        *,
        stage: str = "succeeded",
        message: str | None = None,
        progress_current: int | None = None,
        progress_total: int | None = None,
        result: dict[str, Any] | None = None,
        diagnostics: dict[str, Any] | None = None,
        details: dict[str, Any] | None = None,
        terminal_code: str = "succeeded",
    ) -> WorkflowRun:
        """Finish the workflow successfully with v2 output."""
        self.heartbeat()
        return self.repository.finish_workflow(
            self.workflow_id,
            status=WorkflowRunStatus.SUCCEEDED,
            stage=stage,
            message=message,
            progress_current=progress_current,
            progress_total=progress_total,
            result_ref_json=result,
            diagnostics_json=diagnostics,
            terminal_code=terminal_code,
            metadata_json=details,
        )

    def fail(
        self,
        *,
        stage: str,
        message: str,
        progress_current: int | None = None,
        progress_total: int | None = None,
        diagnostics: dict[str, Any] | None = None,
        details: dict[str, Any] | None = None,
        terminal_code: str = "failed",
    ) -> WorkflowRun:
        """Finish the workflow as failed with diagnostics."""
        self.heartbeat()
        return self.repository.finish_workflow(
            self.workflow_id,
            status=WorkflowRunStatus.FAILED,
            stage=stage,
            message=message,
            progress_current=progress_current,
            progress_total=progress_total,
            error_message=message,
            error_json=diagnostics,
            diagnostics_json=diagnostics,
            terminal_code=terminal_code,
            metadata_json=details,
        )

    def cancel(
        self,
        *,
        message: str = "Workflow cancelled.",
    ) -> WorkflowRun | None:
        """Request or finish cancellation for the workflow."""
        workflow = self.repository.request_cancel(self.workflow_id, message=message)
        if workflow.status == WorkflowRunStatus.CANCELLED:
            return workflow
        return self.repository.cancel_if_requested(self.workflow_id, message=message)

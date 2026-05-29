"""Durable workflow repository helpers."""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import datetime, timedelta
from typing import Any

from sqlmodel import Session, col, func, select

from app.models import (
    WorkflowEvent,
    WorkflowEventType,
    WorkflowRun,
    WorkflowRunKind,
    WorkflowRunStatus,
)
from app.models.base import get_datetime_utc
from vuln_prioritizer.security_redaction import redact_value


def _public_payload(payload: dict[str, Any] | None) -> dict[str, Any]:
    redacted, _paths = redact_value(payload or {})
    return redacted if isinstance(redacted, dict) else {}


def _internal_payload(payload: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return {}
    return dict(payload)


def _workflow_status(value: WorkflowRunStatus | str) -> WorkflowRunStatus:
    if isinstance(value, WorkflowRunStatus):
        return value
    return WorkflowRunStatus(value)


def _workflow_kind(value: WorkflowRunKind | str) -> WorkflowRunKind:
    if isinstance(value, WorkflowRunKind):
        return value
    return WorkflowRunKind(value)


def _workflow_event_type(value: WorkflowEventType | str) -> WorkflowEventType:
    if isinstance(value, WorkflowEventType):
        return value
    return WorkflowEventType(value)


class WorkflowRepository:
    """Persist workflow runs and append-only workflow events."""

    def __init__(self, session: Session) -> None:
        """Initialize a workflow repository."""
        self.session = session

    def create_workflow_run(
        self,
        *,
        kind: WorkflowRunKind | str,
        title: str,
        handler: str,
        project_id: uuid.UUID | None = None,
        analysis_run_id: uuid.UUID | None = None,
        report_id: uuid.UUID | None = None,
        parent_workflow_run_id: uuid.UUID | None = None,
        status: WorkflowRunStatus | str = WorkflowRunStatus.PENDING,
        execution_mode: str = "request",
        idempotency_key: str | None = None,
        queue_name: str = "default",
        priority: int = 0,
        current_stage: str | None = None,
        progress_current: int = 0,
        progress_total: int | None = None,
        metadata_json: dict[str, Any] | None = None,
        payload_json: dict[str, Any] | None = None,
        max_retries: int = 0,
    ) -> WorkflowRun:
        """Create a durable workflow run and its initial event."""
        workflow = WorkflowRun(
            kind=_workflow_kind(kind),
            status=_workflow_status(status),
            title=title,
            handler=handler,
            execution_mode=execution_mode,
            project_id=project_id,
            analysis_run_id=analysis_run_id,
            report_id=report_id,
            parent_workflow_run_id=parent_workflow_run_id,
            idempotency_key=idempotency_key,
            queue_name=queue_name,
            priority=priority,
            current_stage=current_stage,
            progress_current=progress_current,
            progress_total=progress_total,
            metadata_json=_public_payload(metadata_json),
            payload_json=_internal_payload(payload_json),
            max_retries=max_retries,
        )
        self.session.add(workflow)
        self.session.flush()
        self.record_event(
            workflow.id,
            event_type=WorkflowEventType.CREATED,
            status=workflow.status,
            stage=current_stage,
            message=f"{workflow.title} workflow created.",
            progress_current=progress_current,
            progress_total=progress_total,
            metadata_json={"execution_mode": execution_mode},
        )
        return workflow

    def ensure_analysis_workflow(
        self,
        *,
        kind: WorkflowRunKind | str,
        analysis_run_id: uuid.UUID,
        title: str,
        handler: str,
        project_id: uuid.UUID | None,
        status: WorkflowRunStatus | str,
        execution_mode: str,
        current_stage: str | None = None,
        metadata_json: dict[str, Any] | None = None,
        payload_json: dict[str, Any] | None = None,
        max_retries: int | None = None,
        queue_name: str | None = None,
    ) -> WorkflowRun:
        """Return an existing workflow for an analysis run, or create one."""
        existing = self.get_latest_analysis_workflow(
            analysis_run_id=analysis_run_id,
            kind=kind,
        )
        if existing is not None:
            changed = False
            for attr, value in (
                ("project_id", project_id),
                ("execution_mode", execution_mode),
                ("handler", handler),
            ):
                if getattr(existing, attr) != value:
                    setattr(existing, attr, value)
                    changed = True
            if metadata_json:
                merged_metadata = {**dict(existing.metadata_json or {}), **metadata_json}
                existing.metadata_json = _public_payload(merged_metadata)
                changed = True
            if current_stage and existing.current_stage != current_stage:
                existing.current_stage = current_stage
                changed = True
            if payload_json is not None:
                existing.payload_json = _internal_payload(payload_json)
                changed = True
            if max_retries is not None and existing.max_retries != max_retries:
                existing.max_retries = max_retries
                changed = True
            if queue_name is not None and existing.queue_name != queue_name:
                existing.queue_name = queue_name
                changed = True
            if changed:
                existing.updated_at = get_datetime_utc()
                self.session.add(existing)
                self.session.flush()
            return existing
        return self.create_workflow_run(
            kind=kind,
            title=title,
            handler=handler,
            project_id=project_id,
            analysis_run_id=analysis_run_id,
            status=status,
            execution_mode=execution_mode,
            current_stage=current_stage,
            metadata_json=metadata_json,
            payload_json=payload_json,
            max_retries=max_retries or 0,
            queue_name=queue_name or "default",
        )

    def start_workflow(
        self,
        workflow_id: uuid.UUID,
        *,
        stage: str,
        message: str | None = None,
        progress_current: int | None = None,
        progress_total: int | None = None,
        metadata_json: dict[str, Any] | None = None,
    ) -> WorkflowRun:
        """Mark a workflow running and append a start event."""
        workflow = self.require_workflow(workflow_id)
        now = get_datetime_utc()
        workflow.status = WorkflowRunStatus.RUNNING
        workflow.current_stage = stage
        workflow.started_at = workflow.started_at or now
        workflow.updated_at = now
        if progress_current is not None:
            workflow.progress_current = progress_current
        if progress_total is not None:
            workflow.progress_total = progress_total
        self.session.add(workflow)
        self.session.flush()
        self.record_event(
            workflow.id,
            event_type=WorkflowEventType.STARTED,
            status=workflow.status,
            stage=stage,
            message=message or f"{workflow.title} workflow started.",
            progress_current=workflow.progress_current,
            progress_total=workflow.progress_total,
            metadata_json=metadata_json,
        )
        return workflow

    def record_stage(
        self,
        workflow_id: uuid.UUID,
        *,
        stage: str,
        message: str,
        progress_current: int | None = None,
        progress_total: int | None = None,
        metadata_json: dict[str, Any] | None = None,
    ) -> WorkflowEvent:
        """Record a workflow stage/progress event and update latest state."""
        workflow = self.require_workflow(workflow_id)
        workflow.current_stage = stage
        workflow.updated_at = get_datetime_utc()
        if progress_current is not None:
            workflow.progress_current = progress_current
        if progress_total is not None:
            workflow.progress_total = progress_total
        self.session.add(workflow)
        self.session.flush()
        return self.record_event(
            workflow.id,
            event_type=WorkflowEventType.STAGE,
            status=workflow.status,
            stage=stage,
            message=message,
            progress_current=workflow.progress_current,
            progress_total=workflow.progress_total,
            metadata_json=metadata_json,
        )

    def attach_artifact(
        self,
        workflow_id: uuid.UUID,
        *,
        artifact_kind: str,
        artifact_id: str,
        report_id: uuid.UUID | None = None,
        metadata_json: dict[str, Any] | None = None,
    ) -> WorkflowEvent:
        """Attach a generated artifact to a workflow."""
        workflow = self.require_workflow(workflow_id)
        if report_id is not None:
            workflow.report_id = report_id
            workflow.updated_at = get_datetime_utc()
            self.session.add(workflow)
            self.session.flush()
        return self.record_event(
            workflow.id,
            event_type=WorkflowEventType.ARTIFACT,
            status=workflow.status,
            stage=workflow.current_stage,
            message=f"{artifact_kind} artifact recorded.",
            artifact_kind=artifact_kind,
            artifact_id=artifact_id,
            metadata_json=metadata_json,
        )

    def finish_workflow(
        self,
        workflow_id: uuid.UUID,
        *,
        status: WorkflowRunStatus | str,
        stage: str,
        message: str | None = None,
        progress_current: int | None = None,
        progress_total: int | None = None,
        error_message: str | None = None,
        error_json: dict[str, Any] | None = None,
        metadata_json: dict[str, Any] | None = None,
    ) -> WorkflowRun:
        """Mark a workflow terminal and append the terminal event."""
        terminal_status = _workflow_status(status)
        workflow = self.require_workflow(workflow_id)
        now = get_datetime_utc()
        workflow.status = terminal_status
        workflow.current_stage = stage
        workflow.finished_at = workflow.finished_at or now
        workflow.updated_at = now
        workflow.locked_by = None
        workflow.locked_at = None
        workflow.lease_expires_at = None
        workflow.last_heartbeat_at = None
        workflow.attempt_started_at = None
        workflow.next_retry_at = None
        if progress_current is not None:
            workflow.progress_current = progress_current
        if progress_total is not None:
            workflow.progress_total = progress_total
        if error_message is not None:
            workflow.error_message = error_message
        if error_json is not None:
            workflow.error_details_json = _public_payload(error_json)
        if metadata_json:
            workflow.metadata_json = _public_payload(
                {**dict(workflow.metadata_json or {}), **metadata_json}
            )
        self.session.add(workflow)
        self.session.flush()
        self.record_event(
            workflow.id,
            event_type=_terminal_event_type(terminal_status),
            status=workflow.status,
            stage=stage,
            message=message or _terminal_message(workflow, terminal_status),
            progress_current=workflow.progress_current,
            progress_total=workflow.progress_total,
            metadata_json=metadata_json,
        )
        return workflow

    def record_event(
        self,
        workflow_id: uuid.UUID,
        *,
        event_type: WorkflowEventType | str,
        status: WorkflowRunStatus | str,
        stage: str | None = None,
        message: str | None = None,
        progress_current: int | None = None,
        progress_total: int | None = None,
        artifact_kind: str | None = None,
        artifact_id: str | None = None,
        metadata_json: dict[str, Any] | None = None,
    ) -> WorkflowEvent:
        """Append one event to a workflow."""
        event = WorkflowEvent(
            workflow_run_id=workflow_id,
            sequence=self._next_event_sequence(workflow_id),
            event_type=_workflow_event_type(event_type),
            status=_workflow_status(status),
            stage=stage,
            message=message,
            progress_current=progress_current,
            progress_total=progress_total,
            artifact_kind=artifact_kind,
            artifact_id=artifact_id,
            metadata_json=_public_payload(metadata_json),
        )
        self.session.add(event)
        self.session.flush()
        return event

    def set_workflow_payload(
        self,
        workflow_id: uuid.UUID,
        *,
        payload_json: dict[str, Any],
        queue_name: str | None = None,
        max_retries: int | None = None,
        priority: int | None = None,
    ) -> WorkflowRun:
        """Update private worker payload and queue metadata for a workflow."""
        workflow = self.require_workflow(workflow_id)
        workflow.payload_json = _internal_payload(payload_json)
        if queue_name is not None:
            workflow.queue_name = queue_name
        if max_retries is not None:
            workflow.max_retries = max_retries
        if priority is not None:
            workflow.priority = priority
        workflow.updated_at = get_datetime_utc()
        self.session.add(workflow)
        self.session.flush()
        return workflow

    def claim_due_workflows(
        self,
        *,
        worker_id: str,
        queue_names: Sequence[str] = ("default",),
        lease_seconds: int = 300,
        limit: int = 1,
        now: datetime | None = None,
    ) -> list[WorkflowRun]:
        """Claim due pending workflows for one worker."""
        ready_at = now or get_datetime_utc()
        queues = tuple(queue_names) or ("default",)
        statement = (
            select(WorkflowRun)
            .where(
                WorkflowRun.status == WorkflowRunStatus.PENDING,
                col(WorkflowRun.queue_name).in_(queues),
                col(WorkflowRun.cancellation_requested).is_(False),
                (
                    col(WorkflowRun.next_retry_at).is_(None)
                    | (col(WorkflowRun.next_retry_at) <= ready_at)
                ),
            )
            .order_by(
                col(WorkflowRun.priority).desc(),
                col(WorkflowRun.created_at).asc(),
            )
            .limit(max(1, limit))
        )
        if self.session.bind is not None and self.session.bind.dialect.name == "postgresql":
            statement = statement.with_for_update(skip_locked=True)
        workflows = list(self.session.exec(statement).all())
        lease_expires_at = ready_at + timedelta(seconds=max(1, lease_seconds))
        for workflow in workflows:
            workflow.status = WorkflowRunStatus.RUNNING
            workflow.locked_by = worker_id
            workflow.locked_at = ready_at
            workflow.lease_expires_at = lease_expires_at
            workflow.last_heartbeat_at = ready_at
            workflow.attempt_started_at = ready_at
            workflow.started_at = workflow.started_at or ready_at
            workflow.updated_at = ready_at
            workflow.current_stage = workflow.current_stage or "claimed"
            self.session.add(workflow)
            self.session.flush()
            self.record_event(
                workflow.id,
                event_type=WorkflowEventType.STAGE,
                status=workflow.status,
                stage=workflow.current_stage,
                message=f"Workflow claimed by worker {worker_id}.",
                metadata_json={"worker_id": worker_id, "queue_name": workflow.queue_name},
            )
        return workflows

    def record_worker_heartbeat(
        self,
        workflow_id: uuid.UUID,
        *,
        worker_id: str,
        lease_seconds: int,
        now: datetime | None = None,
    ) -> WorkflowRun:
        """Extend the active worker lease if the same worker still owns it."""
        workflow = self.require_workflow(workflow_id)
        if workflow.locked_by != worker_id:
            raise RuntimeError("Workflow is not locked by this worker.")
        timestamp = now or get_datetime_utc()
        workflow.last_heartbeat_at = timestamp
        workflow.lease_expires_at = timestamp + timedelta(seconds=max(1, lease_seconds))
        workflow.updated_at = timestamp
        self.session.add(workflow)
        self.session.flush()
        return workflow

    def request_cancel(
        self,
        workflow_id: uuid.UUID,
        *,
        message: str | None = None,
    ) -> WorkflowRun:
        """Request cooperative cancellation or cancel a pending workflow immediately."""
        workflow = self.require_workflow(workflow_id)
        if _is_terminal_status(workflow.status):
            return workflow
        workflow.cancellation_requested = True
        workflow.updated_at = get_datetime_utc()
        self.session.add(workflow)
        self.session.flush()
        if workflow.status == WorkflowRunStatus.PENDING:
            return self.finish_workflow(
                workflow.id,
                status=WorkflowRunStatus.CANCELLED,
                stage="cancelled",
                message=message or "Workflow cancelled before execution.",
                metadata_json={"cancelled_before_start": True},
            )
        self.record_event(
            workflow.id,
            event_type=WorkflowEventType.STAGE,
            status=workflow.status,
            stage=workflow.current_stage,
            message=message or "Cancellation requested.",
            metadata_json={"cancellation_requested": True},
        )
        return workflow

    def cancel_if_requested(
        self,
        workflow_id: uuid.UUID,
        *,
        stage: str = "cancelled",
        message: str = "Workflow cancelled.",
    ) -> WorkflowRun | None:
        """Finish a workflow as cancelled when a cooperative cancel was requested."""
        workflow = self.require_workflow(workflow_id)
        if not workflow.cancellation_requested or _is_terminal_status(workflow.status):
            return None
        return self.finish_workflow(
            workflow.id,
            status=WorkflowRunStatus.CANCELLED,
            stage=stage,
            message=message,
            metadata_json={"cooperative_cancel": True},
        )

    def schedule_retry_or_fail(
        self,
        workflow_id: uuid.UUID,
        *,
        error_message: str,
        error_json: dict[str, Any] | None = None,
        delay_seconds: int = 30,
        now: datetime | None = None,
    ) -> WorkflowRun:
        """Requeue a failed attempt or permanently fail when retries are exhausted."""
        workflow = self.require_workflow(workflow_id)
        if workflow.cancellation_requested:
            return self.finish_workflow(
                workflow.id,
                status=WorkflowRunStatus.CANCELLED,
                stage="cancelled",
                message="Workflow cancelled during execution.",
                metadata_json={"cooperative_cancel": True},
            )
        if workflow.retry_count >= workflow.max_retries:
            return self.finish_workflow(
                workflow.id,
                status=WorkflowRunStatus.FAILED,
                stage="failed",
                message=error_message,
                error_message=error_message,
                error_json=error_json,
            )
        timestamp = now or get_datetime_utc()
        workflow.retry_count += 1
        workflow.status = WorkflowRunStatus.PENDING
        workflow.current_stage = "queued"
        workflow.error_message = error_message
        workflow.error_details_json = _public_payload(error_json)
        workflow.next_retry_at = timestamp + timedelta(seconds=max(0, delay_seconds))
        workflow.updated_at = timestamp
        workflow.locked_by = None
        workflow.locked_at = None
        workflow.lease_expires_at = None
        workflow.last_heartbeat_at = None
        workflow.attempt_started_at = None
        self.session.add(workflow)
        self.session.flush()
        self.record_event(
            workflow.id,
            event_type=WorkflowEventType.RETRY,
            status=workflow.status,
            stage=workflow.current_stage,
            message=(
                f"Workflow attempt failed; retry {workflow.retry_count}/"
                f"{workflow.max_retries} scheduled."
            ),
            metadata_json={
                "error": error_message,
                "next_retry_at": workflow.next_retry_at.isoformat()
                if workflow.next_retry_at
                else None,
            },
        )
        return workflow

    def release_expired_leases(
        self,
        *,
        now: datetime | None = None,
        delay_seconds: int = 0,
    ) -> list[WorkflowRun]:
        """Requeue or fail running workflows whose worker lease expired."""
        timestamp = now or get_datetime_utc()
        statement = select(WorkflowRun).where(
            WorkflowRun.status == WorkflowRunStatus.RUNNING,
            col(WorkflowRun.lease_expires_at).is_not(None),
            col(WorkflowRun.lease_expires_at) <= timestamp,
        )
        expired = list(self.session.exec(statement).all())
        released: list[WorkflowRun] = []
        for workflow in expired:
            released.append(
                self.schedule_retry_or_fail(
                    workflow.id,
                    error_message="Workflow worker lease expired.",
                    error_json={"locked_by": workflow.locked_by},
                    delay_seconds=delay_seconds,
                    now=timestamp,
                )
            )
        return released

    def clone_for_manual_retry(
        self,
        workflow_id: uuid.UUID,
        *,
        idempotency_key: str | None = None,
    ) -> WorkflowRun:
        """Create a new queued workflow using a previous workflow payload."""
        workflow = self.require_workflow(workflow_id)
        return self.create_workflow_run(
            kind=workflow.kind,
            title=workflow.title,
            handler=workflow.handler,
            project_id=workflow.project_id,
            analysis_run_id=workflow.analysis_run_id,
            parent_workflow_run_id=workflow.id,
            status=WorkflowRunStatus.PENDING,
            execution_mode="worker",
            idempotency_key=idempotency_key,
            queue_name=workflow.queue_name,
            priority=workflow.priority,
            current_stage="queued",
            progress_total=workflow.progress_total,
            metadata_json={
                **dict(workflow.metadata_json or {}),
                "manual_retry_of": str(workflow.id),
            },
            payload_json=dict(workflow.payload_json or {}),
            max_retries=workflow.max_retries,
        )

    def require_workflow(self, workflow_id: uuid.UUID) -> WorkflowRun:
        """Return a workflow or raise ``LookupError``."""
        workflow = self.get_workflow(workflow_id)
        if workflow is None:
            raise LookupError(f"WorkflowRun not found: {workflow_id}")
        return workflow

    def get_workflow(self, workflow_id: uuid.UUID) -> WorkflowRun | None:
        """Return a workflow by primary key."""
        return self.session.get(WorkflowRun, workflow_id)

    def get_latest_analysis_workflow(
        self,
        *,
        analysis_run_id: uuid.UUID,
        kind: WorkflowRunKind | str | None = None,
    ) -> WorkflowRun | None:
        """Return the newest workflow linked to an analysis run."""
        filters: list[Any] = [WorkflowRun.analysis_run_id == analysis_run_id]
        if kind is not None:
            filters.append(WorkflowRun.kind == _workflow_kind(kind))
        statement = select(WorkflowRun).where(*filters).order_by(col(WorkflowRun.created_at).desc())
        return self.session.exec(statement).first()

    def get_latest_report_workflow(self, report_id: uuid.UUID) -> WorkflowRun | None:
        """Return the newest workflow linked to a report artifact."""
        statement = (
            select(WorkflowRun)
            .where(WorkflowRun.report_id == report_id)
            .order_by(col(WorkflowRun.created_at).desc())
        )
        return self.session.exec(statement).first()

    def list_project_workflows(
        self,
        project_id: uuid.UUID,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[list[WorkflowRun], int]:
        """Return project workflows newest first."""
        count_statement = (
            select(func.count())
            .select_from(WorkflowRun)
            .where(WorkflowRun.project_id == project_id)
        )
        count = int(self.session.exec(count_statement).one())
        statement = (
            select(WorkflowRun)
            .where(WorkflowRun.project_id == project_id)
            .order_by(col(WorkflowRun.created_at).desc())
            .offset(offset)
            .limit(limit)
        )
        return list(self.session.exec(statement).all()), count

    def list_workflow_events(
        self,
        workflow_id: uuid.UUID,
        *,
        limit: int = 500,
        offset: int = 0,
    ) -> tuple[list[WorkflowEvent], int]:
        """Return workflow events in sequence order."""
        count_statement = (
            select(func.count())
            .select_from(WorkflowEvent)
            .where(WorkflowEvent.workflow_run_id == workflow_id)
        )
        count = int(self.session.exec(count_statement).one())
        statement = (
            select(WorkflowEvent)
            .where(WorkflowEvent.workflow_run_id == workflow_id)
            .order_by(col(WorkflowEvent.sequence).asc())
            .offset(offset)
            .limit(limit)
        )
        return list(self.session.exec(statement).all()), count

    def latest_event(self, workflow_id: uuid.UUID) -> WorkflowEvent | None:
        """Return the newest event for a workflow."""
        statement = (
            select(WorkflowEvent)
            .where(WorkflowEvent.workflow_run_id == workflow_id)
            .order_by(col(WorkflowEvent.sequence).desc())
        )
        return self.session.exec(statement).first()

    def _next_event_sequence(self, workflow_id: uuid.UUID) -> int:
        statement = select(func.max(WorkflowEvent.sequence)).where(
            WorkflowEvent.workflow_run_id == workflow_id
        )
        current = self.session.exec(statement).one()
        return int(current or 0) + 1


def _terminal_event_type(status: WorkflowRunStatus) -> WorkflowEventType:
    if status == WorkflowRunStatus.SUCCEEDED:
        return WorkflowEventType.SUCCEEDED
    if status == WorkflowRunStatus.CANCELLED:
        return WorkflowEventType.CANCELLED
    if status == WorkflowRunStatus.FAILED:
        return WorkflowEventType.FAILED
    return WorkflowEventType.STAGE


def _terminal_message(workflow: WorkflowRun, status: WorkflowRunStatus) -> str:
    if status == WorkflowRunStatus.SUCCEEDED:
        return f"{workflow.title} workflow succeeded."
    if status == WorkflowRunStatus.FAILED:
        return workflow.error_message or f"{workflow.title} workflow failed."
    if status == WorkflowRunStatus.CANCELLED:
        return f"{workflow.title} workflow cancelled."
    return f"{workflow.title} workflow finished with status {status}."


def _is_terminal_status(status: WorkflowRunStatus | str) -> bool:
    return _workflow_status(status) in {
        WorkflowRunStatus.SUCCEEDED,
        WorkflowRunStatus.COMPLETED_WITH_ERRORS,
        WorkflowRunStatus.FAILED,
        WorkflowRunStatus.CANCELLED,
    }

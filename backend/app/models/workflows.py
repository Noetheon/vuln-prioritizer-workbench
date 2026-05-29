"""Durable workflow run and event models."""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlmodel import Field, SQLModel

from app.models.base import get_datetime_utc


class WorkflowRunKind(StrEnum):
    """Durable workflow families owned by the Workbench core."""

    IMPORT = "import"
    PROVIDER_UPDATE = "provider_update"
    REPORT_GENERATION = "report_generation"


class WorkflowRunStatus(StrEnum):
    """Durable workflow lifecycle state."""

    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    COMPLETED_WITH_ERRORS = "completed_with_errors"
    FAILED = "failed"
    CANCELLED = "cancelled"


class WorkflowEventType(StrEnum):
    """Durable workflow event categories."""

    CREATED = "created"
    STARTED = "started"
    STAGE = "stage"
    PROGRESS = "progress"
    ARTIFACT = "artifact"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"
    RETRY = "retry"


class WorkflowRunBase(SQLModel):
    """Shared persisted workflow state."""

    kind: WorkflowRunKind = Field(sa_column=Column(String(80), nullable=False))
    status: WorkflowRunStatus = Field(
        default=WorkflowRunStatus.PENDING,
        sa_column=Column(String(40), nullable=False),
    )
    title: str = Field(max_length=240)
    handler: str = Field(max_length=240)
    execution_mode: str = Field(default="request", max_length=40)
    idempotency_key: str | None = Field(default=None, max_length=160)
    queue_name: str = Field(default="default", max_length=80)
    priority: int = Field(default=0, sa_column=Column(Integer, nullable=False))
    current_stage: str | None = Field(default=None, max_length=120)
    progress_current: int = Field(default=0, sa_column=Column(Integer, nullable=False))
    progress_total: int | None = Field(default=None, sa_column=Column(Integer, nullable=True))
    retry_count: int = Field(default=0, sa_column=Column(Integer, nullable=False))
    max_retries: int = Field(default=0, sa_column=Column(Integer, nullable=False))
    cancellation_requested: bool = Field(default=False, sa_column=Column(Boolean, nullable=False))
    error_message: str | None = Field(default=None, sa_column=Column(Text, nullable=True))
    error_details_json: dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSON, nullable=False),
    )
    metadata_json: dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSON, nullable=False),
    )
    payload_json: dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSON, nullable=False),
    )


class WorkflowRun(WorkflowRunBase, table=True):
    """Durable workflow state for import, provider-refresh, and report work."""

    __tablename__ = "workflow_run"
    __table_args__ = (
        Index("ix_workflow_run_project_created_at", "project_id", "created_at"),
        Index("ix_workflow_run_analysis_run_kind", "analysis_run_id", "kind"),
        Index("ix_workflow_run_status", "status"),
        Index("ix_workflow_run_queue_ready", "queue_name", "status", "next_retry_at"),
        Index("ix_workflow_run_idempotency_key", "idempotency_key"),
    )

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    project_id: uuid.UUID | None = Field(
        default=None,
        foreign_key="project.id",
        index=True,
        ondelete="CASCADE",
    )
    analysis_run_id: uuid.UUID | None = Field(
        default=None,
        foreign_key="analysis_run.id",
        index=True,
        ondelete="CASCADE",
    )
    report_id: uuid.UUID | None = Field(
        default=None,
        foreign_key="report.id",
        index=True,
        ondelete="SET NULL",
    )
    parent_workflow_run_id: uuid.UUID | None = Field(
        default=None,
        foreign_key="workflow_run.id",
        index=True,
        ondelete="SET NULL",
    )
    created_at: datetime = Field(
        default_factory=get_datetime_utc,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )
    updated_at: datetime = Field(
        default_factory=get_datetime_utc,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )
    started_at: datetime | None = Field(
        default=None,
        sa_column=Column(DateTime(timezone=True), nullable=True),
    )
    finished_at: datetime | None = Field(
        default=None,
        sa_column=Column(DateTime(timezone=True), nullable=True),
    )
    next_retry_at: datetime | None = Field(
        default=None,
        sa_column=Column(DateTime(timezone=True), nullable=True),
    )
    locked_by: str | None = Field(default=None, max_length=120)
    locked_at: datetime | None = Field(
        default=None,
        sa_column=Column(DateTime(timezone=True), nullable=True),
    )
    lease_expires_at: datetime | None = Field(
        default=None,
        sa_column=Column(DateTime(timezone=True), nullable=True),
    )
    last_heartbeat_at: datetime | None = Field(
        default=None,
        sa_column=Column(DateTime(timezone=True), nullable=True),
    )
    attempt_started_at: datetime | None = Field(
        default=None,
        sa_column=Column(DateTime(timezone=True), nullable=True),
    )


class WorkflowEventBase(SQLModel):
    """Shared workflow event payload."""

    sequence: int = Field(sa_column=Column(Integer, nullable=False))
    event_type: WorkflowEventType = Field(sa_column=Column(String(40), nullable=False))
    status: WorkflowRunStatus = Field(sa_column=Column(String(40), nullable=False))
    stage: str | None = Field(default=None, max_length=120)
    message: str | None = Field(default=None, sa_column=Column(Text, nullable=True))
    progress_current: int | None = Field(default=None, sa_column=Column(Integer, nullable=True))
    progress_total: int | None = Field(default=None, sa_column=Column(Integer, nullable=True))
    artifact_kind: str | None = Field(default=None, max_length=80)
    artifact_id: str | None = Field(default=None, max_length=120)
    metadata_json: dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSON, nullable=False),
    )


class WorkflowEvent(WorkflowEventBase, table=True):
    """Append-only event row for a durable workflow."""

    __tablename__ = "workflow_event"
    __table_args__ = (
        UniqueConstraint("workflow_run_id", "sequence", name="uq_workflow_event_sequence"),
        Index("ix_workflow_event_workflow_created_at", "workflow_run_id", "created_at"),
    )

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    workflow_run_id: uuid.UUID = Field(
        foreign_key="workflow_run.id",
        index=True,
        nullable=False,
        ondelete="CASCADE",
    )
    created_at: datetime = Field(
        default_factory=get_datetime_utc,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )


class WorkflowEventPublic(SQLModel):
    """Public workflow event DTO without raw filesystem or secret-bearing fields."""

    id: uuid.UUID
    workflow_run_id: uuid.UUID
    sequence: int
    event_type: WorkflowEventType
    status: WorkflowRunStatus
    stage: str | None = None
    message: str | None = None
    progress_current: int | None = None
    progress_total: int | None = None
    artifact_kind: str | None = None
    artifact_id: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime


class WorkflowRunPublic(SQLModel):
    """Public workflow state DTO used by imports, providers, and reports."""

    id: uuid.UUID
    kind: WorkflowRunKind
    status: WorkflowRunStatus
    title: str
    handler: str
    execution_mode: str
    project_id: uuid.UUID | None = None
    analysis_run_id: uuid.UUID | None = None
    report_id: uuid.UUID | None = None
    parent_workflow_run_id: uuid.UUID | None = None
    current_stage: str | None = None
    progress_current: int = 0
    progress_total: int | None = None
    retry_count: int = 0
    max_retries: int = 0
    cancellation_requested: bool = False
    error_message: str | None = None
    error_details: dict[str, Any] = Field(default_factory=dict)
    details: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    updated_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    next_retry_at: datetime | None = None
    latest_event: WorkflowEventPublic | None = None


class WorkflowRunsPublic(SQLModel):
    """Collection response for workflow runs."""

    data: list[WorkflowRunPublic]
    count: int


class WorkflowEventsPublic(SQLModel):
    """Collection response for workflow events."""

    data: list[WorkflowEventPublic]
    count: int

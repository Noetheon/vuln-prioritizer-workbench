"""Workbench audit event models."""

import uuid
from datetime import datetime
from typing import Any, Literal

from sqlalchemy import JSON, Column, DateTime, Index
from sqlmodel import Field, SQLModel

from app.models.base import get_datetime_utc

AuditEventStatus = Literal["success", "failure"]


class AuditEventBase(SQLModel):
    """Shared audit event fields."""

    action: str = Field(max_length=100, index=True)
    resource_type: str = Field(max_length=100, index=True)
    resource_id: str | None = Field(default=None, max_length=100, index=True)
    status: str = Field(default="success", max_length=20, index=True)
    project_id: uuid.UUID | None = Field(
        default=None,
        foreign_key="project.id",
        index=True,
        nullable=True,
        ondelete="SET NULL",
    )
    detail_json: dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSON, nullable=False),
    )
    created_at: datetime = Field(
        default_factory=get_datetime_utc,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )


class AuditEvent(AuditEventBase, table=True):
    """Workbench audit event, including explicitly finalized lifecycle records."""

    __tablename__ = "audit_event"
    __table_args__ = (
        Index("ix_audit_event_created_at", "created_at"),
        Index("ix_audit_event_project_created", "project_id", "created_at"),
    )

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)


class AuditEventPublic(SQLModel):
    """Audit event shape exposed to administrators."""

    id: uuid.UUID
    action: str
    resource_type: str
    resource_id: str | None
    status: str
    project_id: uuid.UUID | None
    detail: dict[str, Any]
    created_at: datetime


class AuditEventsPublic(SQLModel):
    """Paginated audit event collection."""

    data: list[AuditEventPublic]
    count: int


def audit_event_public(event: AuditEvent) -> AuditEventPublic:
    """Return public audit event metadata."""
    return AuditEventPublic(
        id=event.id,
        action=event.action,
        resource_type=event.resource_type,
        resource_id=event.resource_id,
        status=event.status,
        project_id=event.project_id,
        detail=dict(event.detail_json or {}),
        created_at=event.created_at,
    )

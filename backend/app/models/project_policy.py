"""Per-project priority thresholds and SLA response targets."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Column, DateTime, Integer
from sqlmodel import Field, SQLModel

from app.models.base import get_datetime_utc

PROJECT_POLICY_REASON_MAX_LENGTH = 500


class ProjectPolicy(SQLModel, table=True):
    """The current policy of one project; every change increments its version."""

    __tablename__ = "project_policy"

    project_id: uuid.UUID = Field(
        primary_key=True,
        foreign_key="project.id",
        nullable=False,
        ondelete="CASCADE",
    )
    version: int = Field(default=1, sa_column=Column(Integer, nullable=False))
    policy_json: dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSON, nullable=False),
    )
    updated_at: datetime = Field(
        default_factory=get_datetime_utc,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )
    updated_by: str | None = Field(default=None, max_length=255)


class SlaHoursPublic(SQLModel):
    """Response target in hours for each base priority."""

    critical: int = Field(ge=1, le=8760)
    high: int = Field(ge=1, le=8760)
    medium: int = Field(ge=1, le=8760)
    low: int = Field(ge=1, le=8760)


class ProjectPolicyFields(SQLModel):
    """Thresholds of the transparent base priority rule plus SLA targets."""

    critical_epss_threshold: float = Field(ge=0.0, le=1.0)
    critical_cvss_threshold: float = Field(ge=0.0, le=10.0)
    high_epss_threshold: float = Field(ge=0.0, le=1.0)
    high_cvss_threshold: float = Field(ge=0.0, le=10.0)
    medium_epss_threshold: float = Field(ge=0.0, le=1.0)
    medium_cvss_threshold: float = Field(ge=0.0, le=10.0)
    sla_hours: SlaHoursPublic


class ProjectPolicyPublic(ProjectPolicyFields):
    """A project's effective policy with its version and defaults for comparison."""

    project_id: uuid.UUID
    version: int = 0
    is_default: bool = True
    updated_at: datetime | None = None
    updated_by: str | None = None
    defaults: ProjectPolicyFields


class ProjectPolicyUpdate(ProjectPolicyFields):
    """Replace a project's policy and, by default, re-evaluate its findings."""

    reevaluate: bool = True
    reason: str | None = Field(default=None, max_length=PROJECT_POLICY_REASON_MAX_LENGTH)


class ProjectPolicyUpdatePublic(SQLModel):
    """Saved policy and the re-evaluation it queued, if any."""

    policy: ProjectPolicyPublic
    changed: bool
    evaluation_run_id: uuid.UUID | None = None
    evaluation_skipped_reason: str | None = None

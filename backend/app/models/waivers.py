"""Persisted waiver and risk acceptance models for the template Workbench."""

import uuid
from datetime import date, datetime
from typing import Optional

from pydantic import field_validator, model_validator
from sqlalchemy import Column, Date, DateTime, Index, Text
from sqlmodel import Field, Relationship, SQLModel

from app.models.base import get_datetime_utc


class WaiverScopeBase(SQLModel):
    """Shared waiver scope fields.

    Multiple scope fields are interpreted as an intersection. A CVE+asset waiver,
    for example, only matches findings with both that CVE and that asset.
    """

    cve_id: str | None = Field(default=None, max_length=64)
    finding_id: uuid.UUID | None = None
    asset_id: uuid.UUID | None = None
    asset_key: str | None = Field(default=None, max_length=200)
    service: str | None = Field(default=None, max_length=200)


class WaiverBase(WaiverScopeBase):
    """Shared persisted waiver fields."""

    owner: str = Field(min_length=1, max_length=200)
    reason: str = Field(min_length=1, sa_column=Column(Text, nullable=False))
    expires_at: date = Field(sa_column=Column(Date, nullable=False))
    review_at: date | None = Field(default=None, sa_column=Column(Date, nullable=True))
    approval_ref: str | None = Field(default=None, max_length=300)
    ticket_url: str | None = Field(default=None, max_length=1000)


class Waiver(WaiverBase, table=True):
    """Project-scoped risk acceptance waiver."""

    __tablename__ = "waiver"
    __table_args__ = (
        Index("ix_waiver_project_cve", "project_id", "cve_id"),
        Index("ix_waiver_project_asset", "project_id", "asset_id"),
        Index("ix_waiver_project_asset_key", "project_id", "asset_key"),
        Index("ix_waiver_project_service", "project_id", "service"),
        Index("ix_waiver_finding", "finding_id"),
    )

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    project_id: uuid.UUID = Field(
        foreign_key="project.id",
        index=True,
        nullable=False,
        ondelete="CASCADE",
    )
    finding_id: uuid.UUID | None = Field(
        default=None,
        foreign_key="finding.id",
        index=True,
        ondelete="SET NULL",
    )
    asset_id: uuid.UUID | None = Field(
        default=None,
        foreign_key="asset.id",
        index=True,
        ondelete="SET NULL",
    )
    cve_id: str | None = Field(default=None, max_length=64, index=True)
    asset_key: str | None = Field(default=None, max_length=200)
    service: str | None = Field(default=None, max_length=200)
    created_at: datetime = Field(
        default_factory=get_datetime_utc,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )
    updated_at: datetime = Field(
        default_factory=get_datetime_utc,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )
    project: Optional["Project"] = Relationship(back_populates="waivers")  # type: ignore[name-defined]  # noqa: F821


class WaiverCreate(WaiverScopeBase):
    """Create payload for a project waiver."""

    owner: str | None = Field(default=None, max_length=200)
    reason: str | None = Field(default=None)
    expires_at: date | None = None
    review_at: date | None = None
    approval_ref: str | None = Field(default=None, max_length=300)
    ticket_url: str | None = Field(default=None, max_length=1000)

    @field_validator(
        "cve_id",
        "asset_key",
        "service",
        "owner",
        "reason",
        "approval_ref",
        "ticket_url",
    )
    @classmethod
    def _strip_strings(cls, value: str | None) -> str | None:
        if value is None:
            return None
        stripped = value.strip()
        return stripped or None

    @field_validator("cve_id")
    @classmethod
    def _normalize_cve_id(cls, value: str | None) -> str | None:
        return value.upper() if value else None

    @model_validator(mode="after")
    def _validate_required_fields(self) -> "WaiverCreate":
        _validate_waiver_payload(self)
        return self


class WaiverUpdate(WaiverCreate):
    """Update payload for a waiver.

    Updates replace the waiver scope and governance fields so clients can move a
    waiver from one scope to another with one request.
    """


class WaiverPublic(WaiverBase):
    """Public waiver response with derived lifecycle and match context."""

    id: uuid.UUID
    project_id: uuid.UUID
    created_at: datetime
    updated_at: datetime
    status: str
    days_remaining: int | None = None
    matched_findings: int = 0


class WaiversPublic(SQLModel):
    """Collection response for project waivers."""

    data: list[WaiverPublic]
    count: int


def _validate_waiver_payload(payload: WaiverCreate) -> None:
    if payload.owner is None:
        raise ValueError("owner is required.")
    if payload.reason is None:
        raise ValueError("reason is required.")
    if payload.expires_at is None:
        raise ValueError("expires_at is required.")
    if payload.review_at is not None and payload.review_at > payload.expires_at:
        raise ValueError("review_after_expiry")
    if not any(
        (
            payload.finding_id,
            payload.cve_id,
            payload.asset_id,
            payload.asset_key,
            payload.service,
        )
    ):
        raise ValueError("At least one waiver scope is required.")

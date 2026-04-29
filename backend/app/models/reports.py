"""Report artifact metadata models."""

import uuid
from datetime import datetime
from typing import Any, Literal

from sqlalchemy import JSON, Column, DateTime, Index, Integer, String
from sqlmodel import Field, SQLModel

from app.models.base import get_datetime_utc


class ReportCreate(SQLModel):
    """Request payload for creating a run report."""

    format: Literal["markdown"] = "markdown"


class ReportBase(SQLModel):
    """Shared persisted report metadata fields."""

    kind: str = Field(max_length=80)
    format: str = Field(max_length=40)
    filename: str = Field(max_length=500)
    content_type: str = Field(max_length=120)
    sha256: str = Field(min_length=64, max_length=64)
    size_bytes: int = Field(sa_column=Column(Integer, nullable=False))
    metadata_json: dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSON, nullable=False),
    )


class Report(ReportBase, table=True):
    """Server-owned report artifact linked to an analysis run."""

    __tablename__ = "report"
    __table_args__ = (
        Index("ix_report_project_created_at", "project_id", "created_at"),
        Index("ix_report_analysis_run_created_at", "analysis_run_id", "created_at"),
    )

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    project_id: uuid.UUID = Field(
        foreign_key="project.id",
        index=True,
        nullable=False,
        ondelete="CASCADE",
    )
    analysis_run_id: uuid.UUID = Field(
        foreign_key="analysis_run.id",
        index=True,
        nullable=False,
        ondelete="CASCADE",
    )
    path: str = Field(sa_column=Column(String(1000), nullable=False))
    created_at: datetime = Field(
        default_factory=get_datetime_utc,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )


class ReportPublic(ReportBase):
    """Public report metadata without exposing server filesystem paths."""

    id: uuid.UUID
    project_id: uuid.UUID
    analysis_run_id: uuid.UUID
    created_at: datetime
    download_url: str


class ReportsPublic(SQLModel):
    """Collection response for reports."""

    data: list[ReportPublic]
    count: int

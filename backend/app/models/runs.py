"""Analysis run, occurrence, and provider snapshot domain models."""

import uuid
from datetime import datetime
from typing import Any, Optional

from sqlalchemy import JSON, Column, DateTime, Index, String, Text
from sqlmodel import Field, Relationship, SQLModel

from app.decision_core.contracts import AnalysisEvidenceV2, RunDiagnosticsV2, RunParseErrorV2
from app.models.base import get_datetime_utc
from app.models.enums import AnalysisRunStatus
from app.models.workflows import WorkflowRunPublic


class ProviderSnapshotBase(SQLModel):
    """Shared provider snapshot fields."""

    nvd_last_sync: str | None = Field(default=None, max_length=64)
    epss_date: str | None = Field(default=None, max_length=32)
    kev_catalog_version: str | None = Field(default=None, max_length=128)
    content_hash: str | None = Field(default=None, max_length=128)
    source_hashes_json: dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSON, nullable=False),
    )
    source_metadata_json: dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSON, nullable=False),
    )


class ProviderSnapshot(ProviderSnapshotBase, table=True):
    """Provider data snapshot used by one or more analysis runs."""

    __tablename__ = "provider_snapshot"

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    created_at: datetime = Field(
        default_factory=get_datetime_utc,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )
    content_hash: str | None = Field(default=None, max_length=128, unique=True, index=True)
    analysis_runs: list["AnalysisRun"] = Relationship(back_populates="provider_snapshot")


class AnalysisRunBase(SQLModel):
    """Shared analysis run fields."""

    input_type: str = Field(min_length=1, max_length=80)
    filename: str | None = Field(default=None, max_length=500)
    status: AnalysisRunStatus = Field(
        default=AnalysisRunStatus.PENDING,
        sa_column=Column(String(40), nullable=False),
    )
    started_at: datetime = Field(
        default_factory=get_datetime_utc,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )
    finished_at: datetime | None = Field(
        default=None,
        sa_column=Column(DateTime(timezone=True), nullable=True),
    )
    error_message: str | None = Field(default=None, sa_column=Column(Text, nullable=True))


class AnalysisRun(AnalysisRunBase, table=True):
    """Workbench import or analysis run for a project."""

    __tablename__ = "analysis_run"
    __table_args__ = (
        Index("ix_analysis_run_project_started_at", "project_id", "started_at"),
        Index("ix_analysis_run_project_status", "project_id", "status"),
    )

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    project_id: uuid.UUID = Field(
        foreign_key="project.id",
        index=True,
        nullable=False,
        ondelete="CASCADE",
    )
    provider_snapshot_id: uuid.UUID | None = Field(
        default=None,
        foreign_key="provider_snapshot.id",
        index=True,
        ondelete="SET NULL",
    )
    project: Optional["Project"] = Relationship(back_populates="analysis_runs")  # type: ignore[name-defined]  # noqa: F821
    provider_snapshot: ProviderSnapshot | None = Relationship(back_populates="analysis_runs")
    occurrences: list["FindingOccurrence"] = Relationship(
        back_populates="analysis_run",
        cascade_delete=True,
    )


class AnalysisRunUploadsPublic(SQLModel):
    """Public upload artifact references for one run."""

    input: dict[str, Any] | None = None
    asset_context: dict[str, Any] | None = None
    vex: dict[str, Any] | None = None


class AnalysisRunProviderSnapshotRefPublic(SQLModel):
    """Public provider snapshot reference for one run."""

    id: uuid.UUID | None = None
    file: str | None = None
    hash: str | None = None
    locked: bool = False
    degraded: bool = False


class AnalysisRunCountsPublic(SQLModel):
    """Public import and analysis counters."""

    created_findings: int = 0
    updated_findings: int = 0
    ignored_lines: int = 0
    rows_read: int = 0
    occurrence_count: int = 0
    finding_count: int = 0
    counts_by_priority: dict[str, int] = Field(default_factory=dict)
    kev_hits: int = 0
    suppressed_by_vex: int = 0
    attack_mapped_cves: int = 0


class AnalysisRunPublic(SQLModel):
    """Public analysis run response shape."""

    input_type: str
    filename: str | None
    status: AnalysisRunStatus
    started_at: datetime
    finished_at: datetime | None
    error_message: str | None = None
    id: uuid.UUID
    project_id: uuid.UUID
    provider_snapshot_id: uuid.UUID | None
    evidence: AnalysisEvidenceV2 | None = None
    diagnostics: RunDiagnosticsV2 | None = None
    uploads: AnalysisRunUploadsPublic = Field(default_factory=AnalysisRunUploadsPublic)
    provider_snapshot: AnalysisRunProviderSnapshotRefPublic | None = None
    counts: AnalysisRunCountsPublic = Field(default_factory=AnalysisRunCountsPublic)
    warnings: list[str] = Field(default_factory=list)
    parse_errors: list[RunParseErrorV2] = Field(default_factory=list)
    workflow: WorkflowRunPublic | None = None


class AnalysisRunsPublic(SQLModel):
    """Paginated analysis run collection response."""

    data: list[AnalysisRunPublic]
    count: int


class ImportParseErrorPublic(SQLModel):
    """Stable parser error item for import status and summary APIs."""

    input_type: str
    filename: str | None = None
    message: str
    error_type: str
    line: int | None = None
    field: str | None = None
    value: str | None = None


class AnalysisRunSummaryPublic(SQLModel):
    """UI-oriented summary for one import or analysis run."""

    id: uuid.UUID
    project_id: uuid.UUID
    input_type: str
    filename: str | None
    status: AnalysisRunStatus
    started_at: datetime
    finished_at: datetime | None
    created_findings: int = 0
    updated_findings: int = 0
    ignored_lines: int = 0
    rows_read: int = 0
    occurrence_count: int = 0
    finding_count: int = 0
    counts_by_priority: dict[str, int] = Field(default_factory=dict)
    kev_hits: int = 0
    provider_snapshot_id: uuid.UUID | None = None
    provider_degraded: bool = False
    warnings: list[str] = Field(default_factory=list)
    parse_errors: list[RunParseErrorV2] = Field(default_factory=list)
    evidence: AnalysisEvidenceV2 | None = None
    diagnostics: RunDiagnosticsV2 | None = None
    uploads: AnalysisRunUploadsPublic = Field(default_factory=AnalysisRunUploadsPublic)
    provider_snapshot: AnalysisRunProviderSnapshotRefPublic | None = None
    analysis_decision_scope: str | None = None
    persistence_scope: str | None = None
    workflow: WorkflowRunPublic | None = None


class FindingOccurrenceBase(SQLModel):
    """Shared finding occurrence fields."""

    source: str | None = Field(default=None, max_length=120)
    scanner: str | None = Field(default=None, max_length=120)
    raw_reference: str | None = Field(default=None, max_length=1000)
    fix_version: str | None = Field(default=None, max_length=300)
    evidence_json: dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSON, nullable=False),
    )


class FindingOccurrence(FindingOccurrenceBase, table=True):
    """Concrete scanner/source occurrence that produced a finding in a run."""

    __tablename__ = "finding_occurrence"

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    finding_id: uuid.UUID = Field(
        foreign_key="finding.id",
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
    finding: Optional["Finding"] = Relationship(back_populates="occurrences")  # type: ignore[name-defined]  # noqa: F821
    analysis_run: AnalysisRun | None = Relationship(back_populates="occurrences")

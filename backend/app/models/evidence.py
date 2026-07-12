"""Decision/Evidence Kernel v2 persistence models."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    Float,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlmodel import Field, Relationship, SQLModel

from app.decision_core.contracts import (
    ANALYSIS_EVIDENCE_SCHEMA_VERSION,
    FINDING_DECISION_EVIDENCE_SCHEMA_VERSION,
)
from app.decision_core.ledger import FINDING_CURRENT_PROJECTION_SCHEMA_VERSION
from app.models.base import get_datetime_utc


class AnalysisEvidenceBase(SQLModel):
    """Run-wide validated evidence payload."""

    schema_version: str = Field(
        default=ANALYSIS_EVIDENCE_SCHEMA_VERSION,
        sa_column=Column(String(80), nullable=False),
    )
    payload_json: dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSON, nullable=False),
    )
    diagnostics_json: dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSON, nullable=False),
    )


class AnalysisEvidence(AnalysisEvidenceBase, table=True):
    """Versioned source of truth for one analysis run."""

    __tablename__ = "analysis_evidence"
    __table_args__ = (
        UniqueConstraint("analysis_run_id", name="uq_analysis_evidence_analysis_run"),
        Index("ix_analysis_evidence_project_created_at", "project_id", "created_at"),
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
    provider_snapshot_id: uuid.UUID | None = Field(
        default=None,
        foreign_key="provider_snapshot.id",
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


class FindingDecisionEvidenceBase(SQLModel):
    """Validated immutable finding decision payload for one run."""

    schema_version: str = Field(
        default=FINDING_DECISION_EVIDENCE_SCHEMA_VERSION,
        sa_column=Column(String(80), nullable=False),
    )
    cve_id: str = Field(max_length=64)
    dedup_key: str = Field(max_length=512)
    priority: str = Field(max_length=40)
    status: str = Field(max_length=40)
    payload_json: dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSON, nullable=False),
    )


class FindingDecisionEvidence(FindingDecisionEvidenceBase, table=True):
    """Immutable decision/evidence graph for a finding within one run."""

    __tablename__ = "finding_decision_evidence"
    __table_args__ = (
        UniqueConstraint(
            "finding_id",
            "analysis_run_id",
            name="uq_finding_decision_evidence_finding_run",
        ),
        Index("ix_finding_decision_evidence_project_run", "project_id", "analysis_run_id"),
        Index("ix_finding_decision_evidence_finding_created", "finding_id", "created_at"),
    )

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    analysis_evidence_id: uuid.UUID = Field(
        foreign_key="analysis_evidence.id",
        index=True,
        nullable=False,
        ondelete="CASCADE",
    )
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
    finding_id: uuid.UUID = Field(
        foreign_key="finding.id",
        index=True,
        nullable=False,
        ondelete="CASCADE",
    )
    created_at: datetime = Field(
        default_factory=get_datetime_utc,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )
    updated_at: datetime = Field(
        default_factory=get_datetime_utc,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )


class FindingCurrentProjectionBase(SQLModel):
    """Materialized, queryable current decision state for one finding."""

    schema_version: str = Field(
        default=FINDING_CURRENT_PROJECTION_SCHEMA_VERSION,
        sa_column=Column(String(80), nullable=False),
    )
    cve_id: str = Field(max_length=64)
    dedup_key: str = Field(max_length=512)
    priority: str = Field(max_length=40)
    status: str = Field(max_length=40)
    priority_rank: int = Field(default=99, sa_column=Column(Integer, nullable=False))
    risk_score: float | None = Field(default=None, sa_column=Column(Float, nullable=True))
    operational_rank: int = Field(default=0, sa_column=Column(Integer, nullable=False))
    in_kev: bool = Field(default=False, sa_column=Column(Boolean, nullable=False))
    epss: float | None = Field(default=None, sa_column=Column(Float, nullable=True))
    cvss_base_score: float | None = Field(default=None, sa_column=Column(Float, nullable=True))
    attack_mapped: bool = Field(default=False, sa_column=Column(Boolean, nullable=False))
    suppressed_by_vex: bool = Field(default=False, sa_column=Column(Boolean, nullable=False))
    under_investigation: bool = Field(default=False, sa_column=Column(Boolean, nullable=False))
    waived: bool = Field(default=False, sa_column=Column(Boolean, nullable=False))
    rationale: str | None = Field(default=None, sa_column=Column(Text, nullable=True))
    recommended_action: str | None = Field(default=None, sa_column=Column(Text, nullable=True))
    lifecycle_overlay_json: dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSON, nullable=False),
    )
    source_payload_sha256: str = Field(max_length=64)
    projection_payload_sha256: str = Field(max_length=64)
    revision: int = Field(default=1, sa_column=Column(Integer, nullable=False))
    lifecycle_revision: int = Field(default=0, sa_column=Column(Integer, nullable=False))


class FindingCurrentProjection(FindingCurrentProjectionBase, table=True):
    """Mutable current state derived from immutable per-run decision evidence."""

    __tablename__ = "finding_current_projection"
    __table_args__ = (
        Index(
            "ix_finding_current_projection_project_operational",
            "project_id",
            "operational_rank",
            "priority_rank",
        ),
        Index(
            "ix_finding_current_projection_project_priority",
            "project_id",
            "priority_rank",
        ),
        Index(
            "ix_finding_current_projection_project_status",
            "project_id",
            "status",
        ),
        Index(
            "ix_finding_current_projection_project_kev",
            "project_id",
            "in_kev",
        ),
        Index(
            "ix_finding_current_projection_project_epss",
            "project_id",
            "epss",
        ),
        Index(
            "ix_finding_current_projection_project_cvss",
            "project_id",
            "cvss_base_score",
        ),
        Index(
            "ix_finding_current_projection_project_risk",
            "project_id",
            "risk_score",
        ),
    )

    finding_id: uuid.UUID = Field(
        primary_key=True,
        foreign_key="finding.id",
        nullable=False,
        ondelete="CASCADE",
    )
    project_id: uuid.UUID = Field(
        foreign_key="project.id",
        index=True,
        nullable=False,
        ondelete="CASCADE",
    )
    source_analysis_run_id: uuid.UUID | None = Field(
        default=None,
        foreign_key="analysis_run.id",
        index=True,
        ondelete="SET NULL",
    )
    source_finding_evidence_id: uuid.UUID | None = Field(
        default=None,
        foreign_key="finding_decision_evidence.id",
        index=True,
        ondelete="SET NULL",
    )
    source_created_at: datetime = Field(
        default_factory=get_datetime_utc,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )
    created_at: datetime = Field(
        default_factory=get_datetime_utc,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )
    updated_at: datetime = Field(
        default_factory=get_datetime_utc,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )
    finding: Finding = Relationship(  # type: ignore[name-defined]  # noqa: F821
        back_populates="current_projection",
        sa_relationship_kwargs={"uselist": False},
    )

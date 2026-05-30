"""Decision/Evidence Kernel v2 persistence models."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Column, DateTime, Index, String, UniqueConstraint
from sqlmodel import Field, SQLModel

from app.contracts.decision_evidence import (
    ANALYSIS_EVIDENCE_SCHEMA_VERSION,
    FINDING_DECISION_EVIDENCE_SCHEMA_VERSION,
)
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
    """Validated current finding decision payload for one run."""

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
    """Current decision/evidence graph for a finding within a run."""

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

"""SQLAlchemy 2.x models for the Workbench MVP database."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from vuln_prioritizer.db.base import Base


def _uuid() -> str:
    return uuid4().hex


def utc_now() -> datetime:
    return datetime.now(UTC)


class Project(Base):
    __tablename__ = "projects"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(200), nullable=False, unique=True)
    description: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
    )

    analysis_runs: Mapped[list[AnalysisRun]] = relationship(
        back_populates="project",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    assets: Mapped[list[Asset]] = relationship(
        back_populates="project",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    findings: Mapped[list[Finding]] = relationship(
        back_populates="project",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    reports: Mapped[list[Report]] = relationship(
        back_populates="project",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    evidence_bundles: Mapped[list[EvidenceBundle]] = relationship(
        back_populates="project",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


class ProviderSnapshot(Base):
    __tablename__ = "provider_snapshots"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    nvd_last_sync: Mapped[str | None] = mapped_column(String(64))
    epss_date: Mapped[str | None] = mapped_column(String(32))
    kev_catalog_version: Mapped[str | None] = mapped_column(String(128))
    content_hash: Mapped[str | None] = mapped_column(String(128), unique=True)
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict)

    analysis_runs: Mapped[list[AnalysisRun]] = relationship(back_populates="provider_snapshot")


class AnalysisRun(Base):
    __tablename__ = "analysis_runs"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    project_id: Mapped[str] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
    )
    input_type: Mapped[str] = mapped_column(String(80), nullable=False)
    input_filename: Mapped[str | None] = mapped_column(String(500))
    input_path: Mapped[str | None] = mapped_column(String(1000))
    status: Mapped[str] = mapped_column(String(40), nullable=False, default="pending")
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error_message: Mapped[str | None] = mapped_column(Text)
    provider_snapshot_id: Mapped[str | None] = mapped_column(
        ForeignKey("provider_snapshots.id", ondelete="SET NULL")
    )
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict)
    attack_summary_json: Mapped[dict] = mapped_column(JSON, default=dict)
    summary_json: Mapped[dict] = mapped_column(JSON, default=dict)

    project: Mapped[Project] = relationship(back_populates="analysis_runs")
    provider_snapshot: Mapped[ProviderSnapshot | None] = relationship(
        back_populates="analysis_runs"
    )
    occurrences: Mapped[list[FindingOccurrence]] = relationship(
        back_populates="analysis_run",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    findings: Mapped[list[Finding]] = relationship(back_populates="analysis_run")
    reports: Mapped[list[Report]] = relationship(
        back_populates="analysis_run",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    evidence_bundles: Mapped[list[EvidenceBundle]] = relationship(
        back_populates="analysis_run",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    __table_args__ = (Index("ix_analysis_runs_project_started_at", "project_id", "started_at"),)


class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    project_id: Mapped[str] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
    )
    asset_id: Mapped[str] = mapped_column(String(200), nullable=False)
    target_ref: Mapped[str | None] = mapped_column(String(500))
    owner: Mapped[str | None] = mapped_column(String(200))
    business_service: Mapped[str | None] = mapped_column(String(200))
    environment: Mapped[str | None] = mapped_column(String(80))
    exposure: Mapped[str | None] = mapped_column(String(80))
    criticality: Mapped[str | None] = mapped_column(String(80))

    project: Mapped[Project] = relationship(back_populates="assets")
    findings: Mapped[list[Finding]] = relationship(back_populates="asset")

    __table_args__ = (Index("uq_assets_project_asset_id", "project_id", "asset_id", unique=True),)


class Component(Base):
    __tablename__ = "components"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(300), nullable=False)
    version: Mapped[str | None] = mapped_column(String(200))
    purl: Mapped[str | None] = mapped_column(String(1000))
    ecosystem: Mapped[str | None] = mapped_column(String(120))
    package_type: Mapped[str | None] = mapped_column(String(120))

    findings: Mapped[list[Finding]] = relationship(back_populates="component")

    __table_args__ = (
        Index("uq_components_identity", "name", "version", "purl", unique=True),
        Index("ix_components_purl", "purl"),
    )


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    cve_id: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    source_id: Mapped[str | None] = mapped_column(String(120))
    title: Mapped[str | None] = mapped_column(String(500))
    description: Mapped[str | None] = mapped_column(Text)
    cvss_score: Mapped[float | None] = mapped_column(Float)
    cvss_vector: Mapped[str | None] = mapped_column(String(300))
    severity: Mapped[str | None] = mapped_column(String(40))
    cwe: Mapped[str | None] = mapped_column(String(200))
    published_at: Mapped[str | None] = mapped_column(String(64))
    modified_at: Mapped[str | None] = mapped_column(String(64))
    provider_json: Mapped[dict] = mapped_column(JSON, default=dict)

    findings: Mapped[list[Finding]] = relationship(back_populates="vulnerability")


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    project_id: Mapped[str] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
    )
    analysis_run_id: Mapped[str | None] = mapped_column(
        ForeignKey("analysis_runs.id", ondelete="SET NULL")
    )
    vulnerability_id: Mapped[str] = mapped_column(
        ForeignKey("vulnerabilities.id", ondelete="RESTRICT"),
        nullable=False,
    )
    component_id: Mapped[str | None] = mapped_column(
        ForeignKey("components.id", ondelete="SET NULL")
    )
    asset_id: Mapped[str | None] = mapped_column(ForeignKey("assets.id", ondelete="SET NULL"))
    cve_id: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(40), nullable=False, default="open")
    priority: Mapped[str] = mapped_column(String(40), nullable=False)
    priority_rank: Mapped[int] = mapped_column(Integer, nullable=False, default=99)
    risk_score: Mapped[float | None] = mapped_column(Float)
    operational_rank: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    in_kev: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    epss: Mapped[float | None] = mapped_column(Float)
    cvss_base_score: Mapped[float | None] = mapped_column(Float)
    attack_mapped: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    suppressed_by_vex: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    recommended_action: Mapped[str | None] = mapped_column(Text)
    rationale: Mapped[str | None] = mapped_column(Text)
    explanation_json: Mapped[dict] = mapped_column(JSON, default=dict)
    finding_json: Mapped[dict] = mapped_column(JSON, default=dict)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    waived: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    project: Mapped[Project] = relationship(back_populates="findings")
    analysis_run: Mapped[AnalysisRun | None] = relationship(back_populates="findings")
    vulnerability: Mapped[Vulnerability] = relationship(back_populates="findings")
    component: Mapped[Component | None] = relationship(back_populates="findings")
    asset: Mapped[Asset | None] = relationship(back_populates="findings")
    occurrences: Mapped[list[FindingOccurrence]] = relationship(
        back_populates="finding",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    __table_args__ = (
        Index(
            "uq_findings_project_vulnerability_component_asset",
            "project_id",
            "vulnerability_id",
            "component_id",
            "asset_id",
            unique=True,
        ),
        Index("ix_findings_cve_id", "cve_id"),
        Index("ix_findings_project_priority", "project_id", "priority_rank"),
        Index("ix_findings_project_status", "project_id", "status"),
    )


class FindingOccurrence(Base):
    __tablename__ = "finding_occurrences"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    finding_id: Mapped[str] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"),
        nullable=False,
    )
    analysis_run_id: Mapped[str] = mapped_column(
        ForeignKey("analysis_runs.id", ondelete="CASCADE"),
        nullable=False,
    )
    scanner: Mapped[str | None] = mapped_column(String(120))
    raw_reference: Mapped[str | None] = mapped_column(String(1000))
    fix_version: Mapped[str | None] = mapped_column(String(300))
    evidence_json: Mapped[dict] = mapped_column(JSON, default=dict)

    finding: Mapped[Finding] = relationship(back_populates="occurrences")
    analysis_run: Mapped[AnalysisRun] = relationship(back_populates="occurrences")

    __table_args__ = (Index("ix_finding_occurrences_run", "analysis_run_id"),)


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    project_id: Mapped[str] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
    )
    analysis_run_id: Mapped[str] = mapped_column(
        ForeignKey("analysis_runs.id", ondelete="CASCADE"),
        nullable=False,
    )
    kind: Mapped[str] = mapped_column(String(80), nullable=False)
    format: Mapped[str] = mapped_column(String(40), nullable=False)
    path: Mapped[str] = mapped_column(String(1000), nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    project: Mapped[Project] = relationship(back_populates="reports")
    analysis_run: Mapped[AnalysisRun] = relationship(back_populates="reports")

    __table_args__ = (Index("ix_reports_run", "analysis_run_id"),)


class EvidenceBundle(Base):
    __tablename__ = "evidence_bundles"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    project_id: Mapped[str] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
    )
    analysis_run_id: Mapped[str] = mapped_column(
        ForeignKey("analysis_runs.id", ondelete="CASCADE"),
        nullable=False,
    )
    path: Mapped[str] = mapped_column(String(1000), nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    manifest_json: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    project: Mapped[Project] = relationship(back_populates="evidence_bundles")
    analysis_run: Mapped[AnalysisRun] = relationship(back_populates="evidence_bundles")

    __table_args__ = (Index("ix_evidence_bundles_run", "analysis_run_id"),)

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
    finding_status_history: Mapped[list[FindingStatusHistory]] = relationship(
        back_populates="project",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    audit_events: Mapped[list[AuditEvent]] = relationship(
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
    waivers: Mapped[list[Waiver]] = relationship(
        back_populates="project",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    detection_controls: Mapped[list[DetectionControl]] = relationship(
        back_populates="project",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    config_snapshots: Mapped[list[ProjectConfigSnapshot]] = relationship(
        back_populates="project",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    artifact_retention: Mapped[ProjectArtifactRetention | None] = relationship(
        back_populates="project",
        cascade="all, delete-orphan",
        passive_deletes=True,
        uselist=False,
    )
    workbench_jobs: Mapped[list[WorkbenchJob]] = relationship(
        back_populates="project",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    github_issue_exports: Mapped[list[GitHubIssueExport]] = relationship(
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
    attack_contexts: Mapped[list[FindingAttackContext]] = relationship(
        back_populates="analysis_run",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
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
    attack_mappings: Mapped[list[AttackMappingRecord]] = relationship(
        back_populates="vulnerability",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


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
    under_investigation: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    waiver_status: Mapped[str | None] = mapped_column(String(80))
    waiver_reason: Mapped[str | None] = mapped_column(Text)
    waiver_owner: Mapped[str | None] = mapped_column(String(200))
    waiver_expires_on: Mapped[str | None] = mapped_column(String(32))
    waiver_review_on: Mapped[str | None] = mapped_column(String(32))
    waiver_days_remaining: Mapped[int | None] = mapped_column(Integer)
    waiver_scope: Mapped[str | None] = mapped_column(String(120))
    waiver_id: Mapped[str | None] = mapped_column(String(200))
    waiver_matched_scope: Mapped[str | None] = mapped_column(String(120))
    waiver_approval_ref: Mapped[str | None] = mapped_column(String(300))
    waiver_ticket_url: Mapped[str | None] = mapped_column(String(1000))
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
    attack_contexts: Mapped[list[FindingAttackContext]] = relationship(
        back_populates="finding",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    status_history: Mapped[list[FindingStatusHistory]] = relationship(
        back_populates="finding",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="FindingStatusHistory.created_at",
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


class FindingStatusHistory(Base):
    __tablename__ = "finding_status_history"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    project_id: Mapped[str] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
    )
    finding_id: Mapped[str] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"),
        nullable=False,
    )
    previous_status: Mapped[str | None] = mapped_column(String(40))
    new_status: Mapped[str] = mapped_column(String(40), nullable=False)
    actor: Mapped[str | None] = mapped_column(String(200))
    reason: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    project: Mapped[Project] = relationship(back_populates="finding_status_history")
    finding: Mapped[Finding] = relationship(back_populates="status_history")

    __table_args__ = (
        Index("ix_finding_status_history_finding", "finding_id", "created_at"),
        Index("ix_finding_status_history_project", "project_id", "created_at"),
    )


class AttackMappingRecord(Base):
    __tablename__ = "attack_mappings"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    vulnerability_id: Mapped[str] = mapped_column(
        ForeignKey("vulnerabilities.id", ondelete="CASCADE"),
        nullable=False,
    )
    cve_id: Mapped[str] = mapped_column(String(64), nullable=False)
    attack_object_id: Mapped[str] = mapped_column(String(64), nullable=False)
    attack_object_name: Mapped[str | None] = mapped_column(String(300))
    mapping_type: Mapped[str | None] = mapped_column(String(120))
    source: Mapped[str] = mapped_column(String(80), nullable=False)
    source_version: Mapped[str | None] = mapped_column(String(120))
    source_hash: Mapped[str | None] = mapped_column(String(128))
    source_path: Mapped[str | None] = mapped_column(String(1000))
    attack_version: Mapped[str | None] = mapped_column(String(80))
    domain: Mapped[str | None] = mapped_column(String(80))
    metadata_hash: Mapped[str | None] = mapped_column(String(128))
    metadata_path: Mapped[str | None] = mapped_column(String(1000))
    confidence: Mapped[float | None] = mapped_column(Float)
    review_status: Mapped[str] = mapped_column(String(80), nullable=False, default="unreviewed")
    rationale: Mapped[str | None] = mapped_column(Text)
    references_json: Mapped[list] = mapped_column(JSON, default=list)
    mapping_json: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    vulnerability: Mapped[Vulnerability] = relationship(back_populates="attack_mappings")

    __table_args__ = (
        Index("ix_attack_mappings_cve_id", "cve_id"),
        Index("ix_attack_mappings_technique", "attack_object_id"),
        Index(
            "uq_attack_mappings_source_cve_technique_type",
            "source",
            "cve_id",
            "attack_object_id",
            "mapping_type",
            unique=True,
        ),
    )


class FindingAttackContext(Base):
    __tablename__ = "finding_attack_contexts"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    finding_id: Mapped[str] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"),
        nullable=False,
    )
    analysis_run_id: Mapped[str] = mapped_column(
        ForeignKey("analysis_runs.id", ondelete="CASCADE"),
        nullable=False,
    )
    cve_id: Mapped[str] = mapped_column(String(64), nullable=False)
    mapped: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    source: Mapped[str] = mapped_column(String(80), nullable=False, default="none")
    source_version: Mapped[str | None] = mapped_column(String(120))
    source_hash: Mapped[str | None] = mapped_column(String(128))
    source_path: Mapped[str | None] = mapped_column(String(1000))
    attack_version: Mapped[str | None] = mapped_column(String(80))
    domain: Mapped[str | None] = mapped_column(String(80))
    metadata_hash: Mapped[str | None] = mapped_column(String(128))
    metadata_path: Mapped[str | None] = mapped_column(String(1000))
    attack_relevance: Mapped[str] = mapped_column(String(40), nullable=False, default="Unmapped")
    threat_context_rank: Mapped[int] = mapped_column(Integer, nullable=False, default=99)
    rationale: Mapped[str | None] = mapped_column(Text)
    review_status: Mapped[str] = mapped_column(String(80), nullable=False, default="unreviewed")
    techniques_json: Mapped[list] = mapped_column(JSON, default=list)
    tactics_json: Mapped[list] = mapped_column(JSON, default=list)
    mappings_json: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    finding: Mapped[Finding] = relationship(back_populates="attack_contexts")
    analysis_run: Mapped[AnalysisRun] = relationship(back_populates="attack_contexts")

    __table_args__ = (
        Index(
            "uq_finding_attack_contexts_finding_run",
            "finding_id",
            "analysis_run_id",
            unique=True,
        ),
        Index("ix_finding_attack_contexts_run_rank", "analysis_run_id", "threat_context_rank"),
        Index("ix_finding_attack_contexts_technique_source", "source", "attack_relevance"),
    )


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


class Waiver(Base):
    __tablename__ = "waivers"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    project_id: Mapped[str] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
    )
    cve_id: Mapped[str | None] = mapped_column(String(64))
    finding_id: Mapped[str | None] = mapped_column(ForeignKey("findings.id", ondelete="SET NULL"))
    asset_id: Mapped[str | None] = mapped_column(String(200))
    component_name: Mapped[str | None] = mapped_column(String(300))
    component_version: Mapped[str | None] = mapped_column(String(200))
    service: Mapped[str | None] = mapped_column(String(200))
    owner: Mapped[str] = mapped_column(String(200), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    expires_on: Mapped[str] = mapped_column(String(32), nullable=False)
    review_on: Mapped[str | None] = mapped_column(String(32))
    approval_ref: Mapped[str | None] = mapped_column(String(300))
    ticket_url: Mapped[str | None] = mapped_column(String(1000))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
    )

    project: Mapped[Project] = relationship(back_populates="waivers")

    __table_args__ = (
        Index("ix_waivers_project_cve", "project_id", "cve_id"),
        Index("ix_waivers_project_asset", "project_id", "asset_id"),
        Index("ix_waivers_finding", "finding_id"),
    )


class DetectionControl(Base):
    __tablename__ = "detection_controls"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    project_id: Mapped[str] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
    )
    control_id: Mapped[str | None] = mapped_column(String(120))
    name: Mapped[str] = mapped_column(String(300), nullable=False)
    technique_id: Mapped[str] = mapped_column(String(64), nullable=False)
    technique_name: Mapped[str | None] = mapped_column(String(300))
    source_type: Mapped[str | None] = mapped_column(String(120))
    coverage_level: Mapped[str] = mapped_column(String(40), nullable=False, default="unknown")
    environment: Mapped[str | None] = mapped_column(String(80))
    owner: Mapped[str | None] = mapped_column(String(200))
    evidence_ref: Mapped[str | None] = mapped_column(String(1000))
    evidence_refs_json: Mapped[list] = mapped_column(JSON, default=list)
    review_status: Mapped[str] = mapped_column(String(80), nullable=False, default="unreviewed")
    notes: Mapped[str | None] = mapped_column(Text)
    last_verified_at: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
    )

    project: Mapped[Project] = relationship(back_populates="detection_controls")
    history: Mapped[list[DetectionControlHistory]] = relationship(
        back_populates="control",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="DetectionControlHistory.created_at",
    )
    attachments: Mapped[list[DetectionControlAttachment]] = relationship(
        back_populates="control",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="DetectionControlAttachment.created_at",
    )

    __table_args__ = (
        Index("ix_detection_controls_project_technique", "project_id", "technique_id"),
        Index(
            "uq_detection_controls_project_identity",
            "project_id",
            "control_id",
            "technique_id",
            unique=True,
        ),
    )


class DetectionControlHistory(Base):
    __tablename__ = "detection_control_history"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    project_id: Mapped[str] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
    )
    control_id: Mapped[str] = mapped_column(
        ForeignKey("detection_controls.id", ondelete="CASCADE"),
        nullable=False,
    )
    event_type: Mapped[str] = mapped_column(String(80), nullable=False)
    actor: Mapped[str | None] = mapped_column(String(200))
    reason: Mapped[str | None] = mapped_column(Text)
    previous_json: Mapped[dict] = mapped_column(JSON, default=dict)
    current_json: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    control: Mapped[DetectionControl] = relationship(back_populates="history")

    __table_args__ = (
        Index("ix_detection_control_history_control", "control_id", "created_at"),
        Index("ix_detection_control_history_project", "project_id", "created_at"),
    )


class DetectionControlAttachment(Base):
    __tablename__ = "detection_control_attachments"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    project_id: Mapped[str] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
    )
    control_id: Mapped[str] = mapped_column(
        ForeignKey("detection_controls.id", ondelete="CASCADE"),
        nullable=False,
    )
    filename: Mapped[str] = mapped_column(String(500), nullable=False)
    content_type: Mapped[str | None] = mapped_column(String(200))
    path: Mapped[str] = mapped_column(String(1000), nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    control: Mapped[DetectionControl] = relationship(back_populates="attachments")

    __table_args__ = (
        Index("ix_detection_control_attachments_control", "control_id", "created_at"),
        Index("ix_detection_control_attachments_project", "project_id", "created_at"),
    )


class ApiToken(Base):
    __tablename__ = "api_tokens"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (Index("ix_api_tokens_active", "revoked_at"),)


class ProviderUpdateJob(Base):
    __tablename__ = "provider_update_jobs"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    status: Mapped[str] = mapped_column(String(40), nullable=False, default="pending")
    requested_sources_json: Mapped[list] = mapped_column(JSON, default=list)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error_message: Mapped[str | None] = mapped_column(Text)
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict)

    __table_args__ = (Index("ix_provider_update_jobs_started_at", "started_at"),)


class WorkbenchJob(Base):
    __tablename__ = "workbench_jobs"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    project_id: Mapped[str | None] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"))
    kind: Mapped[str] = mapped_column(String(80), nullable=False)
    status: Mapped[str] = mapped_column(String(40), nullable=False, default="queued")
    target_type: Mapped[str | None] = mapped_column(String(120))
    target_id: Mapped[str | None] = mapped_column(String(120))
    progress: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=3)
    priority: Mapped[int] = mapped_column(Integer, nullable=False, default=100)
    idempotency_key: Mapped[str | None] = mapped_column(String(200), unique=True)
    payload_json: Mapped[dict] = mapped_column(JSON, default=dict)
    result_json: Mapped[dict] = mapped_column(JSON, default=dict)
    logs_json: Mapped[list] = mapped_column(JSON, default=list)
    error_message: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    queued_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=utc_now)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    lease_owner: Mapped[str | None] = mapped_column(String(200))
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    project: Mapped[Project | None] = relationship(back_populates="workbench_jobs")

    __table_args__ = (
        Index("ix_workbench_jobs_status_priority", "status", "priority", "queued_at"),
        Index("ix_workbench_jobs_project_created", "project_id", "created_at"),
        Index("ix_workbench_jobs_target", "target_type", "target_id"),
        Index("ix_workbench_jobs_lease", "lease_expires_at"),
    )


class ProjectConfigSnapshot(Base):
    __tablename__ = "project_config_snapshots"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    project_id: Mapped[str] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
    )
    source: Mapped[str] = mapped_column(String(80), nullable=False, default="api")
    config_json: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
    )

    project: Mapped[Project] = relationship(back_populates="config_snapshots")

    __table_args__ = (Index("ix_project_config_snapshots_project", "project_id", "created_at"),)


class ProjectArtifactRetention(Base):
    __tablename__ = "project_artifact_retention"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    project_id: Mapped[str] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )
    report_retention_days: Mapped[int | None] = mapped_column(Integer)
    evidence_retention_days: Mapped[int | None] = mapped_column(Integer)
    max_disk_usage_mb: Mapped[int | None] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
    )

    project: Mapped[Project] = relationship(back_populates="artifact_retention")

    __table_args__ = (Index("ix_project_artifact_retention_project", "project_id"),)


class GitHubIssueExport(Base):
    __tablename__ = "github_issue_exports"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    project_id: Mapped[str] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
    )
    finding_id: Mapped[str | None] = mapped_column(ForeignKey("findings.id", ondelete="SET NULL"))
    duplicate_key: Mapped[str] = mapped_column(String(300), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    html_url: Mapped[str | None] = mapped_column(String(1000))
    issue_number: Mapped[int | None] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    project: Mapped[Project] = relationship(back_populates="github_issue_exports")

    __table_args__ = (
        Index(
            "uq_github_issue_exports_project_duplicate",
            "project_id",
            "duplicate_key",
            unique=True,
        ),
        Index("ix_github_issue_exports_finding", "finding_id"),
    )


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    project_id: Mapped[str | None] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=True,
    )
    event_type: Mapped[str] = mapped_column(String(120), nullable=False)
    target_type: Mapped[str | None] = mapped_column(String(120))
    target_id: Mapped[str | None] = mapped_column(String(120))
    actor: Mapped[str | None] = mapped_column(String(200))
    message: Mapped[str | None] = mapped_column(Text)
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    project: Mapped[Project | None] = relationship(back_populates="audit_events")

    __table_args__ = (
        Index("ix_audit_events_project_created", "project_id", "created_at"),
        Index("ix_audit_events_event_type", "event_type"),
        Index("ix_audit_events_target", "target_type", "target_id"),
    )

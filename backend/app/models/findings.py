"""Finding domain models."""

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import Column, DateTime, Index, String, UniqueConstraint
from sqlmodel import Field, Relationship, SQLModel

from app.decision_core.contracts import FindingDecisionEvidenceV2
from app.models.base import get_datetime_utc
from app.models.enums import FindingPriority, FindingStatus


class FindingBase(SQLModel):
    """Shared finding fields."""

    cve_id: str = Field(min_length=1, max_length=64)
    dedup_key: str = Field(default_factory=lambda: str(uuid.uuid4()), max_length=512)
    status: FindingStatus = Field(
        default=FindingStatus.OPEN,
        sa_column=Column(String(40), nullable=False),
    )


class Finding(FindingBase, table=True):
    """Prioritized vulnerability finding within a project."""

    __tablename__ = "finding"
    __table_args__ = (
        UniqueConstraint("project_id", "dedup_key", name="uq_finding_project_dedup_key"),
        Index("ix_finding_cve_id", "cve_id"),
        Index("ix_finding_project_status", "project_id", "status"),
        Index("ix_finding_project_asset", "project_id", "asset_id"),
        Index("ix_finding_project_vulnerability", "project_id", "vulnerability_id"),
    )

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    project_id: uuid.UUID = Field(
        foreign_key="project.id",
        index=True,
        nullable=False,
        ondelete="CASCADE",
    )
    vulnerability_id: uuid.UUID = Field(
        foreign_key="vulnerability.id",
        index=True,
        nullable=False,
        ondelete="RESTRICT",
    )
    component_id: uuid.UUID | None = Field(
        default=None,
        foreign_key="component.id",
        index=True,
        ondelete="SET NULL",
    )
    asset_id: uuid.UUID | None = Field(
        default=None,
        foreign_key="asset.id",
        index=True,
        ondelete="SET NULL",
    )
    first_seen_at: datetime = Field(
        default_factory=get_datetime_utc,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )
    last_seen_at: datetime = Field(
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
    project: Optional["Project"] = Relationship(back_populates="findings")  # type: ignore[name-defined]  # noqa: F821
    vulnerability: Optional["Vulnerability"] = Relationship(back_populates="findings")  # type: ignore[name-defined]  # noqa: F821
    component: Optional["Component"] = Relationship(back_populates="findings")  # type: ignore[name-defined]  # noqa: F821
    asset: Optional["Asset"] = Relationship(back_populates="findings")  # type: ignore[name-defined]  # noqa: F821
    occurrences: list["FindingOccurrence"] = Relationship(  # type: ignore[name-defined]  # noqa: F821
        back_populates="finding",
        cascade_delete=True,
    )


class FindingPublic(FindingBase):
    """Public finding response shape."""

    id: uuid.UUID
    project_id: uuid.UUID
    vulnerability_id: uuid.UUID
    component_id: uuid.UUID | None
    asset_id: uuid.UUID | None
    first_seen_at: datetime
    last_seen_at: datetime
    created_at: datetime
    updated_at: datetime
    priority: FindingPriority = FindingPriority.MEDIUM
    priority_rank: int = 99
    risk_score: float | None = None
    operational_rank: int = 0
    in_kev: bool = False
    epss: float | None = None
    cvss_base_score: float | None = None
    attack_mapped: bool = False
    suppressed_by_vex: bool = False
    under_investigation: bool = False
    waived: bool = False
    recommended_action: str | None = None
    rationale: str | None = None
    component_name: str | None = None
    component_version: str | None = None
    component_purl: str | None = None
    asset_name: str | None = None
    asset_key: str | None = None
    asset_target_ref: str | None = None
    asset_environment: str | None = None
    asset_criticality: str | None = None
    owner: str | None = None
    business_service: str | None = None
    exposure: str | None = None
    evidence: FindingDecisionEvidenceV2 | None = None


class FindingOccurrencePublic(SQLModel):
    """Public occurrence row for finding detail views."""

    id: uuid.UUID
    analysis_run_id: uuid.UUID
    source: str | None = None
    scanner: str | None = None
    raw_reference: str | None = None
    fix_version: str | None = None
    source_format: str | None = None
    source_id: str | None = None
    source_record_id: str | None = None
    component_name: str | None = None
    component_version: str | None = None
    purl: str | None = None
    fix_versions: list[str] | None = None
    target_kind: str | None = None
    target_ref: str | None = None
    asset_owner: str | None = None
    asset_business_service: str | None = None
    asset_exposure: str | None = None
    raw_severity: str | None = None
    vex_status: str | None = None
    vex_justification: str | None = None
    vex_action_statement: str | None = None
    vex_match_type: str | None = None
    vex_source_format: str | None = None
    vex_source_record_id: str | None = None
    vex_source_path: str | None = None
    vex_candidate_count: int = 0
    created_at: datetime | None = None


class FindingAttackMappingDetailPublic(SQLModel):
    """Defensive ATT&CK mapping row for finding detail views."""

    technique_id: str
    technique_name: str | None = None
    tactics: list[str] = Field(default_factory=list)
    source: str | None = None
    confidence: str | None = None
    review_status: str | None = None
    mapping_type: str | None = None
    rationale: str | None = None
    defensive_note: str | None = None
    references: list[str] = Field(default_factory=list)


class FindingAttackTechniqueDetailPublic(SQLModel):
    """ATT&CK technique row rendered by the Workbench detail tab."""

    technique_id: str
    name: str | None = None
    tactics: list[str] = Field(default_factory=list)
    url: str | None = None
    source: str | None = None
    confidence: str | None = None
    review_status: str | None = None
    rationale: str | None = None
    defensive_note: str | None = None


class FindingAttackContextDetailPublic(SQLModel):
    """Safe finding-level ATT&CK context DTO for the React Workbench."""

    mapped: bool = False
    source: str = "none"
    review_status: str = "unreviewed"
    defensive_note: str | None = None
    rationale: str | None = None
    confidence: str | None = None
    low_confidence: bool = False
    attack_relevance: str = "Unmapped"
    technique_ids: list[str] = Field(default_factory=list)
    tactics: list[str] = Field(default_factory=list)
    mappings: list[FindingAttackMappingDetailPublic] = Field(default_factory=list)
    techniques: list[FindingAttackTechniqueDetailPublic] = Field(default_factory=list)


class FindingDetailPublic(FindingPublic):
    """Public finding detail response shape."""

    occurrences: list[FindingOccurrencePublic] = Field(default_factory=list)
    attack_context: FindingAttackContextDetailPublic | None = None


class FindingsPublic(SQLModel):
    """Paginated finding collection response."""

    data: list[FindingPublic]
    count: int

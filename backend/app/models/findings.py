"""Finding domain models."""

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import JSON, Column, DateTime, Float, Index, Integer, String, UniqueConstraint
from sqlmodel import Field, Relationship, SQLModel

from app.models.assets import Asset, Component
from app.models.base import get_datetime_utc
from app.models.enums import FindingPriority, FindingStatus
from app.models.projects import Project
from app.models.vulnerabilities import Vulnerability

if TYPE_CHECKING:
    from app.models.runs import FindingOccurrence


class FindingBase(SQLModel):
    """Shared finding fields."""

    cve_id: str = Field(min_length=1, max_length=64)
    dedup_key: str = Field(default_factory=lambda: str(uuid.uuid4()), max_length=512)
    status: FindingStatus = Field(
        default=FindingStatus.OPEN,
        sa_column=Column(String(40), nullable=False),
    )
    priority: FindingPriority = Field(
        default=FindingPriority.MEDIUM,
        sa_column=Column(String(40), nullable=False),
    )
    priority_rank: int = Field(default=99, sa_column=Column(Integer, nullable=False))
    risk_score: float | None = Field(default=None, sa_column=Column(Float, nullable=True))
    operational_rank: int = Field(default=0, sa_column=Column(Integer, nullable=False))
    in_kev: bool = False
    epss: float | None = Field(default=None, sa_column=Column(Float, nullable=True))
    cvss_base_score: float | None = Field(default=None, sa_column=Column(Float, nullable=True))
    attack_mapped: bool = False
    suppressed_by_vex: bool = False
    under_investigation: bool = False
    waived: bool = False
    recommended_action: str | None = None
    rationale: str | None = None
    explanation_json: dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSON, nullable=False),
    )
    data_quality_json: dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSON, nullable=False),
    )
    evidence_json: dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSON, nullable=False),
    )


class Finding(FindingBase, table=True):
    """Prioritized vulnerability finding within a project."""

    __tablename__ = "finding"
    __table_args__ = (
        UniqueConstraint("project_id", "dedup_key", name="uq_finding_project_dedup_key"),
        UniqueConstraint(
            "project_id",
            "vulnerability_id",
            "component_id",
            "asset_id",
            name="uq_finding_project_vulnerability_component_asset",
        ),
        Index("ix_finding_cve_id", "cve_id"),
        Index("ix_finding_project_priority", "project_id", "priority_rank"),
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
    project: Project | None = Relationship(back_populates="findings")
    vulnerability: Vulnerability | None = Relationship(back_populates="findings")
    component: Component | None = Relationship(back_populates="findings")
    asset: Asset | None = Relationship(back_populates="findings")
    occurrences: list["FindingOccurrence"] = Relationship(
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


class FindingsPublic(SQLModel):
    """Paginated finding collection response."""

    data: list[FindingPublic]
    count: int

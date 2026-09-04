"""Asset and component domain models."""

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import Column, DateTime, Index, String, Text, UniqueConstraint
from sqlmodel import Field, Relationship, SQLModel

from app.models.base import get_datetime_utc
from app.models.enums import AssetCriticality, AssetEnvironment, AssetExposure


class AssetBase(SQLModel):
    """Shared asset fields."""

    asset_key: str = Field(min_length=1, max_length=200)
    name: str = Field(min_length=1, max_length=300)
    target_ref: str | None = Field(default=None, max_length=500)
    owner: str | None = Field(default=None, max_length=200)
    business_service: str | None = Field(default=None, max_length=200)
    environment: AssetEnvironment = Field(
        default=AssetEnvironment.UNKNOWN,
        sa_column=Column(String(80), nullable=False),
    )
    exposure: AssetExposure = Field(
        default=AssetExposure.UNKNOWN,
        sa_column=Column(String(80), nullable=False),
    )
    criticality: AssetCriticality = Field(
        default=AssetCriticality.UNKNOWN,
        sa_column=Column(String(80), nullable=False),
    )


class AssetCreate(AssetBase):
    """Asset creation payload."""


class AssetUpdate(SQLModel):
    """Asset update payload."""

    asset_key: str | None = Field(default=None, min_length=1, max_length=200)
    name: str | None = Field(default=None, min_length=1, max_length=300)
    target_ref: str | None = Field(default=None, max_length=500)
    owner: str | None = Field(default=None, max_length=200)
    business_service: str | None = Field(default=None, max_length=200)
    environment: AssetEnvironment | None = None
    exposure: AssetExposure | None = None
    criticality: AssetCriticality | None = None


class Asset(AssetBase, table=True):
    """Project-scoped asset affected by one or more findings."""

    __tablename__ = "asset"
    __table_args__ = (
        UniqueConstraint("project_id", "asset_key", name="uq_asset_project_asset_key"),
        Index("ix_asset_project_environment", "project_id", "environment"),
        Index("ix_asset_project_exposure", "project_id", "exposure"),
        Index("ix_asset_project_criticality", "project_id", "criticality"),
    )

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    project_id: uuid.UUID = Field(
        foreign_key="project.id",
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
    project: Optional["Project"] = Relationship(back_populates="assets")  # type: ignore[name-defined]  # noqa: F821
    findings: list["Finding"] = Relationship(back_populates="asset")  # type: ignore[name-defined]  # noqa: F821


class AssetPublic(AssetBase):
    """Public asset response shape."""

    id: uuid.UUID
    project_id: uuid.UUID
    created_at: datetime
    updated_at: datetime
    finding_count: int = 0
    rescore_needed: bool = False


class AssetsPublic(SQLModel):
    """Paginated asset collection response."""

    data: list[AssetPublic]
    count: int


class AssetContextImportPublic(SQLModel):
    """Summary returned after importing asset-context CSV rows."""

    project_id: uuid.UUID
    imported_assets: int = 0
    created_assets: int = 0
    updated_assets: int = 0
    unchanged_assets: int = 0
    rescore_needed_findings: int = 0
    total_rows: int = 0
    loaded_rows: int = 0
    skipped_rows: int = 0
    warnings: list[str] = Field(default_factory=list)
    asset_keys: list[str] = Field(default_factory=list)


class AssetRecalculatePublic(SQLModel):
    """Summary returned after recalculating findings for one asset."""

    asset_id: uuid.UUID
    asset_key: str
    recalculated_findings: int = 0
    cleared_rescore_flags: int = 0
    operational_scores: list[int] = Field(default_factory=list)
    rescore_needed: bool = False


class ComponentBase(SQLModel):
    """Shared component fields."""

    name: str = Field(min_length=1, max_length=300)
    version: str | None = Field(default=None, max_length=200)
    purl: str | None = Field(default=None, max_length=1000)
    ecosystem: str | None = Field(default=None, max_length=120)
    package_type: str | None = Field(default=None, max_length=120)


class Component(ComponentBase, table=True):
    """Software component associated with findings."""

    __tablename__ = "component"
    __table_args__ = (UniqueConstraint("identity_key", name="uq_component_identity_key"),)

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    identity_key: str = Field(max_length=128)
    identity_material: str = Field(sa_column=Column(Text, nullable=False))
    created_at: datetime = Field(
        default_factory=get_datetime_utc,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )
    updated_at: datetime = Field(
        default_factory=get_datetime_utc,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )
    findings: list["Finding"] = Relationship(back_populates="component")  # type: ignore[name-defined]  # noqa: F821

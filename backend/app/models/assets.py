"""Asset and component domain models."""

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Column, DateTime, Index, String, UniqueConstraint
from sqlmodel import Field, Relationship, SQLModel

from app.models.base import get_datetime_utc
from app.models.enums import AssetCriticality, AssetEnvironment, AssetExposure
from app.models.projects import Project

if TYPE_CHECKING:
    from app.models.findings import Finding


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
    project: Project | None = Relationship(back_populates="assets")
    findings: list["Finding"] = Relationship(back_populates="asset")


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
    __table_args__ = (
        UniqueConstraint("purl", name="uq_component_purl"),
        UniqueConstraint("name", "version", "ecosystem", name="uq_component_identity"),
    )

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    created_at: datetime = Field(
        default_factory=get_datetime_utc,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )
    updated_at: datetime = Field(
        default_factory=get_datetime_utc,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )
    findings: list["Finding"] = Relationship(back_populates="component")

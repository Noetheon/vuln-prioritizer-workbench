"""Project domain models for the template-aligned Workbench."""

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import Column, DateTime
from sqlmodel import Field, Relationship, SQLModel

from app.models.base import get_datetime_utc


class ProjectBase(SQLModel):
    """Shared Project fields for Workbench project ownership."""

    name: str = Field(min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=4096)


class ProjectCreate(ProjectBase):
    """Project creation payload."""


class ProjectUpdate(SQLModel):
    """Project update payload reserved for the next domain slice."""

    name: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=4096)


class Project(ProjectBase, table=True):
    """Workbench project domain shell owned by a user."""

    __tablename__ = "project"

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    owner_id: uuid.UUID = Field(
        foreign_key="user.id",
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
    owner: Optional["User"] = Relationship(back_populates="projects")  # type: ignore[name-defined]  # noqa: F821
    assets: list["Asset"] = Relationship(back_populates="project", cascade_delete=True)  # type: ignore[name-defined]  # noqa: F821
    findings: list["Finding"] = Relationship(back_populates="project", cascade_delete=True)  # type: ignore[name-defined]  # noqa: F821
    analysis_runs: list["AnalysisRun"] = Relationship(  # type: ignore[name-defined]  # noqa: F821
        back_populates="project",
        cascade_delete=True,
    )


class ProjectPublic(ProjectBase):
    """Public Project shape returned by the API."""

    id: uuid.UUID
    owner_id: uuid.UUID
    created_at: datetime
    updated_at: datetime


class ProjectsPublic(SQLModel):
    """Paginated Project collection shape."""

    data: list[ProjectPublic]
    count: int

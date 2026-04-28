"""Template-aligned API and persistence models for the migration backend shell."""

import uuid
from datetime import UTC, datetime

from sqlalchemy import Column, DateTime
from sqlmodel import Field, Relationship, SQLModel


def get_datetime_utc() -> datetime:
    """Return a timezone-aware UTC timestamp."""
    return datetime.now(UTC)


class Token(SQLModel):
    """OAuth2 bearer token response."""

    access_token: str
    token_type: str = "bearer"


class TokenPayload(SQLModel):
    """JWT payload accepted by the template shell."""

    sub: str | None = None


class UserBase(SQLModel):
    """Shared user fields from the official template's account model."""

    email: str = Field(index=True, max_length=255)
    is_active: bool = True
    is_superuser: bool = True
    full_name: str | None = None


class User(UserBase, table=True):
    """DB-backed local-first user shell used for project ownership."""

    __tablename__ = "user"

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    email: str = Field(index=True, unique=True, max_length=255)
    hashed_password: str = Field(default="configured-superuser", max_length=255)
    created_at: datetime = Field(
        default_factory=get_datetime_utc,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )
    projects: list["Project"] = Relationship(back_populates="owner", cascade_delete=True)


class UserPublic(UserBase):
    """Public user shape exposed by template auth routes."""

    id: uuid.UUID
    created_at: datetime


class UsersPublic(SQLModel):
    """Paginated user collection shape reserved for template parity."""

    data: list[UserPublic]
    count: int


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
    owner_id: uuid.UUID = Field(foreign_key="user.id", nullable=False, ondelete="CASCADE")
    created_at: datetime = Field(
        default_factory=get_datetime_utc,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )
    updated_at: datetime = Field(
        default_factory=get_datetime_utc,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )
    owner: User | None = Relationship(back_populates="projects")


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


class MigrationStatus(SQLModel):
    """Template migration state for the Workbench adapter."""

    phase: str
    legacy_workbench_mounted: bool


class WorkbenchStatus(SQLModel):
    """Status response returned by the template Workbench adapter."""

    status: str
    app: str
    core_package: str
    core_version: str
    legacy_api_prefix: str
    migration: MigrationStatus

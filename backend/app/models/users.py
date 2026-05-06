"""User models for the Workbench backend app."""

import uuid
from datetime import datetime

from sqlalchemy import Column, DateTime
from sqlmodel import Field, Relationship, SQLModel

from app.models.base import get_datetime_utc


class UserBase(SQLModel):
    """Shared user fields from the upstream account model."""

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
    projects: list["Project"] = Relationship(back_populates="owner", cascade_delete=True)  # type: ignore[name-defined]  # noqa: F821


class UserPublic(UserBase):
    """Public user shape exposed by Workbench auth routes."""

    id: uuid.UUID
    created_at: datetime


class UserPasswordChange(SQLModel):
    """Payload for rotating the current user's password."""

    current_password: str = Field(min_length=1, max_length=255)
    new_password: str = Field(min_length=12, max_length=255)


class UserPasswordReset(SQLModel):
    """Admin payload for resetting a persisted user password."""

    new_password: str = Field(min_length=12, max_length=255)


class UsersPublic(SQLModel):
    """Paginated user collection shape reserved for upstream parity."""

    data: list[UserPublic]
    count: int

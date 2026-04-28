"""User models for the template-aligned backend app."""

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Column, DateTime
from sqlmodel import Field, Relationship, SQLModel

from app.models.base import get_datetime_utc

if TYPE_CHECKING:
    from app.models.projects import Project


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

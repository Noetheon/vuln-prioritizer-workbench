"""Revocable Workbench session models."""

import uuid
from datetime import datetime

from sqlalchemy import Column, DateTime, Index, String
from sqlmodel import Field, SQLModel

from app.models.base import get_datetime_utc


class AuthSessionBase(SQLModel):
    """Shared persisted session metadata."""

    user_id: uuid.UUID = Field(foreign_key="user.id", index=True, ondelete="CASCADE")
    jti_hash: str = Field(sa_column=Column(String(128), nullable=False, unique=True))
    created_at: datetime = Field(
        default_factory=get_datetime_utc,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )
    expires_at: datetime = Field(sa_column=Column(DateTime(timezone=True), nullable=False))
    last_seen_at: datetime | None = Field(
        default=None,
        sa_column=Column(DateTime(timezone=True), nullable=True),
    )
    revoked_at: datetime | None = Field(
        default=None,
        sa_column=Column(DateTime(timezone=True), nullable=True),
    )


class AuthSession(AuthSessionBase, table=True):
    """Revocable JWT session record keyed by a hashed JTI."""

    __tablename__ = "auth_session"
    __table_args__ = (
        Index("ix_auth_session_expires_at", "expires_at"),
        Index("ix_auth_session_revoked_at", "revoked_at"),
    )

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)


class AuthSessionPublic(SQLModel):
    """Session metadata returned by administrative endpoints."""

    id: uuid.UUID
    user_id: uuid.UUID
    active: bool
    created_at: datetime
    expires_at: datetime
    last_seen_at: datetime | None
    revoked_at: datetime | None


class AuthSessionsPublic(SQLModel):
    """Collection response for session metadata."""

    data: list[AuthSessionPublic]
    count: int


def auth_session_public(session: AuthSession) -> AuthSessionPublic:
    """Return public session metadata without the JTI hash."""
    return AuthSessionPublic(
        id=session.id,
        user_id=session.user_id,
        active=session.revoked_at is None,
        created_at=session.created_at,
        expires_at=session.expires_at,
        last_seen_at=session.last_seen_at,
        revoked_at=session.revoked_at,
    )

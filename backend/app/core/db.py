"""Database helpers for the template-aligned backend shell."""

from __future__ import annotations

import uuid

from sqlmodel import Session, SQLModel, create_engine, select

from app.core.config import settings
from app.models import User

CONFIGURED_SUPERUSER_NAMESPACE = uuid.UUID("82a5f27c-a7db-4b44-a860-143b0137e419")


def _connect_args(database_uri: str) -> dict[str, bool]:
    if database_uri.startswith("sqlite"):
        return {"check_same_thread": False}
    return {}


engine = create_engine(
    settings.SQLALCHEMY_DATABASE_URI,
    connect_args=_connect_args(settings.SQLALCHEMY_DATABASE_URI),
    pool_pre_ping=True,
)


def configured_superuser_id(email: str) -> uuid.UUID:
    """Return a stable local-first UUID for the configured bootstrap user."""
    return uuid.uuid5(CONFIGURED_SUPERUSER_NAMESPACE, email.lower())


def init_db(session: Session) -> None:
    """Create metadata in local/dev contexts and ensure the configured user exists."""
    SQLModel.metadata.create_all(session.get_bind())
    ensure_configured_superuser(session)


def ensure_configured_superuser(session: Session) -> User:
    """Create or return the configured superuser used by the migration shell."""
    statement = select(User).where(User.email == settings.FIRST_SUPERUSER)
    user = session.exec(statement).first()
    if user:
        return user

    user = User(
        id=configured_superuser_id(settings.FIRST_SUPERUSER),
        email=settings.FIRST_SUPERUSER,
        is_active=True,
        is_superuser=True,
        hashed_password="configured-superuser-password-placeholder",
    )
    session.add(user)
    session.commit()
    session.refresh(user)
    return user

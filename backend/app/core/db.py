"""Database helpers for the active template-aligned backend runtime."""

from __future__ import annotations

import uuid

from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, SQLModel, create_engine, select

from app.core import security
from app.core.config import Settings, settings
from app.models import User

CONFIGURED_SUPERUSER_NAMESPACE = uuid.UUID("82a5f27c-a7db-4b44-a860-143b0137e419")


def _connect_args(database_uri: str) -> dict[str, bool]:
    if database_uri.startswith("sqlite"):
        return {"check_same_thread": False}
    return {}


def create_db_engine(active_settings: Settings) -> Engine:
    """Create a SQLAlchemy engine for one concrete settings object."""
    return create_engine(
        active_settings.SQLALCHEMY_DATABASE_URI,
        connect_args=_connect_args(active_settings.SQLALCHEMY_DATABASE_URI),
        pool_pre_ping=True,
    )


engine = create_db_engine(settings)


def configured_superuser_id(email: str) -> uuid.UUID:
    """Return a stable local-first UUID for the configured bootstrap user."""
    return uuid.uuid5(CONFIGURED_SUPERUSER_NAMESPACE, email.lower())


def init_db(session: Session, active_settings: Settings | None = None) -> None:
    """Create metadata in local/dev contexts and ensure the configured user exists."""
    SQLModel.metadata.create_all(session.get_bind())
    ensure_configured_superuser(session, active_settings=active_settings)


def ensure_configured_superuser(
    session: Session,
    active_settings: Settings | None = None,
) -> User:
    """Create or return the configured superuser used by the active runtime."""
    selected_settings = active_settings or settings
    statement = select(User).where(User.email == selected_settings.FIRST_SUPERUSER)
    user = session.exec(statement).first()
    if user:
        if security.password_hash_needs_bootstrap(user.hashed_password):
            user.hashed_password = security.get_password_hash(
                selected_settings.FIRST_SUPERUSER_PASSWORD
            )
            session.add(user)
            session.flush()
        return user

    user = User(
        id=configured_superuser_id(selected_settings.FIRST_SUPERUSER),
        email=selected_settings.FIRST_SUPERUSER,
        is_active=True,
        is_superuser=True,
        hashed_password=security.get_password_hash(selected_settings.FIRST_SUPERUSER_PASSWORD),
    )
    session.add(user)
    try:
        session.commit()
    except IntegrityError:
        session.rollback()
        existing = session.exec(statement).first()
        if existing:
            return existing
        raise
    session.refresh(user)
    return user

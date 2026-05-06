"""Repository helpers for revocable Workbench sessions."""

import uuid
from datetime import datetime

from sqlalchemy import or_
from sqlmodel import Session, col, select

from app.models import AuthSession
from app.models.base import get_datetime_utc


class AuthSessionRepository:
    """Persistence helpers for revocable JWT sessions."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def create_auth_session(
        self,
        *,
        user_id: uuid.UUID,
        jti_hash: str,
        expires_at: datetime,
    ) -> AuthSession:
        """Create a revocable auth session without committing the transaction."""
        record = AuthSession(
            user_id=user_id,
            jti_hash=jti_hash,
            expires_at=expires_at,
        )
        self.session.add(record)
        self.session.flush()
        return record

    def get_active_auth_session_by_hash(self, jti_hash: str) -> AuthSession | None:
        """Return an active session for a hashed JWT ID."""
        now = get_datetime_utc()
        statement = select(AuthSession).where(
            AuthSession.jti_hash == jti_hash,
            col(AuthSession.revoked_at).is_(None),
            col(AuthSession.expires_at) > now,
        )
        return self.session.exec(statement).first()

    def mark_auth_session_seen(self, auth_session: AuthSession) -> AuthSession:
        """Update last-seen metadata without committing the transaction."""
        auth_session.last_seen_at = get_datetime_utc()
        self.session.add(auth_session)
        self.session.flush()
        return auth_session

    def revoke_auth_session(self, auth_session: AuthSession) -> AuthSession:
        """Revoke one auth session without committing the transaction."""
        if auth_session.revoked_at is None:
            auth_session.revoked_at = get_datetime_utc()
        self.session.add(auth_session)
        self.session.flush()
        return auth_session

    def list_auth_sessions(self, *, limit: int = 100) -> list[AuthSession]:
        """Return recent sessions without exposing token material."""
        statement = select(AuthSession).order_by(col(AuthSession.created_at).desc()).limit(limit)
        return list(self.session.exec(statement).all())

    def delete_expired_auth_sessions(self, *, before: datetime) -> int:
        """Delete sessions that are expired or revoked before the retention cutoff."""
        statement = select(AuthSession).where(
            or_(col(AuthSession.expires_at) < before, col(AuthSession.revoked_at) < before)
        )
        records = list(self.session.exec(statement).all())
        for record in records:
            self.session.delete(record)
        self.session.flush()
        return len(records)

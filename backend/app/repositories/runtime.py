"""Runtime repository helpers for service liveness."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlmodel import Session, col, select

from app.models import RuntimeServiceHeartbeat
from app.models.base import get_datetime_utc


class RuntimeHeartbeatRepository:
    """Persist and read service heartbeat rows."""

    def __init__(self, session: Session) -> None:
        """Initialize a runtime heartbeat repository."""
        self.session = session

    def record_heartbeat(
        self,
        *,
        service_name: str,
        instance_id: str,
        metadata_json: dict[str, Any] | None = None,
        now: datetime | None = None,
    ) -> RuntimeServiceHeartbeat:
        """Create or update one service instance heartbeat."""
        timestamp = now or get_datetime_utc()
        heartbeat = self.session.get(
            RuntimeServiceHeartbeat,
            (service_name, instance_id),
        )
        if heartbeat is None:
            heartbeat = RuntimeServiceHeartbeat(
                service_name=service_name,
                instance_id=instance_id,
                started_at=timestamp,
                last_seen_at=timestamp,
                metadata_json=dict(metadata_json or {}),
            )
        else:
            heartbeat.last_seen_at = timestamp
            if metadata_json is not None:
                heartbeat.metadata_json = dict(metadata_json)
        self.session.add(heartbeat)
        self.session.flush()
        return heartbeat

    def latest_for_service(self, service_name: str) -> RuntimeServiceHeartbeat | None:
        """Return the most recent heartbeat for a service family."""
        statement = (
            select(RuntimeServiceHeartbeat)
            .where(RuntimeServiceHeartbeat.service_name == service_name)
            .order_by(col(RuntimeServiceHeartbeat.last_seen_at).desc())
            .limit(1)
        )
        return self.session.exec(statement).first()

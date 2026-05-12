"""Repository helpers for Workbench audit events."""

import uuid
from datetime import datetime
from typing import Any

from sqlmodel import Session, col, func, select

from app.models import AuditEvent, AuditEventStatus


class AuditEventRepository:
    """Persistence helpers for append-only audit events."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def create_audit_event(
        self,
        *,
        action: str,
        resource_type: str,
        resource_id: str | None = None,
        status: AuditEventStatus = "success",
        project_id: uuid.UUID | None = None,
        detail: dict[str, Any] | None = None,
    ) -> AuditEvent:
        """Create an audit event without committing the transaction."""
        event = AuditEvent(
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            status=status,
            project_id=project_id,
            detail_json=detail or {},
        )
        self.session.add(event)
        self.session.flush()
        return event

    def list_audit_events(
        self,
        *,
        limit: int,
        offset: int = 0,
        project_id: uuid.UUID | None = None,
    ) -> tuple[list[AuditEvent], int]:
        """Return recent audit events plus count."""
        count_statement = select(func.count()).select_from(AuditEvent)
        statement = select(AuditEvent).order_by(col(AuditEvent.created_at).desc())
        if project_id is not None:
            count_statement = count_statement.where(AuditEvent.project_id == project_id)
            statement = statement.where(AuditEvent.project_id == project_id)
        count = self.session.exec(count_statement).one()
        events = self.session.exec(statement.offset(offset).limit(limit)).all()
        return list(events), count

    def delete_audit_events_before(self, *, before: datetime) -> int:
        """Delete audit events older than the retention cutoff."""
        statement = select(AuditEvent).where(AuditEvent.created_at < before)
        records = list(self.session.exec(statement).all())
        for record in records:
            self.session.delete(record)
        self.session.flush()
        return len(records)

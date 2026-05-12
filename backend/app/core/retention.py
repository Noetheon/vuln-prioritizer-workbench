"""Retention cleanup entrypoint for Workbench operational data."""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta

from sqlmodel import Session, col, func, select

from app.core.config import Settings, settings
from app.core.db import engine
from app.models import AuditEvent
from app.models.base import get_datetime_utc
from app.repositories import AuditEventRepository
from app.services.audit import record_audit_event


@dataclass(frozen=True)
class RetentionCleanupResult:
    """Summary of retention cleanup activity."""

    audit_events: int = 0
    dry_run: bool = False


def run_retention_cleanup(
    session: Session,
    *,
    active_settings: Settings,
    dry_run: bool = False,
) -> RetentionCleanupResult:
    """Apply configured retention windows without committing the transaction."""
    now = get_datetime_utc()
    audit_cutoff = now - timedelta(days=active_settings.AUDIT_RETENTION_DAYS)

    if dry_run:
        result = RetentionCleanupResult(
            audit_events=_audit_events_before(session, audit_cutoff),
            dry_run=True,
        )
    else:
        result = RetentionCleanupResult(
            audit_events=AuditEventRepository(session).delete_audit_events_before(
                before=audit_cutoff
            ),
            dry_run=False,
        )
        record_audit_event(
            session,
            action="retention.cleanup",
            resource_type="retention",
            detail=asdict(result),
        )
    return result


def _audit_events_before(session: Session, cutoff: datetime) -> int:
    statement = (
        select(func.count()).select_from(AuditEvent).where(col(AuditEvent.created_at) < cutoff)
    )
    return session.exec(statement).one()


def main() -> None:
    parser = argparse.ArgumentParser(description="Clean up retained Workbench operational data.")
    parser.add_argument("--dry-run", action="store_true", help="Report cleanup counts only.")
    args = parser.parse_args()
    with Session(engine) as session:
        result = run_retention_cleanup(session, active_settings=settings, dry_run=args.dry_run)
        if args.dry_run:
            session.rollback()
        else:
            session.commit()
    print(json.dumps(asdict(result), sort_keys=True))


if __name__ == "__main__":
    main()

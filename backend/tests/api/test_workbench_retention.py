from __future__ import annotations

from dataclasses import replace
from datetime import timedelta

from sqlmodel import Session, select
from utils.workbench_env import WorkbenchApiEnv

from app.core.retention import run_retention_cleanup
from app.models import AuditEvent
from app.models.base import get_datetime_utc


def test_retention_cleanup_deletes_old_operational_records(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    old_timestamp = get_datetime_utc() - timedelta(days=45)
    active_settings = replace(
        workbench_api_env.client.app.state.workbench_settings,
        AUDIT_RETENTION_DAYS=30,
    )
    with Session(workbench_api_env.engine) as session:
        session.add(
            AuditEvent(
                action="old.event",
                resource_type="test",
                detail_json={},
                created_at=old_timestamp,
            )
        )
        session.commit()

        dry_run = run_retention_cleanup(
            session,
            active_settings=active_settings,
            dry_run=True,
        )
        assert dry_run.audit_events == 1
        session.rollback()

        result = run_retention_cleanup(
            session,
            active_settings=active_settings,
            dry_run=False,
        )
        session.commit()

        assert result.audit_events == 1
        old_event = session.exec(select(AuditEvent).where(AuditEvent.action == "old.event")).first()
        assert (
            session.exec(select(AuditEvent).where(AuditEvent.action == "retention.cleanup")).first()
            is not None
        )
        assert old_event is None

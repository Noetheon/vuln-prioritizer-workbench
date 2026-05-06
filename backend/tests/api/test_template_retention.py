from __future__ import annotations

from dataclasses import replace
from datetime import timedelta

from sqlmodel import Session, select
from utils.template_workbench import CONFIGURED_USER_ID, TemplateApiEnv

from app.core.retention import run_retention_cleanup
from app.models import ApiToken, AuditEvent, AuthSession
from app.models.base import get_datetime_utc


def test_retention_cleanup_deletes_old_operational_records(
    template_api_env: TemplateApiEnv,
) -> None:
    old_timestamp = get_datetime_utc() - timedelta(days=45)
    active_settings = replace(
        template_api_env.client.app.state.template_settings,
        AUDIT_RETENTION_DAYS=30,
        SESSION_RETENTION_DAYS=30,
        REVOKED_API_TOKEN_RETENTION_DAYS=30,
    )
    with Session(template_api_env.engine) as session:
        session.add(
            AuditEvent(
                action="old.event",
                resource_type="test",
                detail_json={},
                created_at=old_timestamp,
            )
        )
        session.add(
            AuthSession(
                user_id=CONFIGURED_USER_ID,
                jti_hash="old-session",
                created_at=old_timestamp,
                expires_at=old_timestamp,
            )
        )
        session.add(
            ApiToken(
                name="old-token",
                token_hash="a" * 64,
                scopes_json=["admin"],
                created_at=old_timestamp,
                revoked_at=old_timestamp,
            )
        )
        session.commit()

        dry_run = run_retention_cleanup(
            session,
            active_settings=active_settings,
            dry_run=True,
        )
        assert dry_run.audit_events == 1
        assert dry_run.auth_sessions == 1
        assert dry_run.revoked_api_tokens == 1
        session.rollback()

        result = run_retention_cleanup(
            session,
            active_settings=active_settings,
            dry_run=False,
        )
        session.commit()

        assert result.audit_events == 1
        assert result.auth_sessions == 1
        assert result.revoked_api_tokens == 1
        old_event = session.exec(select(AuditEvent).where(AuditEvent.action == "old.event")).first()
        old_session = session.exec(
            select(AuthSession).where(AuthSession.jti_hash == "old-session")
        ).first()
        old_token = session.exec(select(ApiToken).where(ApiToken.name == "old-token")).first()
        assert (
            session.exec(select(AuditEvent).where(AuditEvent.action == "retention.cleanup")).first()
            is not None
        )
        assert old_event is None
        assert old_session is None
        assert old_token is None

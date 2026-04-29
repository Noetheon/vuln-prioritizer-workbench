"""API token, GitHub export, and audit-event persistence helpers."""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from vuln_prioritizer.db.models import (
    ApiToken,
    AuditEvent,
    GitHubIssueExport,
    utc_now,
)


class SecurityAuditRepositoryMixin:
    """SecurityAudit repository methods."""

    session: Session

    def create_api_token(self, *, name: str, token_hash: str) -> ApiToken:
        token = ApiToken(name=name, token_hash=token_hash)
        self.session.add(token)
        self.session.flush()
        return token

    def get_active_api_token_by_hash(self, token_hash: str) -> ApiToken | None:
        return self.session.scalar(
            select(ApiToken).where(ApiToken.token_hash == token_hash, ApiToken.revoked_at.is_(None))
        )

    def has_active_api_tokens(self) -> bool:
        return (
            self.session.scalar(select(ApiToken.id).where(ApiToken.revoked_at.is_(None)).limit(1))
            is not None
        )

    def mark_api_token_used(self, token: ApiToken) -> None:
        token.last_used_at = utc_now()
        self.session.flush()

    def list_api_tokens(self) -> list[ApiToken]:
        statement = select(ApiToken).order_by(ApiToken.created_at.desc(), ApiToken.name)
        return list(self.session.scalars(statement))

    def get_api_token(self, token_id: str) -> ApiToken | None:
        return self.session.get(ApiToken, token_id)

    def revoke_api_token(self, token: ApiToken) -> ApiToken:
        token.revoked_at = utc_now()
        self.session.flush()
        return token

    def github_issue_export_exists(self, project_id: str, duplicate_key: str) -> bool:
        statement = select(GitHubIssueExport.id).where(
            GitHubIssueExport.project_id == project_id,
            GitHubIssueExport.duplicate_key == duplicate_key,
        )
        return self.session.scalar(statement) is not None

    def create_github_issue_export(
        self,
        *,
        project_id: str,
        finding_id: str | None,
        duplicate_key: str,
        title: str,
        html_url: str | None,
        issue_number: int | None,
    ) -> GitHubIssueExport:
        export = GitHubIssueExport(
            project_id=project_id,
            finding_id=finding_id,
            duplicate_key=duplicate_key,
            title=title,
            html_url=html_url,
            issue_number=issue_number,
        )
        self.session.add(export)
        self.session.flush()
        return export

    def create_audit_event(
        self,
        *,
        event_type: str,
        project_id: str | None = None,
        target_type: str | None = None,
        target_id: str | None = None,
        actor: str | None = None,
        message: str | None = None,
        metadata_json: dict[str, Any] | None = None,
    ) -> AuditEvent:
        event = AuditEvent(
            project_id=project_id,
            event_type=event_type,
            target_type=target_type,
            target_id=target_id,
            actor=actor,
            message=message,
            metadata_json=metadata_json or {},
        )
        self.session.add(event)
        self.session.flush()
        return event

    def list_project_audit_events(self, project_id: str, *, limit: int = 100) -> list[AuditEvent]:
        statement = (
            select(AuditEvent)
            .where(AuditEvent.project_id == project_id)
            .order_by(AuditEvent.created_at.desc())
            .limit(limit)
        )
        return list(self.session.scalars(statement))

    def list_audit_events(
        self,
        *,
        project_id: str | None = None,
        limit: int = 100,
    ) -> list[AuditEvent]:
        statement = select(AuditEvent)
        if project_id is not None:
            statement = statement.where(AuditEvent.project_id == project_id)
        statement = statement.order_by(AuditEvent.created_at.desc()).limit(limit)
        return list(self.session.scalars(statement))

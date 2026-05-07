"""GitHub issue export repository helpers."""

from __future__ import annotations

import uuid

from sqlalchemy import or_
from sqlmodel import Session, col, select

from app.models.github_issues import GitHubIssueExport


class GitHubIssueExportRepository:
    """Persistence helpers for GitHub issue export idempotency."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def export_exists(
        self,
        *,
        project_id: uuid.UUID,
        repository: str,
        duplicate_key: str,
    ) -> bool:
        statement = select(GitHubIssueExport.id).where(
            GitHubIssueExport.project_id == project_id,
            GitHubIssueExport.repository == repository,
            GitHubIssueExport.duplicate_key == duplicate_key,
            col(GitHubIssueExport.issue_url).is_not(None),
            col(GitHubIssueExport.issue_number).is_not(None),
        )
        return self.session.exec(statement).first() is not None

    def delete_incomplete_export(
        self,
        *,
        project_id: uuid.UUID,
        repository: str,
        duplicate_key: str,
    ) -> int:
        """Remove stale local reservations that never recorded a GitHub issue."""
        statement = select(GitHubIssueExport).where(
            GitHubIssueExport.project_id == project_id,
            GitHubIssueExport.repository == repository,
            GitHubIssueExport.duplicate_key == duplicate_key,
            or_(
                col(GitHubIssueExport.issue_url).is_(None),
                col(GitHubIssueExport.issue_number).is_(None),
            ),
        )
        records = list(self.session.exec(statement).all())
        for record in records:
            self.session.delete(record)
        self.session.flush()
        return len(records)

    def create_export(
        self,
        *,
        project_id: uuid.UUID,
        repository: str,
        duplicate_key: str,
        title: str,
        finding_id: uuid.UUID | None,
        issue_url: str | None,
        issue_number: int | None,
    ) -> GitHubIssueExport:
        export = GitHubIssueExport(
            project_id=project_id,
            repository=repository,
            duplicate_key=duplicate_key,
            title=title,
            finding_id=finding_id,
            issue_url=issue_url,
            issue_number=issue_number,
        )
        self.session.add(export)
        self.session.flush()
        return export

    def update_export_result(
        self,
        export: GitHubIssueExport,
        *,
        issue_url: str | None,
        issue_number: int | None,
    ) -> GitHubIssueExport:
        export.issue_url = issue_url
        export.issue_number = issue_number
        self.session.add(export)
        self.session.flush()
        return export

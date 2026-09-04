"""GitHub issue export repository helpers."""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import or_
from sqlmodel import Session, col, select

from app.models.github_issues import (
    GitHubIssueExport,
    github_issue_export_is_complete,
    normalize_github_repository,
)


class GitHubIssueExportRepository:
    """Persistence helpers for GitHub issue export idempotency."""

    def __init__(self, session: Session) -> None:
        """Initialize a new instance of GitHubIssueExportRepository."""
        self.session = session

    def export_exists(
        self,
        *,
        project_id: uuid.UUID,
        repository: str,
        duplicate_key: str,
        finding_id: uuid.UUID | None = None,
    ) -> bool:
        """
        Return whether this finding already has a completed external issue.

        ``duplicate_key`` remains the fallback identity for legacy rows without
        a finding link.  Linked exports also match on ``finding_id`` because a
        component alias merge may legitimately change the rendered key while
        the underlying Workbench finding and external GitHub issue stay the
        same.
        """
        repository = normalize_github_repository(repository)
        identity_predicate = col(GitHubIssueExport.duplicate_key) == duplicate_key
        if finding_id is not None:
            identity_predicate = or_(
                identity_predicate,
                col(GitHubIssueExport.finding_id) == finding_id,
            )
        exports = self._matching_exports(
            project_id=project_id,
            repository=repository,
            identity_predicate=identity_predicate,
        )
        return any(
            github_issue_export_is_complete(
                repository=export.repository,
                issue_url=export.issue_url,
                issue_number=export.issue_number,
            )
            for export in exports
        )

    def incomplete_export_exists(
        self,
        *,
        project_id: uuid.UUID,
        repository: str,
        duplicate_key: str,
        finding_id: uuid.UUID | None = None,
    ) -> bool:
        """Return whether an earlier external-create outcome is still unresolved."""
        repository = normalize_github_repository(repository)
        identity_predicate = col(GitHubIssueExport.duplicate_key) == duplicate_key
        if finding_id is not None:
            identity_predicate = or_(
                identity_predicate,
                col(GitHubIssueExport.finding_id) == finding_id,
            )
        exports = self._matching_exports(
            project_id=project_id,
            repository=repository,
            identity_predicate=identity_predicate,
        )
        return any(
            not github_issue_export_is_complete(
                repository=export.repository,
                issue_url=export.issue_url,
                issue_number=export.issue_number,
            )
            for export in exports
        )

    def project_has_incomplete_exports(self, project_id: uuid.UUID) -> bool:
        """Fail closed when any project export may still be in flight or unresolved."""
        exports = self.session.exec(
            select(GitHubIssueExport).where(GitHubIssueExport.project_id == project_id)
        )
        return any(
            not github_issue_export_is_complete(
                repository=export.repository,
                issue_url=export.issue_url,
                issue_number=export.issue_number,
            )
            for export in exports
        )

    def _matching_exports(
        self,
        *,
        project_id: uuid.UUID,
        repository: str,
        identity_predicate: Any,
    ) -> list[GitHubIssueExport]:
        """Load the bounded identity rows so completion uses one strict validator."""
        statement = select(GitHubIssueExport).where(
            GitHubIssueExport.project_id == project_id,
            GitHubIssueExport.repository == repository,
            identity_predicate,
        )
        return list(self.session.exec(statement).all())

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
        """Create export method for GitHubIssueExportRepository."""
        repository = normalize_github_repository(repository)
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
        """Update export result method for GitHubIssueExportRepository."""
        export.issue_url = issue_url
        export.issue_number = issue_number
        self.session.add(export)
        self.session.flush()
        return export

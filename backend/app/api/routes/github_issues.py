"""GitHub issue export routes for template Workbench findings."""

from __future__ import annotations

import uuid

from fastapi import APIRouter
from sqlalchemy.exc import IntegrityError

from app.api.deps import ScopedReportUser, SessionDep
from app.api.routes.workbench_access import require_visible_project
from app.models import (
    GitHubIssueExportCreate,
    GitHubIssueExportPublic,
    GitHubIssueExportRecord,
    GitHubIssuePreviewCreate,
    GitHubIssuePreviewPublic,
)
from app.repositories import GitHubIssueExportRepository
from app.services import (
    build_github_issue_preview_items,
    create_github_issue,
    github_export_token,
    github_repository_path,
)
from app.services.audit import record_audit_event

router = APIRouter(tags=["github-issues"])


@router.post(
    "/projects/{project_id}/github/issues/preview",
    response_model=GitHubIssuePreviewPublic,
)
def preview_project_github_issues(
    project_id: uuid.UUID,
    payload: GitHubIssuePreviewCreate,
    session: SessionDep,
    current_user: ScopedReportUser,
) -> GitHubIssuePreviewPublic:
    """Prepare GitHub issue markdown for selected or top-ranked visible findings."""
    require_visible_project(session, current_user, project_id)
    items = build_github_issue_preview_items(session, project_id=project_id, payload=payload)
    return GitHubIssuePreviewPublic(dry_run=True, count=len(items), data=items)


@router.post(
    "/projects/{project_id}/github/issues/export",
    response_model=GitHubIssueExportPublic,
)
def export_project_github_issues(
    project_id: uuid.UUID,
    payload: GitHubIssueExportCreate,
    session: SessionDep,
    current_user: ScopedReportUser,
) -> GitHubIssueExportPublic:
    """Dry-run or explicitly create GitHub issues for selected visible findings."""
    require_visible_project(session, current_user, project_id)
    repository_path = github_repository_path(payload.repository)
    token = None if payload.dry_run else github_export_token(payload.token_env)
    repo = GitHubIssueExportRepository(session)
    preview_items = build_github_issue_preview_items(
        session,
        project_id=project_id,
        payload=payload,
    )

    data: list[GitHubIssueExportRecord] = []
    batch_keys: set[str] = set()
    created_count = 0
    skipped_count = 0
    for item in preview_items:
        duplicate = item.duplicate_key in batch_keys or repo.export_exists(
            project_id=project_id,
            repository=payload.repository,
            duplicate_key=item.duplicate_key,
        )
        if duplicate:
            skipped_count += 1
            data.append(
                GitHubIssueExportRecord(
                    **item.model_dump(),
                    status="skipped_duplicate",
                    issue_url=None,
                    issue_number=None,
                )
            )
        elif payload.dry_run:
            data.append(
                GitHubIssueExportRecord(
                    **item.model_dump(),
                    status="preview",
                    issue_url=None,
                    issue_number=None,
                )
            )
        else:
            try:
                with session.begin_nested():
                    reserved_export = repo.create_export(
                        project_id=project_id,
                        repository=payload.repository,
                        duplicate_key=item.duplicate_key,
                        title=item.title,
                        finding_id=item.finding_id,
                        issue_url=None,
                        issue_number=None,
                    )
            except IntegrityError:
                skipped_count += 1
                data.append(
                    GitHubIssueExportRecord(
                        **item.model_dump(),
                        status="skipped_duplicate",
                        issue_url=None,
                        issue_number=None,
                    )
                )
                batch_keys.add(item.duplicate_key)
                continue
            issue = create_github_issue(
                repository_path=repository_path,
                token=token or "",
                item=item,
            )
            repo.update_export_result(
                reserved_export,
                issue_url=issue["issue_url"],
                issue_number=issue["issue_number"],
            )
            created_count += 1
            data.append(
                GitHubIssueExportRecord(
                    **item.model_dump(),
                    status="created",
                    issue_url=issue["issue_url"],
                    issue_number=issue["issue_number"],
                )
            )
        batch_keys.add(item.duplicate_key)
    record_audit_event(
        session,
        action="github_issue.export",
        resource_type="github_issue_export",
        actor=current_user,
        project_id=project_id,
        detail={
            "repository": payload.repository,
            "dry_run": payload.dry_run,
            "created_count": created_count,
            "skipped_count": skipped_count,
            "count": len(data),
        },
    )
    session.commit()
    return GitHubIssueExportPublic(
        dry_run=payload.dry_run,
        created_count=created_count,
        skipped_count=skipped_count,
        count=len(data),
        data=data,
    )

"""GitHub issue export routes for Workbench findings."""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, HTTPException
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session

from app.api.deps import LocalActor, SessionDep
from app.api.routes.workbench_access import require_project
from app.core.local_actor import LocalWorkbenchActor
from app.models import (
    AuditEventStatus,
    GitHubIssueExportCreate,
    GitHubIssueExportPublic,
    GitHubIssueExportRecord,
    GitHubIssuePreviewCreate,
    GitHubIssuePreviewPublic,
)
from app.repositories import GitHubIssueExportRepository
from app.services import (
    GitHubIssueCreationError,
    build_github_issue_preview_items,
    create_github_issue,
    github_export_token,
    github_repository_path,
)
from app.services.audit import record_audit_event
from app.services.decision_scope_lock import lock_project_decision_scope

router = APIRouter(tags=["github-issues"])


@router.post(
    "/projects/{project_id}/github/issues/preview",
    response_model=GitHubIssuePreviewPublic,
)
def preview_project_github_issues(
    project_id: uuid.UUID,
    payload: GitHubIssuePreviewCreate,
    session: SessionDep,
    local_actor: LocalActor,
) -> GitHubIssuePreviewPublic:
    """Prepare GitHub issue markdown for selected or top-ranked visible findings."""
    require_project(session, project_id)
    try:
        items = build_github_issue_preview_items(session, project_id=project_id, payload=payload)
    except HTTPException as exc:
        _record_github_issue_preview_audit(
            session,
            project_id=project_id,
            payload=payload,
            actor=local_actor,
            status="failure",
            count=0,
            failure_kind=_http_failure_kind(exc),
            http_status_code=exc.status_code,
        )
        session.commit()
        raise
    _record_github_issue_preview_audit(
        session,
        project_id=project_id,
        payload=payload,
        actor=local_actor,
        status="success",
        count=len(items),
    )
    session.commit()
    return GitHubIssuePreviewPublic(dry_run=True, count=len(items), data=items)


@router.post(
    "/projects/{project_id}/github/issues/export",
    response_model=GitHubIssueExportPublic,
)
def export_project_github_issues(
    project_id: uuid.UUID,
    payload: GitHubIssueExportCreate,
    session: SessionDep,
    local_actor: LocalActor,
) -> GitHubIssueExportPublic:
    """Dry-run or explicitly create GitHub issues for selected visible findings."""
    _lock_existing_export_project(session, project_id)
    repository_path = github_repository_path(payload.repository)
    try:
        token = None if payload.dry_run else github_export_token(payload.token_env)
    except HTTPException as exc:
        _record_github_issue_export_audit(
            session,
            project_id=project_id,
            payload=payload,
            actor=local_actor,
            status="failure",
            data=[],
            created_count=0,
            skipped_count=0,
            failure_kind=_token_failure_kind(exc),
            http_status_code=exc.status_code,
        )
        session.commit()
        raise
    repo = GitHubIssueExportRepository(session)
    try:
        preview_items = build_github_issue_preview_items(
            session,
            project_id=project_id,
            payload=payload,
        )
    except HTTPException as exc:
        _record_github_issue_export_audit(
            session,
            project_id=project_id,
            payload=payload,
            actor=local_actor,
            status="failure",
            data=[],
            created_count=0,
            skipped_count=0,
            failure_kind=_http_failure_kind(exc),
            http_status_code=exc.status_code,
        )
        session.commit()
        raise

    data: list[GitHubIssueExportRecord] = []
    batch_keys: set[str] = set()
    created_count = 0
    skipped_count = 0
    stale_reservation_count = 0
    for item in preview_items:
        # A reservation commit releases the project row lock before the network
        # call. Reacquire it before each later item; the incomplete reservation
        # itself blocks deletion while GitHub's outcome is unknown.
        _lock_existing_export_project(session, project_id)
        duplicate = item.duplicate_key in batch_keys or repo.export_exists(
            project_id=project_id,
            repository=payload.repository,
            duplicate_key=item.duplicate_key,
            finding_id=item.finding_id,
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
            unresolved_reservation = repo.incomplete_export_exists(
                project_id=project_id,
                repository=payload.repository,
                duplicate_key=item.duplicate_key,
                finding_id=item.finding_id,
            )
            if unresolved_reservation:
                _record_github_issue_export_audit(
                    session,
                    project_id=project_id,
                    payload=payload,
                    actor=local_actor,
                    status="failure",
                    data=data,
                    created_count=created_count,
                    skipped_count=skipped_count,
                    stale_reservation_count=stale_reservation_count,
                    failure_kind="reservation_unresolved",
                    http_status_code=409,
                    failed_item=item,
                    reservation_outcome="blocked_unresolved",
                )
                session.commit()
                raise HTTPException(
                    status_code=409,
                    detail=(
                        "A previous GitHub issue creation outcome is unresolved. "
                        "Verify the remote repository before clearing the local reservation."
                    ),
                )
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
                completed_winner = repo.export_exists(
                    project_id=project_id,
                    repository=payload.repository,
                    duplicate_key=item.duplicate_key,
                    finding_id=item.finding_id,
                )
                if completed_winner:
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
                unresolved_winner = repo.incomplete_export_exists(
                    project_id=project_id,
                    repository=payload.repository,
                    duplicate_key=item.duplicate_key,
                    finding_id=item.finding_id,
                )
                _record_github_issue_export_audit(
                    session,
                    project_id=project_id,
                    payload=payload,
                    actor=local_actor,
                    status="failure",
                    data=data,
                    created_count=created_count,
                    skipped_count=skipped_count,
                    stale_reservation_count=stale_reservation_count,
                    failure_kind=(
                        "reservation_unresolved" if unresolved_winner else "reservation_conflict"
                    ),
                    http_status_code=409,
                    failed_item=item,
                    reservation_outcome=(
                        "blocked_unresolved"
                        if unresolved_winner
                        else "blocked_conflict_without_winner"
                    ),
                )
                session.commit()
                raise HTTPException(
                    status_code=409,
                    detail=(
                        "A concurrent GitHub export reservation is unresolved."
                        if unresolved_winner
                        else "GitHub export reservation state changed; retry after refreshing."
                    ),
                )
            # The reservation must survive a process crash or an ambiguous
            # network outcome after GitHub may already have created the issue.
            session.commit()
            try:
                issue = create_github_issue(
                    repository_path=repository_path,
                    token=token or "",
                    item=item,
                )
            except HTTPException as exc:
                uncertain_outcome = _github_create_outcome_is_uncertain(exc)
                if not uncertain_outcome:
                    session.delete(reserved_export)
                    session.flush()
                _record_github_issue_export_audit(
                    session,
                    project_id=project_id,
                    payload=payload,
                    actor=local_actor,
                    status="failure",
                    data=data,
                    created_count=created_count,
                    skipped_count=skipped_count,
                    stale_reservation_count=stale_reservation_count,
                    failure_kind=_github_create_failure_kind(exc),
                    http_status_code=exc.status_code,
                    upstream_status_code=(
                        exc.upstream_status_code
                        if isinstance(exc, GitHubIssueCreationError)
                        else None
                    ),
                    failed_item=item,
                    reservation_outcome=(
                        "retained_unresolved" if uncertain_outcome else "removed_confirmed_failure"
                    ),
                )
                session.commit()
                raise
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
    _record_github_issue_export_audit(
        session,
        project_id=project_id,
        payload=payload,
        actor=local_actor,
        status="success",
        data=data,
        created_count=created_count,
        skipped_count=skipped_count,
        stale_reservation_count=stale_reservation_count,
    )
    session.commit()
    return GitHubIssueExportPublic(
        dry_run=payload.dry_run,
        created_count=created_count,
        skipped_count=skipped_count,
        count=len(data),
        data=data,
    )


def _lock_existing_export_project(session: Session, project_id: uuid.UUID) -> None:
    """Serialize export reservations with project deletion and reject stale callers."""
    require_project(session, project_id)
    lock_project_decision_scope(session, project_id)


def _record_github_issue_preview_audit(
    session: Session,
    *,
    project_id: uuid.UUID,
    payload: GitHubIssuePreviewCreate,
    actor: LocalWorkbenchActor,
    status: AuditEventStatus,
    count: int,
    failure_kind: str | None = None,
    http_status_code: int | None = None,
) -> None:
    detail: dict[str, Any] = {
        "dry_run": True,
        "count": count,
        "requested_finding_count": len(payload.finding_ids),
        "limit": payload.limit,
        "priority": str(payload.priority) if payload.priority is not None else None,
        "include_evidence_refs": payload.include_evidence_refs,
    }
    if failure_kind is not None:
        detail["failure_kind"] = failure_kind
    if http_status_code is not None:
        detail["http_status_code"] = http_status_code
    record_audit_event(
        session,
        action="github_issue.preview",
        resource_type="github_issue_preview",
        status=status,
        actor=actor,
        project_id=project_id,
        detail=detail,
    )


def _record_github_issue_export_audit(
    session: Session,
    *,
    project_id: uuid.UUID,
    payload: GitHubIssueExportCreate,
    actor: LocalWorkbenchActor,
    status: AuditEventStatus,
    data: list[GitHubIssueExportRecord],
    created_count: int,
    skipped_count: int,
    stale_reservation_count: int = 0,
    failure_kind: str | None = None,
    http_status_code: int | None = None,
    upstream_status_code: int | None = None,
    failed_item: Any | None = None,
    reservation_outcome: str | None = None,
) -> None:
    detail: dict[str, Any] = {
        "repository": payload.repository,
        "dry_run": payload.dry_run,
        "created_count": created_count,
        "skipped_count": skipped_count,
        "failed_count": 1 if status == "failure" and failed_item is not None else 0,
        "count": len(data),
        "status_counts": _export_status_counts(data),
        "stale_reservation_count": stale_reservation_count,
        "token_env_configured": bool(payload.token_env),
    }
    if failure_kind is not None:
        detail["failure_kind"] = failure_kind
    if http_status_code is not None:
        detail["http_status_code"] = http_status_code
    if upstream_status_code is not None:
        detail["upstream_status_code"] = upstream_status_code
    if reservation_outcome is not None:
        detail["reservation_outcome"] = reservation_outcome
    if failed_item is not None:
        detail["failed_finding_id"] = str(failed_item.finding_id)
        detail["failed_cve_id"] = failed_item.cve_id
    record_audit_event(
        session,
        action="github_issue.export",
        resource_type="github_issue_export",
        status=status,
        actor=actor,
        project_id=project_id,
        detail=detail,
    )


def _export_status_counts(data: list[GitHubIssueExportRecord]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in data:
        counts[item.status] = counts.get(item.status, 0) + 1
    return counts


def _github_create_failure_kind(exc: HTTPException) -> str:
    if isinstance(exc, GitHubIssueCreationError):
        return exc.failure_kind
    return _http_failure_kind(exc)


def _github_create_outcome_is_uncertain(exc: HTTPException) -> bool:
    """Return whether a failed POST may still have created a remote issue."""
    if not isinstance(exc, GitHubIssueCreationError):
        return False
    if exc.failure_kind in {"invalid_response", "network_error"}:
        return True
    status = exc.upstream_status_code
    return status is None or status >= 500 or status in {408, 425, 429}


def _token_failure_kind(exc: HTTPException) -> str:
    detail = str(exc.detail)
    if "token_env is required" in detail:
        return "token_env_required"
    if "is not configured" in detail:
        return "token_not_configured"
    return _http_failure_kind(exc)


def _http_failure_kind(exc: HTTPException) -> str:
    return f"http_{exc.status_code}"

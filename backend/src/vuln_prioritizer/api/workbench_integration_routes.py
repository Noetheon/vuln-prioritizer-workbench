"""GitHub issue and ticket-sync API routes."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from vuln_prioritizer.api.deps import get_db_session
from vuln_prioritizer.api.schemas import (
    GitHubIssueExportRequest,
    GitHubIssueExportResponse,
    GitHubIssuePreviewRequest,
    GitHubIssuePreviewResponse,
    TicketSyncExportRequest,
    TicketSyncPreviewRequest,
    TicketSyncResponse,
)
from vuln_prioritizer.api.workbench_findings import _filter_findings, _sort_findings
from vuln_prioritizer.api.workbench_github import (
    _create_github_issue,
    _github_export_token,
    _github_issue_preview_payload,
    _github_repository_path,
)
from vuln_prioritizer.api.workbench_route_support import (
    _ticket_sync_preview_items,
)
from vuln_prioritizer.api.workbench_tickets import (
    _create_jira_issue,
    _create_servicenow_ticket,
    _jira_project_key,
    _servicenow_table,
    _ticket_base_url,
    _ticket_sync_token,
)
from vuln_prioritizer.db.repositories import WorkbenchRepository

router = APIRouter()


@router.post(
    "/projects/{project_id}/github/issues/preview",
    response_model=GitHubIssuePreviewResponse,
)
def preview_github_issues(
    project_id: str,
    payload: GitHubIssuePreviewRequest,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    if repo.get_project(project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    findings = _sort_findings(
        _filter_findings(
            repo.list_project_findings(project_id),
            priority=payload.priority,
            status=None,
            q=None,
            kev=None,
            owner=None,
            service=None,
            min_epss=None,
            min_cvss=None,
        ),
        sort="operational",
    )
    preview_items = []
    duplicate_keys: set[str] = set()
    for finding in findings:
        item = _github_issue_preview_payload(finding, payload=payload)
        if item["duplicate_key"] in duplicate_keys:
            continue
        duplicate_keys.add(item["duplicate_key"])
        preview_items.append(item)
        if len(preview_items) >= payload.limit:
            break
    return {
        "dry_run": True,
        "items": preview_items,
    }


@router.post(
    "/projects/{project_id}/github/issues/export",
    response_model=GitHubIssueExportResponse,
)
def export_github_issues(
    project_id: str,
    payload: GitHubIssueExportRequest,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    if repo.get_project(project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    repository_path = _github_repository_path(payload.repository)
    token = None if payload.dry_run else _github_export_token(payload.token_env)
    findings = _sort_findings(
        _filter_findings(
            repo.list_project_findings(project_id),
            priority=payload.priority,
            status=None,
            q=None,
            kev=None,
            owner=None,
            service=None,
            min_epss=None,
            min_cvss=None,
        ),
        sort="operational",
    )
    exported_items = []
    batch_keys: set[str] = set()
    created_count = 0
    skipped_count = 0
    for finding in findings:
        item = _github_issue_preview_payload(finding, payload=payload)
        duplicate_key = item["duplicate_key"]
        already_exported = repo.github_issue_export_exists(project_id, duplicate_key)
        if duplicate_key in batch_keys or already_exported:
            skipped_count += 1
            exported_items.append(
                {
                    **item,
                    "status": "skipped_duplicate",
                    "issue_url": None,
                    "issue_number": None,
                }
            )
        elif payload.dry_run:
            exported_items.append(
                {
                    **item,
                    "status": "preview",
                    "issue_url": None,
                    "issue_number": None,
                }
            )
        else:
            if token is None:
                raise HTTPException(status_code=422, detail="GitHub token is not configured.")
            issue = _create_github_issue(
                repository_path=repository_path,
                token=token,
                item=item,
            )
            repo.create_github_issue_export(
                project_id=project_id,
                finding_id=finding.id,
                duplicate_key=duplicate_key,
                title=item["title"],
                html_url=issue["html_url"],
                issue_number=issue["number"],
            )
            created_count += 1
            exported_items.append(
                {
                    **item,
                    "status": "created",
                    "issue_url": issue["html_url"],
                    "issue_number": issue["number"],
                }
            )
        batch_keys.add(duplicate_key)
        if len(exported_items) >= payload.limit:
            break
    repo.create_audit_event(
        project_id=project_id,
        event_type="github_issues.exported",
        target_type="project",
        target_id=project_id,
        message="GitHub issue export was processed.",
        metadata_json={
            "dry_run": payload.dry_run,
            "created_count": created_count,
            "skipped_count": skipped_count,
            "item_count": len(exported_items),
        },
    )
    session.commit()
    return {
        "dry_run": payload.dry_run,
        "created_count": created_count,
        "skipped_count": skipped_count,
        "items": exported_items,
    }


@router.post(
    "/projects/{project_id}/tickets/preview",
    response_model=TicketSyncResponse,
)
def preview_ticket_sync(
    project_id: str,
    payload: TicketSyncPreviewRequest,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    if repo.get_project(project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    return {
        "dry_run": True,
        "created_count": 0,
        "skipped_count": 0,
        "items": [
            {**item, "status": "preview", "ticket_url": None, "external_id": None}
            for item in _ticket_sync_preview_items(repo, project_id, payload)
        ],
    }


@router.post(
    "/projects/{project_id}/tickets/export",
    response_model=TicketSyncResponse,
)
def export_ticket_sync(
    project_id: str,
    payload: TicketSyncExportRequest,
    session: Annotated[Session, Depends(get_db_session)],
) -> dict[str, Any]:
    repo = WorkbenchRepository(session)
    if repo.get_project(project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    base_url = None if payload.dry_run else _ticket_base_url(payload.base_url)
    token = None if payload.dry_run else _ticket_sync_token(payload.token_env)
    jira_project_key = (
        _jira_project_key(payload.jira_project_key)
        if payload.provider == "jira" and not payload.dry_run
        else None
    )
    servicenow_table = (
        _servicenow_table(payload.servicenow_table)
        if payload.provider == "servicenow"
        else payload.servicenow_table
    )
    exported_items: list[dict[str, Any]] = []
    batch_keys: set[str] = set()
    created_count = 0
    skipped_count = 0
    for item in _ticket_sync_preview_items(repo, project_id, payload):
        duplicate_key = item["duplicate_key"]
        stored_duplicate_key = f"{payload.provider}:{duplicate_key}"
        already_exported = repo.github_issue_export_exists(project_id, stored_duplicate_key)
        if duplicate_key in batch_keys or already_exported:
            skipped_count += 1
            exported_items.append(
                {**item, "status": "skipped_duplicate", "ticket_url": None, "external_id": None}
            )
        elif payload.dry_run:
            exported_items.append(
                {**item, "status": "preview", "ticket_url": None, "external_id": None}
            )
        else:
            if base_url is None or token is None:
                raise HTTPException(status_code=422, detail="Ticket sync is not configured.")
            if payload.provider == "jira":
                if jira_project_key is None:
                    raise HTTPException(status_code=422, detail="jira_project_key is required.")
                ticket = _create_jira_issue(
                    base_url=base_url,
                    token=token,
                    project_key=jira_project_key,
                    item=item,
                )
            else:
                ticket = _create_servicenow_ticket(
                    base_url=base_url,
                    token=token,
                    table=servicenow_table,
                    item=item,
                )
            repo.create_github_issue_export(
                project_id=project_id,
                finding_id=str(item.get("finding_id")) if item.get("finding_id") else None,
                duplicate_key=stored_duplicate_key,
                title=str(item.get("title") or item.get("cve_id") or "Ticket sync item"),
                html_url=ticket.get("ticket_url"),
                issue_number=None,
            )
            created_count += 1
            exported_items.append({**item, "status": "created", **ticket})
        batch_keys.add(duplicate_key)
        if len(exported_items) >= payload.limit:
            break
    repo.create_audit_event(
        project_id=project_id,
        event_type="ticket_sync.exported",
        target_type="project",
        target_id=project_id,
        message=f"{payload.provider} ticket sync was processed.",
        metadata_json={
            "provider": payload.provider,
            "dry_run": payload.dry_run,
            "created_count": created_count,
            "skipped_count": skipped_count,
            "item_count": len(exported_items),
        },
    )
    session.commit()
    return {
        "dry_run": payload.dry_run,
        "created_count": created_count,
        "skipped_count": skipped_count,
        "items": exported_items,
    }

"""Transactional project deletion with fail-closed external export safety."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlmodel import Session

from app.core.config import Settings
from app.core.local_actor import LocalWorkbenchActor
from app.models import Project
from app.repositories import GitHubIssueExportRepository, ProjectRepository
from app.services.artifact_cleanup import (
    ProjectArtifactCleanupResult,
    cleanup_project_artifacts,
)
from app.services.audit import record_audit_event, update_audit_event
from app.services.decision_scope_lock import (
    ProjectDecisionLockError,
    lock_project_decision_scope,
)
from app.services.project_lifecycle_lock import (
    ProjectLifecycleLease,
    lock_project_lifecycle,
    validate_project_lifecycle_lease,
)


class ProjectDeletionBlockedError(RuntimeError):
    """Raised when unresolved external side effects make deletion unsafe."""


class ProjectArtifactCleanupError(RuntimeError):
    """Raised after relational deletion when managed artifact cleanup fails."""


@dataclass(frozen=True, slots=True)
class ProjectDeletionResult:
    """Completed relational and managed-artifact project deletion."""

    project_id: uuid.UUID
    artifact_cleanup: ProjectArtifactCleanupResult


def delete_project_with_artifact_cleanup(
    *,
    session: Session,
    settings: Settings,
    project: Project,
    actor: LocalWorkbenchActor,
    audit_action: str = "project.delete",
    audit_detail: dict[str, Any] | None = None,
    lifecycle_lease: ProjectLifecycleLease | None = None,
) -> ProjectDeletionResult:
    """Delete one project behind lifecycle and decision locks."""
    expected_created_at = project.created_at
    if lifecycle_lease is None:
        with lock_project_lifecycle(settings, project.id) as acquired_lease:
            return _delete_project_with_artifact_cleanup_locked(
                session=session,
                settings=settings,
                project=project,
                actor=actor,
                audit_action=audit_action,
                audit_detail=audit_detail,
                lifecycle_lease=acquired_lease,
                expected_created_at=expected_created_at,
            )
    return _delete_project_with_artifact_cleanup_locked(
        session=session,
        settings=settings,
        project=project,
        actor=actor,
        audit_action=audit_action,
        audit_detail=audit_detail,
        lifecycle_lease=lifecycle_lease,
        expected_created_at=expected_created_at,
    )


def _delete_project_with_artifact_cleanup_locked(
    *,
    session: Session,
    settings: Settings,
    project: Project,
    actor: LocalWorkbenchActor,
    audit_action: str,
    audit_detail: dict[str, Any] | None,
    lifecycle_lease: ProjectLifecycleLease,
    expected_created_at: datetime,
) -> ProjectDeletionResult:
    """Delete relational state and artifacts while the lifecycle lock is held."""
    project_id = project.id
    validate_project_lifecycle_lease(
        lifecycle_lease,
        settings=settings,
        project_id=project_id,
    )
    lock_project_decision_scope(session, project_id)
    current = session.get(Project, project_id, populate_existing=True)
    if current is None:
        raise ProjectDecisionLockError(f"Project {project_id} does not exist.")
    if current.created_at != expected_created_at:
        raise ProjectDeletionBlockedError(
            "Project deletion was cancelled because that ID was recreated while the request waited."
        )

    if GitHubIssueExportRepository(session).project_has_incomplete_exports(project_id):
        record_audit_event(
            session,
            action=audit_action,
            resource_type="project",
            resource_id=project_id,
            actor=actor,
            project_id=project_id,
            status="failure",
            detail={
                **dict(audit_detail or {}),
                "failure_kind": "github_export_unresolved",
                "artifact_cleanup_status": "not_started",
            },
        )
        session.commit()
        raise ProjectDeletionBlockedError(
            "Project deletion is blocked while a GitHub issue export outcome "
            "is in flight or unresolved. Verify the remote issue first."
        )

    cleanup_plan = cleanup_project_artifacts(
        settings=settings,
        project_id=project_id,
        dry_run=True,
    )
    delete_event = record_audit_event(
        session,
        action=audit_action,
        resource_type="project",
        resource_id=project_id,
        actor=actor,
        project_id=project_id,
        detail={
            **dict(audit_detail or {}),
            "name": current.name,
            "artifact_cleanup_status": "pending",
            "scheduled_artifact_paths": list(cleanup_plan.removed_paths),
            "missing_artifact_paths": list(cleanup_plan.missing_paths),
        },
    )
    delete_event_id = delete_event.id
    ProjectRepository(session).delete_project(current)
    # A database error must leave the managed evidence trees untouched. Commit
    # the relational deletion before beginning destructive filesystem cleanup.
    session.commit()

    try:
        cleanup_result = cleanup_project_artifacts(
            settings=settings,
            project_id=project_id,
        )
    except OSError as exc:
        session.rollback()
        if (
            update_audit_event(
                session,
                delete_event_id,
                status="failure",
                detail_patch={
                    "artifact_cleanup_status": "failed",
                    "artifact_cleanup_error_type": type(exc).__name__,
                },
            )
            is not None
        ):
            session.commit()
        raise ProjectArtifactCleanupError(
            "Project data was deleted, but managed artifact cleanup failed. "
            f"Review the {audit_action} audit event."
        ) from exc

    if (
        update_audit_event(
            session,
            delete_event_id,
            detail_patch={
                "artifact_cleanup_status": "completed",
                "removed_artifact_paths": list(cleanup_result.removed_paths),
                "missing_artifact_paths": list(cleanup_result.missing_paths),
            },
        )
        is not None
    ):
        session.commit()
    return ProjectDeletionResult(
        project_id=project_id,
        artifact_cleanup=cleanup_result,
    )

"""Durable local Workbench job journal helpers."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, TypeVar

from sqlalchemy.orm import Session

from vuln_prioritizer.db.models import WorkbenchJob
from vuln_prioritizer.db.repositories import WorkbenchRepository

T = TypeVar("T")


def run_sync_workbench_job(
    *,
    session: Session,
    kind: str,
    project_id: str | None = None,
    target_type: str | None = None,
    target_id: str | None = None,
    payload_json: dict[str, Any] | None = None,
    idempotency_key: str | None = None,
    worker_id: str = "sync",
    preserve_side_effects_on: tuple[type[Exception], ...] = (),
    operation: Callable[[WorkbenchRepository, WorkbenchJob], T],
    result: Callable[[T], dict[str, Any]],
) -> tuple[WorkbenchJob, T]:
    """Record a durable job and execute the operation in the current request.

    The Workbench stays backward-compatible and local-first: existing endpoints still complete
    synchronously, while the job record gives users progress, logs, retry state, and audit context.
    """
    repo = WorkbenchRepository(session)
    job = repo.enqueue_workbench_job(
        kind=kind,
        project_id=project_id,
        target_type=target_type,
        target_id=target_id,
        payload_json=payload_json,
        idempotency_key=idempotency_key,
    )
    if job.status == "completed":
        value = operation(repo, job)
        return job, value
    repo.start_workbench_job(job, worker_id=worker_id)
    repo.update_workbench_job_progress(job, progress=25, message=f"{kind} started")
    nested = session.begin_nested()
    try:
        value = operation(repo, job)
    except Exception as exc:
        if preserve_side_effects_on and isinstance(exc, preserve_side_effects_on):
            nested.commit()
        else:
            nested.rollback()
        session.refresh(job)
        if hasattr(exc, "job_id"):
            setattr(exc, "job_id", job.id)
        repo.fail_workbench_job(job, error_message=str(exc), retryable=False)
        session.commit()
        raise
    nested.commit()
    repo.complete_workbench_job(job, result_json=result(value))
    return job, value

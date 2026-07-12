"""Standalone DB-backed worker for durable Workbench workflows."""

from __future__ import annotations

import argparse
import socket
import threading
import time
import uuid
from collections.abc import Sequence
from dataclasses import dataclass

from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError
from sqlmodel import Session

from app.core.config import Settings, load_settings
from app.core.db import create_db_engine
from app.models import WorkflowRunStatus
from app.repositories import RuntimeHeartbeatRepository, WorkflowRepository
from app.services.workflows import finish_cancelled_workflow
from app.workers.workflow_handlers import (
    WorkflowCancelled,
    WorkflowNonRetryableError,
    execute_workflow_handler,
)

WORKFLOW_WORKER_SERVICE_NAME = "workflow-worker"


@dataclass(frozen=True, slots=True)
class WorkerTickResult:
    """One worker polling tick result."""

    claimed: int = 0
    completed: int = 0
    cancelled: int = 0
    retried_or_failed: int = 0


def run_worker_once(
    *,
    engine: Engine,
    settings: Settings,
    worker_id: str,
    queue_names: Sequence[str] = ("default",),
    lease_seconds: int = 300,
    retry_delay_seconds: int = 30,
    limit: int = 1,
) -> WorkerTickResult:
    """Claim and execute at most ``limit`` due workflow jobs."""
    with Session(engine) as session:
        _record_worker_service_heartbeat_in_session(
            session,
            worker_id=worker_id,
            queue_names=queue_names,
            lease_seconds=lease_seconds,
        )
        repository = WorkflowRepository(session)
        repository.release_expired_leases(delay_seconds=retry_delay_seconds)
        workflows = repository.claim_due_workflows(
            worker_id=worker_id,
            queue_names=queue_names,
            lease_seconds=lease_seconds,
            limit=limit,
        )
        workflow_ids = [workflow.id for workflow in workflows]
        session.commit()

    completed = 0
    cancelled = 0
    retried_or_failed = 0
    for workflow_id in workflow_ids:
        outcome = _execute_claimed_workflow(
            engine=engine,
            settings=settings,
            worker_id=worker_id,
            workflow_id=workflow_id,
            lease_seconds=lease_seconds,
            retry_delay_seconds=retry_delay_seconds,
        )
        if outcome == "completed":
            completed += 1
        elif outcome == "cancelled":
            cancelled += 1
        elif outcome == "retried_or_failed":
            retried_or_failed += 1
    if workflow_ids:
        _record_worker_service_heartbeat(
            engine=engine,
            worker_id=worker_id,
            queue_names=queue_names,
            lease_seconds=lease_seconds,
        )
    return WorkerTickResult(
        claimed=len(workflow_ids),
        completed=completed,
        cancelled=cancelled,
        retried_or_failed=retried_or_failed,
    )


def run_worker_loop(
    *,
    engine: Engine,
    settings: Settings,
    worker_id: str,
    queue_names: Sequence[str] = ("default",),
    lease_seconds: int = 300,
    retry_delay_seconds: int = 30,
    poll_interval_seconds: float = 2.0,
    max_jobs: int | None = None,
    stop_event: threading.Event | None = None,
) -> None:
    """Run the durable workflow worker until interrupted or max_jobs is reached."""
    processed = 0
    while max_jobs is None or processed < max_jobs:
        if stop_event is not None and stop_event.is_set():
            return
        result = run_worker_once(
            engine=engine,
            settings=settings,
            worker_id=worker_id,
            queue_names=queue_names,
            lease_seconds=lease_seconds,
            retry_delay_seconds=retry_delay_seconds,
        )
        processed += result.completed + result.cancelled + result.retried_or_failed
        if result.claimed == 0:
            interval = max(0.1, poll_interval_seconds)
            if stop_event is not None:
                if stop_event.wait(interval):
                    return
            else:
                time.sleep(interval)


def _execute_claimed_workflow(
    *,
    engine: Engine,
    settings: Settings,
    worker_id: str,
    workflow_id: uuid.UUID,
    lease_seconds: int,
    retry_delay_seconds: int,
) -> str:
    try:
        with Session(engine) as session:
            repository = WorkflowRepository(session)
            workflow = repository.require_workflow(workflow_id)
            if workflow.locked_by != worker_id or workflow.status != WorkflowRunStatus.RUNNING:
                return "skipped"
            repository.record_worker_heartbeat(
                workflow.id,
                worker_id=worker_id,
                lease_seconds=lease_seconds,
            )
            try:
                execute_workflow_handler(
                    session,
                    settings=settings,
                    workflow=workflow,
                    worker_id=worker_id,
                    lease_seconds=lease_seconds,
                )
            except WorkflowNonRetryableError:
                session.commit()
                return "retried_or_failed"
            session.commit()
            return "completed"
    except WorkflowNonRetryableError as exc:
        with Session(engine) as session:
            repository = WorkflowRepository(session)
            current_workflow = repository.get_workflow(workflow_id)
            if (
                current_workflow is not None
                and current_workflow.status == WorkflowRunStatus.RUNNING
            ):
                repository.finish_workflow(
                    workflow_id,
                    status=WorkflowRunStatus.FAILED,
                    stage=current_workflow.current_stage or "failed",
                    message=str(exc),
                    error_message=str(exc),
                    error_json={
                        "message": str(exc),
                        "error_type": "WorkflowNonRetryableError",
                    },
                    diagnostics_json={
                        "message": str(exc),
                        "error_type": "WorkflowNonRetryableError",
                    },
                    terminal_code="non_retryable_failed",
                )
            session.commit()
        return "retried_or_failed"
    except WorkflowCancelled:
        with Session(engine) as session:
            finish_cancelled_workflow(
                session,
                workflow_id,
                message="Workflow cancelled by user request.",
            )
            session.commit()
        return "cancelled"
    except Exception as exc:
        with Session(engine) as session:
            repository = WorkflowRepository(session)
            current_workflow = repository.get_workflow(workflow_id)
            if current_workflow is None or current_workflow.status in {
                WorkflowRunStatus.SUCCEEDED,
                WorkflowRunStatus.COMPLETED_WITH_ERRORS,
                WorkflowRunStatus.CANCELLED,
            }:
                session.commit()
                return "retried_or_failed"
            repository.schedule_retry_or_fail(
                workflow_id,
                error_message=str(exc),
                error_json={"error_type": exc.__class__.__name__},
                delay_seconds=retry_delay_seconds,
            )
            session.commit()
        return "retried_or_failed"


def _record_worker_service_heartbeat(
    *,
    engine: Engine,
    worker_id: str,
    queue_names: Sequence[str],
    lease_seconds: int,
) -> None:
    with Session(engine) as session:
        if _record_worker_service_heartbeat_in_session(
            session,
            worker_id=worker_id,
            queue_names=queue_names,
            lease_seconds=lease_seconds,
        ):
            try:
                session.commit()
            except SQLAlchemyError:
                session.rollback()


def _record_worker_service_heartbeat_in_session(
    session: Session,
    *,
    worker_id: str,
    queue_names: Sequence[str],
    lease_seconds: int,
) -> bool:
    try:
        RuntimeHeartbeatRepository(session).record_heartbeat(
            service_name=WORKFLOW_WORKER_SERVICE_NAME,
            instance_id=worker_id,
            metadata_json={
                "queue_names": list(queue_names),
                "lease_seconds": lease_seconds,
                "poller": "workflow_worker",
            },
        )
    except SQLAlchemyError:
        session.rollback()
        return False
    return True


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entrypoint used by Docker Compose and local worker runs."""
    parser = argparse.ArgumentParser(description="Run durable Workbench workflow jobs.")
    parser.add_argument("--worker-id", default=_default_worker_id())
    parser.add_argument("--queue", action="append", default=None)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--max-jobs", type=int, default=None)
    parser.add_argument("--lease-seconds", type=int, default=300)
    parser.add_argument("--retry-delay-seconds", type=int, default=30)
    parser.add_argument("--poll-interval", type=float, default=2.0)
    args = parser.parse_args(argv)

    settings = load_settings()
    engine = create_db_engine(settings)
    queues = tuple(args.queue or ["default"])
    try:
        if args.once:
            run_worker_once(
                engine=engine,
                settings=settings,
                worker_id=args.worker_id,
                queue_names=queues,
                lease_seconds=args.lease_seconds,
                retry_delay_seconds=args.retry_delay_seconds,
            )
        else:
            run_worker_loop(
                engine=engine,
                settings=settings,
                worker_id=args.worker_id,
                queue_names=queues,
                lease_seconds=args.lease_seconds,
                retry_delay_seconds=args.retry_delay_seconds,
                poll_interval_seconds=args.poll_interval,
                max_jobs=args.max_jobs,
            )
    finally:
        engine.dispose()
    return 0


def _default_worker_id() -> str:
    return f"{socket.gethostname()}-{uuid.uuid4()}"


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

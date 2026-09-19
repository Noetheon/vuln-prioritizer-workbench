from __future__ import annotations

import threading
from datetime import timedelta
from typing import Any

import pytest
from sqlmodel import Session
from utils.workbench_env import WorkbenchApiEnv

from app.models import WorkflowRun, WorkflowRunKind, WorkflowRunStatus
from app.models.base import get_datetime_utc
from app.repositories.workflows import WorkflowLeaseLostError, WorkflowRepository
from app.services.workflow_execution import WorkflowExecutionContext
from app.workers import workflow_handlers
from app.workers.workflow_worker import WorkerTickResult, run_worker_once


@pytest.mark.parametrize("claim_change", ["expired", "different-worker", "new-attempt"])
def test_computation_checkpoint_rejects_lost_claim_without_waiting_for_publication(
    file_backed_workbench_api_env: WorkbenchApiEnv,
    claim_change: str,
) -> None:
    engine = file_backed_workbench_api_env.engine
    with Session(engine) as session:
        repository = WorkflowRepository(session)
        workflow = repository.create_workflow_run(
            kind=WorkflowRunKind.IMPORT, title="Checkpoint fence", handler="test"
        )
        identity = workflow.id
        session.commit()
        repository.claim_due_workflows(worker_id="worker", lease_seconds=300)
        session.commit()

    with Session(engine) as session:
        context = WorkflowExecutionContext.for_workflow(
            WorkflowRepository(session), identity, worker_id="worker"
        )
        context.begin_compute()
        cached = context.workflow()
        with Session(engine) as successor:
            workflow = successor.get(WorkflowRun, identity)
            assert workflow is not None
            if claim_change == "expired":
                workflow.lease_expires_at = get_datetime_utc() - timedelta(seconds=1)
            elif claim_change == "different-worker":
                workflow.locked_by = "replacement-worker"
            else:
                workflow.attempt_count += 1
            successor.add(workflow)
            successor.commit()

        assert cached.locked_by == "worker"
        assert cached.attempt_count == 1
        with pytest.raises(WorkflowLeaseLostError):
            context.checkpoint()


def test_shutdown_requeues_active_work_and_can_resume_without_user_cancellation(
    file_backed_workbench_api_env: WorkbenchApiEnv,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    env = file_backed_workbench_api_env
    stop_event = threading.Event()
    cleaned_up: list[bool] = []
    invocations = 0
    with Session(env.engine) as session:
        workflow = WorkflowRepository(session).create_workflow_run(
            kind=WorkflowRunKind.REPORT_GENERATION,
            title="Interrupted work",
            handler="test",
            max_attempts=1,
        )
        identity = workflow.id
        session.commit()

    def interrupt_then_succeed(
        _session: Session, *, context: WorkflowExecutionContext, **_kwargs: Any
    ) -> None:
        nonlocal invocations
        invocations += 1
        assert context.stop_event is stop_event
        context.begin_compute()
        if invocations == 1:
            stop_event.set()
            try:
                context.checkpoint()
            finally:
                cleaned_up.append(True)
        context.begin_publication()
        context.succeed(message="Resumed work complete.")

    monkeypatch.setattr(
        workflow_handlers, "_execute_report_generation_workflow", interrupt_then_succeed
    )
    settings = env.client.app.state.workbench_settings
    first = run_worker_once(
        engine=env.engine,
        settings=settings,
        worker_id="worker",
        stop_event=stop_event,
    )
    assert first == WorkerTickResult(claimed=1, retried_or_failed=1)
    assert cleaned_up == [True]
    with Session(env.engine) as session:
        repository = WorkflowRepository(session)
        workflow = repository.require_workflow(identity)
        assert workflow.status == WorkflowRunStatus.PENDING
        assert workflow.cancellation_requested is False
        assert workflow.locked_by is None
        assert workflow.attempt_count == 1
        assert workflow.max_attempts == 2
        assert workflow.diagnostics_json == {"error_type": "WorkflowShutdownRequested"}
        events, _ = repository.list_workflow_events(identity)
        assert not any(event.event_type == "cancelled" for event in events)

    # A stopped worker must not claim the pending retry.
    assert (
        run_worker_once(
            engine=env.engine, settings=settings, worker_id="worker", stop_event=stop_event
        )
        == WorkerTickResult()
    )
    stop_event.clear()
    second = run_worker_once(
        engine=env.engine,
        settings=settings,
        worker_id="worker",
        stop_event=stop_event,
    )
    assert second == WorkerTickResult(claimed=1, completed=1)
    with Session(env.engine) as session:
        workflow = WorkflowRepository(session).require_workflow(identity)
        assert workflow.status == WorkflowRunStatus.SUCCEEDED
        assert workflow.attempt_count == 2
        assert workflow.cancellation_requested is False

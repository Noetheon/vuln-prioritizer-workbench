from __future__ import annotations

import uuid
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy.exc import SQLAlchemyError
from sqlmodel import Session
from utils.import_contract_fixtures import SAMPLE_CVES
from utils.workbench_env import WorkbenchApiEnv, create_project_via_api, local_api_headers
from utils.workbench_workflow_contracts import (
    configure_workflow_context,
    list_reports,
    post_import,
    run_summary,
)

from app.models import AnalysisRun, AnalysisRunStatus, WorkflowRunKind, WorkflowRunStatus
from app.repositories import WorkflowRepository
from app.workers import workflow_handlers, workflow_worker
from app.workers.workflow_worker import run_worker_once


def test_worker_service_heartbeat_lock_is_best_effort(
    monkeypatch: pytest.MonkeyPatch,
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    """A transient SQLite lock must not crash an otherwise idle worker tick."""

    def raise_locked_heartbeat(*_args: Any, **_kwargs: Any) -> None:
        raise SQLAlchemyError("database is locked")

    monkeypatch.setattr(
        workflow_worker.RuntimeHeartbeatRepository,
        "record_heartbeat",
        raise_locked_heartbeat,
    )

    result = run_worker_once(
        engine=workbench_api_env.engine,
        settings=workbench_api_env.client.app.state.workbench_settings,
        worker_id="locked-heartbeat-worker",
    )

    assert result == workflow_worker.WorkerTickResult()


def test_worker_executes_queued_import_provider_and_report_jobs(
    monkeypatch: pytest.MonkeyPatch,
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    for env_name in ("NVD_API_KEY", "FIRST_API_KEY"):
        monkeypatch.delenv(env_name, raising=False)
    for proxy_name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
        monkeypatch.setenv(proxy_name, "http://127.0.0.1:9")

    context = configure_workflow_context(workbench_api_env, tmp_path)
    queued_import = post_import(
        workbench_api_env,
        context,
        data={
            "input_type": "cve-list",
            "provider_snapshot_file": "demo_provider_snapshot.json",
            "locked_provider_data": "true",
        },
        files={"file": ("sample_cves.txt", SAMPLE_CVES.read_bytes(), "text/plain")},
        drain=False,
    )
    import_workflow = queued_import["workflow"]
    assert queued_import["status"] == "pending"
    assert import_workflow["kind"] == "import"
    assert import_workflow["status"] == "pending"
    assert "execution_mode" not in import_workflow

    workflow_list_response = workbench_api_env.client.get(
        f"/api/v1/projects/{context.project_id}/workflows",
        headers=context.headers,
        params={"limit": 0, "offset": -1},
    )
    assert workflow_list_response.status_code == 200, workflow_list_response.text
    workflow_list = workflow_list_response.json()
    assert workflow_list["count"] == 1
    assert workflow_list["data"][0]["id"] == import_workflow["id"]

    result = _run_worker_tick(workbench_api_env)
    assert result.claimed == 1
    assert result.completed == 1
    summary = run_summary(workbench_api_env, context, queued_import["id"])
    assert summary["status"] == "succeeded"
    assert summary["workflow"]["status"] == "succeeded"
    assert summary["workflow"]["latest_event"]["event_type"] == "succeeded"

    report_job = workbench_api_env.client.post(
        f"/api/v1/runs/{queued_import['id']}/report-jobs",
        headers=context.headers,
        json={"format": "markdown"},
    )
    assert report_job.status_code == 200, report_job.text
    report_workflow = report_job.json()
    assert report_workflow["kind"] == "report_generation"
    assert report_workflow["status"] == "pending"
    assert "execution_mode" not in report_workflow

    result = _run_worker_tick(workbench_api_env)
    assert result.claimed == 1
    assert result.completed == 1
    reports = list_reports(workbench_api_env, context, queued_import["id"])
    assert reports["count"] == 1
    assert reports["data"][0]["workflow"]["id"] == report_workflow["id"]
    assert reports["data"][0]["workflow"]["status"] == "succeeded"

    active_settings = workbench_api_env.client.app.state.workbench_settings
    workbench_api_env.client.app.state.workbench_settings = replace(
        active_settings,
        PROVIDER_SNAPSHOT_DIR=str(tmp_path / "workbench-provider-snapshots"),
        PROVIDER_CACHE_DIR=str(tmp_path / "workbench-provider-cache"),
    )
    try:
        headers = local_api_headers(workbench_api_env.client)
        provider_response = workbench_api_env.client.post(
            "/api/v1/providers/update-jobs",
            headers=headers,
            json={
                "sources": ["kev"],
                "cve_ids": ["CVE-2024-3094"],
                "cache_only": True,
            },
        )
        assert provider_response.status_code == 200, provider_response.text
        provider_job = provider_response.json()
        assert provider_job["status"] == "pending"
        assert provider_job["workflow"]["kind"] == "provider_update"
        assert "execution_mode" not in provider_job["workflow"]

        result = _run_worker_tick(workbench_api_env)
        assert result.claimed == 1
        assert result.completed == 1
        status_response = workbench_api_env.client.get(
            "/api/v1/providers/status",
            headers=headers,
        )
        assert status_response.status_code == 200, status_response.text
        latest_update = status_response.json()["latest_update_job"]
        assert latest_update["id"] == provider_job["id"]
        assert latest_update["status"] == "succeeded"
        assert latest_update["workflow"]["status"] == "succeeded"
    finally:
        workbench_api_env.client.app.state.workbench_settings = active_settings


def test_retry_runner_requeues_and_then_fails_exhausted_workflow(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    with Session(workbench_api_env.engine) as session:
        workflow = WorkflowRepository(session).create_workflow_run(
            kind=WorkflowRunKind.REPORT_GENERATION,
            title="Generate broken report",
            handler="app.services.reports.ReportService.create_report_for_workflow",
            status=WorkflowRunStatus.PENDING,
            current_stage="queued",
            payload_json={},
            max_retries=1,
        )
        workflow_id = workflow.id
        session.commit()

    result = _run_worker_tick(workbench_api_env, retry_delay_seconds=0)
    assert result.claimed == 1
    assert result.retried_or_failed == 1
    with Session(workbench_api_env.engine) as session:
        workflow = WorkflowRepository(session).require_workflow(workflow_id)
        assert workflow.status == WorkflowRunStatus.PENDING
        assert workflow.retry_count == 1
        assert workflow.next_retry_at is not None

    result = _run_worker_tick(workbench_api_env, retry_delay_seconds=0)
    assert result.claimed == 1
    assert result.retried_or_failed == 1
    with Session(workbench_api_env.engine) as session:
        workflow = WorkflowRepository(session).require_workflow(workflow_id)
        assert workflow.status == WorkflowRunStatus.FAILED
        events, _count = WorkflowRepository(session).list_workflow_events(workflow_id)
        assert "retry" in {event.event_type for event in events}
        assert events[-1].event_type == "failed"


def test_cancel_retry_and_websocket_stream_routes_are_public_contracts(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    with Session(workbench_api_env.engine) as session:
        workflow = WorkflowRepository(session).create_workflow_run(
            kind=WorkflowRunKind.REPORT_GENERATION,
            title="Queued report",
            handler="app.services.reports.ReportService.create_report_for_workflow",
            status=WorkflowRunStatus.PENDING,
            current_stage="queued",
            payload_json={},
            max_retries=1,
        )
        workflow_id = str(workflow.id)
        session.commit()

    headers = local_api_headers(workbench_api_env.client)
    read_response = workbench_api_env.client.get(
        f"/api/v1/workflows/{workflow_id}",
        headers=headers,
    )
    assert read_response.status_code == 200, read_response.text
    assert read_response.json()["id"] == workflow_id

    events_response = workbench_api_env.client.get(
        f"/api/v1/workflows/{workflow_id}/events",
        headers=headers,
        params={"limit": 0, "offset": -1},
    )
    assert events_response.status_code == 200, events_response.text
    assert events_response.json()["data"][0]["event_type"] == "created"

    previous_engine = getattr(workbench_api_env.client.app.state, "workbench_engine", None)
    workbench_api_env.client.app.state.workbench_engine = workbench_api_env.engine
    try:
        with workbench_api_env.client.websocket_connect(
            f"/api/v1/workflows/{workflow_id}/stream",
        ) as websocket:
            snapshot = websocket.receive_json()
            event = websocket.receive_json()
            assert snapshot["type"] == "workflow"
            assert snapshot["workflow"]["id"] == workflow_id
            assert event["type"] == "event"
            assert event["event"]["event_type"] == "created"
    finally:
        if previous_engine is None:
            delattr(workbench_api_env.client.app.state, "workbench_engine")
        else:
            workbench_api_env.client.app.state.workbench_engine = previous_engine

    retry_too_early = workbench_api_env.client.post(
        f"/api/v1/workflows/{workflow_id}/retry",
        headers=headers,
    )
    assert retry_too_early.status_code == 409, retry_too_early.text

    cancel_response = workbench_api_env.client.post(
        f"/api/v1/workflows/{workflow_id}/cancel",
        headers=headers,
    )
    assert cancel_response.status_code == 200, cancel_response.text
    cancelled = cancel_response.json()
    assert cancelled["status"] == "cancelled"
    assert cancelled["cancellation_requested"] is True
    assert cancelled["latest_event"]["event_type"] == "cancelled"

    project = create_project_via_api(workbench_api_env.client, headers=headers)
    with Session(workbench_api_env.engine) as session:
        linked_run = AnalysisRun(
            project_id=uuid.UUID(project["id"]),
            input_type="cve-list",
            filename="queued-cves.txt",
            status=AnalysisRunStatus.PENDING,
        )
        session.add(linked_run)
        session.flush()
        linked_workflow = WorkflowRepository(session).create_workflow_run(
            kind=WorkflowRunKind.IMPORT,
            title="Queued import",
            handler="app.services.import_execution.execute_project_import_upload",
            project_id=linked_run.project_id,
            analysis_run_id=linked_run.id,
            status=WorkflowRunStatus.PENDING,
            current_stage="queued",
        )
        linked_run_id = linked_run.id
        linked_workflow_id = str(linked_workflow.id)
        session.commit()

    linked_cancel_response = workbench_api_env.client.post(
        f"/api/v1/workflows/{linked_workflow_id}/cancel",
        headers=headers,
    )
    assert linked_cancel_response.status_code == 200, linked_cancel_response.text
    assert linked_cancel_response.json()["status"] == "cancelled"
    with Session(workbench_api_env.engine) as session:
        cancelled_run = session.get(AnalysisRun, linked_run_id)
        assert cancelled_run is not None
        assert cancelled_run.status == AnalysisRunStatus.CANCELLED
        assert cancelled_run.error_message == "Cancellation requested by user."

    retry_response = workbench_api_env.client.post(
        f"/api/v1/workflows/{workflow_id}/retry",
        headers=headers,
    )
    assert retry_response.status_code == 200, retry_response.text
    retry = retry_response.json()
    assert retry["status"] == "pending"
    assert retry["parent_workflow_run_id"] == workflow_id
    assert "execution_mode" not in retry

    missing_workflow_id = uuid.uuid4()
    for method, path in (
        ("get", f"/api/v1/workflows/{missing_workflow_id}"),
        ("get", f"/api/v1/workflows/{missing_workflow_id}/events"),
        ("post", f"/api/v1/workflows/{missing_workflow_id}/cancel"),
        ("post", f"/api/v1/workflows/{missing_workflow_id}/retry"),
    ):
        response = getattr(workbench_api_env.client, method)(path, headers=headers)
        assert response.status_code == 404, response.text


def test_worker_cancellation_loop_and_cli_runtime_paths(
    monkeypatch: pytest.MonkeyPatch,
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers=headers)
    with Session(workbench_api_env.engine) as session:
        run = AnalysisRun(
            project_id=uuid.UUID(project["id"]),
            input_type="cve-list",
            filename="cancellable-cves.txt",
            status=AnalysisRunStatus.RUNNING,
        )
        session.add(run)
        session.flush()
        workflow = WorkflowRepository(session).create_workflow_run(
            kind=WorkflowRunKind.IMPORT,
            title="Cancellable import",
            handler="app.services.import_execution.execute_project_import_upload",
            project_id=run.project_id,
            analysis_run_id=run.id,
            status=WorkflowRunStatus.PENDING,
            current_stage="queued",
            payload_json={},
            max_retries=1,
        )
        workflow_id = workflow.id
        run_id = run.id
        session.commit()

    def cancel_during_handler(session: Session, **kwargs: Any) -> None:
        workflow = kwargs["workflow"]
        WorkflowRepository(session).request_cancel(
            workflow.id,
            message="Cancellation requested during handler.",
        )
        session.commit()
        raise workflow_worker.WorkflowCancelled("cancelled")

    monkeypatch.setattr(workflow_worker, "execute_workflow_handler", cancel_during_handler)

    result = _run_worker_tick(workbench_api_env)
    assert result.claimed == 1
    assert result.cancelled == 1
    with Session(workbench_api_env.engine) as session:
        workflow = WorkflowRepository(session).require_workflow(workflow_id)
        assert workflow.status == WorkflowRunStatus.CANCELLED
        assert workflow.locked_by is None
        cancelled_run = session.get(AnalysisRun, run_id)
        assert cancelled_run is not None
        assert cancelled_run.status == AnalysisRunStatus.CANCELLED

    with Session(workbench_api_env.engine) as session:
        skipped_workflow = WorkflowRepository(session).create_workflow_run(
            kind=WorkflowRunKind.REPORT_GENERATION,
            title="Already claimed report",
            handler="app.services.reports.ReportService.create_report_for_workflow",
            status=WorkflowRunStatus.RUNNING,
            current_stage="running",
        )
        skipped_workflow.locked_by = "another-worker"
        session.add(skipped_workflow)
        skipped_workflow_id = skipped_workflow.id
        session.commit()
    assert (
        workflow_worker._execute_claimed_workflow(
            engine=workbench_api_env.engine,
            settings=workbench_api_env.client.app.state.workbench_settings,
            worker_id="test-worker",
            workflow_id=skipped_workflow_id,
            lease_seconds=30,
            retry_delay_seconds=0,
        )
        == "skipped"
    )

    with Session(workbench_api_env.engine) as session:
        deterministic_failure = WorkflowRepository(session).create_workflow_run(
            kind=WorkflowRunKind.REPORT_GENERATION,
            title="Deterministic failure report",
            handler="app.services.reports.ReportService.create_report_for_workflow",
            status=WorkflowRunStatus.PENDING,
            current_stage="queued",
        )
        deterministic_failure_id = deterministic_failure.id
        session.commit()

    def fail_without_retry(session: Session, **kwargs: Any) -> None:
        workflow = kwargs["workflow"]
        WorkflowRepository(session).finish_workflow(
            workflow.id,
            status=WorkflowRunStatus.FAILED,
            stage="failed",
            message="Invalid user input.",
        )
        session.commit()
        raise workflow_worker.WorkflowNonRetryableError("invalid user input")

    monkeypatch.setattr(workflow_worker, "execute_workflow_handler", fail_without_retry)
    assert _run_worker_tick(workbench_api_env).retried_or_failed == 1
    with Session(workbench_api_env.engine) as session:
        assert WorkflowRepository(session).require_workflow(deterministic_failure_id).status == (
            WorkflowRunStatus.FAILED
        )

    with Session(workbench_api_env.engine) as session:
        committed_success = WorkflowRepository(session).create_workflow_run(
            kind=WorkflowRunKind.REPORT_GENERATION,
            title="Committed success report",
            handler="app.services.reports.ReportService.create_report_for_workflow",
            status=WorkflowRunStatus.PENDING,
            current_stage="queued",
        )
        committed_success_id = committed_success.id
        session.commit()

    def commit_success_then_raise(session: Session, **kwargs: Any) -> None:
        workflow = kwargs["workflow"]
        WorkflowRepository(session).finish_workflow(
            workflow.id,
            status=WorkflowRunStatus.SUCCEEDED,
            stage="done",
            message="Finished before late exception.",
        )
        session.commit()
        raise RuntimeError("late handler cleanup failure")

    monkeypatch.setattr(workflow_worker, "execute_workflow_handler", commit_success_then_raise)
    assert _run_worker_tick(workbench_api_env).retried_or_failed == 1
    with Session(workbench_api_env.engine) as session:
        assert (
            WorkflowRepository(session).require_workflow(committed_success_id).status
            == WorkflowRunStatus.SUCCEEDED
        )

    loop_results = iter(
        (
            workflow_worker.WorkerTickResult(claimed=0),
            workflow_worker.WorkerTickResult(claimed=1, completed=1),
        )
    )
    loop_calls: list[dict[str, Any]] = []

    def fake_once(**kwargs: Any) -> workflow_worker.WorkerTickResult:
        loop_calls.append(kwargs)
        return next(loop_results)

    sleep_calls: list[float] = []
    monkeypatch.setattr(workflow_worker, "run_worker_once", fake_once)
    monkeypatch.setattr(workflow_worker.time, "sleep", sleep_calls.append)
    workflow_worker.run_worker_loop(
        engine=workbench_api_env.engine,
        settings=workbench_api_env.client.app.state.workbench_settings,
        worker_id="loop-worker",
        poll_interval_seconds=0.01,
        max_jobs=1,
    )
    assert len(loop_calls) == 2
    assert sleep_calls == [0.1]

    class FakeEngine:
        disposed = False

        def dispose(self) -> None:
            self.disposed = True

    once_engine = FakeEngine()
    once_calls: list[dict[str, Any]] = []
    monkeypatch.setattr(
        workflow_worker,
        "load_settings",
        lambda: workbench_api_env.client.app.state.workbench_settings,
    )
    monkeypatch.setattr(workflow_worker, "create_db_engine", lambda _settings: once_engine)
    monkeypatch.setattr(
        workflow_worker,
        "run_worker_once",
        lambda **kwargs: once_calls.append(kwargs) or workflow_worker.WorkerTickResult(),
    )

    assert (
        workflow_worker.main(
            [
                "--once",
                "--worker-id",
                "cli-worker",
                "--queue",
                "reports",
                "--lease-seconds",
                "7",
                "--retry-delay-seconds",
                "3",
            ]
        )
        == 0
    )
    assert once_engine.disposed is True
    assert once_calls[0]["worker_id"] == "cli-worker"
    assert once_calls[0]["queue_names"] == ("reports",)

    loop_engine = FakeEngine()
    main_loop_calls: list[dict[str, Any]] = []
    monkeypatch.setattr(workflow_worker, "create_db_engine", lambda _settings: loop_engine)
    monkeypatch.setattr(
        workflow_worker, "run_worker_loop", lambda **kwargs: main_loop_calls.append(kwargs)
    )
    assert workflow_worker.main(["--worker-id", "loop-cli", "--max-jobs", "1"]) == 0
    assert loop_engine.disposed is True
    assert main_loop_calls[0]["worker_id"] == "loop-cli"

    assert workflow_worker._default_worker_id()


def test_workflow_handler_validation_edges(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    active_settings = workbench_api_env.client.app.state.workbench_settings
    settings = replace(active_settings, IMPORT_UPLOAD_DIR=str(tmp_path / "uploads"))
    settings.import_upload_dir_path.mkdir(parents=True, exist_ok=True)

    with Session(workbench_api_env.engine) as session:
        repository = WorkflowRepository(session)
        import_workflow = repository.create_workflow_run(
            kind=WorkflowRunKind.IMPORT,
            title="Broken import",
            handler="app.services.import_execution.execute_project_import_upload",
            status=WorkflowRunStatus.RUNNING,
        )
        missing_run_import = repository.create_workflow_run(
            kind=WorkflowRunKind.IMPORT,
            title="Missing run import",
            handler="app.services.import_execution.execute_project_import_upload",
            status=WorkflowRunStatus.RUNNING,
            project_id=uuid.uuid4(),
            analysis_run_id=uuid.uuid4(),
        )
        provider_workflow = repository.create_workflow_run(
            kind=WorkflowRunKind.PROVIDER_UPDATE,
            title="Broken provider update",
            handler="app.services.provider_updates.resume_provider_update_job",
            status=WorkflowRunStatus.RUNNING,
        )
        report_workflow = repository.create_workflow_run(
            kind=WorkflowRunKind.REPORT_GENERATION,
            title="Broken report",
            handler="app.services.reports.ReportService.create_report_for_workflow",
            status=WorkflowRunStatus.RUNNING,
        )
        missing_run_report = repository.create_workflow_run(
            kind=WorkflowRunKind.REPORT_GENERATION,
            title="Missing run report",
            handler="app.services.reports.ReportService.create_report_for_workflow",
            status=WorkflowRunStatus.RUNNING,
            payload_json={"run_id": str(uuid.uuid4())},
        )
        run_without_project = AnalysisRun(
            project_id=uuid.uuid4(),
            input_type="cve-list",
            filename="known-cves.txt",
            status=AnalysisRunStatus.SUCCEEDED,
        )
        session.add(run_without_project)
        session.flush()
        missing_project_report = repository.create_workflow_run(
            kind=WorkflowRunKind.REPORT_GENERATION,
            title="Missing project report",
            handler="app.services.reports.ReportService.create_report_for_workflow",
            status=WorkflowRunStatus.RUNNING,
            payload_json={"run_id": str(run_without_project.id)},
        )
        cancellable = repository.create_workflow_run(
            kind=WorkflowRunKind.REPORT_GENERATION,
            title="Cancelled report",
            handler="app.services.reports.ReportService.create_report_for_workflow",
            status=WorkflowRunStatus.RUNNING,
        )
        repository.request_cancel(cancellable.id)

        with pytest.raises(workflow_handlers.WorkflowHandlerError, match="missing run/project"):
            workflow_handlers._execute_import_workflow(
                session,
                settings=settings,
                workflow=import_workflow,
            )
        with pytest.raises(workflow_handlers.WorkflowHandlerError, match="Analysis run not found"):
            workflow_handlers._execute_import_workflow(
                session,
                settings=settings,
                workflow=missing_run_import,
            )
        with pytest.raises(workflow_handlers.WorkflowHandlerError, match="missing run linkage"):
            workflow_handlers._execute_provider_update_workflow(
                session,
                settings=settings,
                workflow=provider_workflow,
            )
        with pytest.raises(workflow_handlers.WorkflowHandlerError, match="missing run linkage"):
            workflow_handlers._execute_report_generation_workflow(
                session,
                settings=settings,
                workflow=report_workflow,
            )
        with pytest.raises(workflow_handlers.WorkflowHandlerError, match="Analysis run not found"):
            workflow_handlers._execute_report_generation_workflow(
                session,
                settings=settings,
                workflow=missing_run_report,
            )
        with pytest.raises(workflow_handlers.WorkflowHandlerError, match="Project not found"):
            workflow_handlers._execute_report_generation_workflow(
                session,
                settings=settings,
                workflow=missing_project_report,
            )
        with pytest.raises(workflow_handlers.WorkflowCancelled):
            workflow_handlers._raise_if_cancelled(repository, cancellable.id)

    run = AnalysisRun(
        project_id=uuid.uuid4(),
        input_type="cve-list",
        filename="known-cves.txt",
        status=AnalysisRunStatus.PENDING,
    )
    with pytest.raises(workflow_handlers.WorkflowHandlerError, match="no stored input upload"):
        workflow_handlers._stored_import_upload_request(settings, run=run, payload={})
    with pytest.raises(workflow_handlers.WorkflowHandlerError, match="missing"):
        workflow_handlers._upload_content(settings, {})
    with pytest.raises(workflow_handlers.WorkflowHandlerError, match="escapes upload root"):
        workflow_handlers._read_upload_ref(settings, "../outside.txt")
    with pytest.raises(workflow_handlers.WorkflowHandlerError, match="Stored upload not found"):
        workflow_handlers._read_upload_ref(settings, "missing.txt")

    stored_file = settings.import_upload_dir_path / "sample.txt"
    stored_file.write_bytes(b"CVE-2024-3094\n")
    upload = workflow_handlers._upload_content(
        settings,
        {
            "storage_ref": "sample.txt",
            "original_filename": "sample.txt",
            "content_type": "text/plain",
        },
    )
    assert upload.content == b"CVE-2024-3094\n"
    assert workflow_handlers._optional_upload_content(settings, {}) is None
    assert (
        workflow_handlers._optional_upload_content(
            settings,
            {"storage_ref": "sample.txt"},
        ).content
        == b"CVE-2024-3094\n"
    )
    assert workflow_handlers._string_list("kev") == []
    assert workflow_handlers._string_list(["kev", "", 3]) == ["kev"]
    assert workflow_handlers._uuid_value(upload.filename) is None
    parsed_uuid = uuid.uuid4()
    assert workflow_handlers._uuid_value(parsed_uuid) == parsed_uuid
    assert workflow_handlers._uuid_value(str(parsed_uuid)) == parsed_uuid
    assert workflow_handlers._uuid_value("not-a-uuid") is None


def _run_worker_tick(
    workbench_api_env: WorkbenchApiEnv,
    *,
    retry_delay_seconds: int = 0,
):
    return run_worker_once(
        engine=workbench_api_env.engine,
        settings=workbench_api_env.client.app.state.workbench_settings,
        worker_id=f"test-worker-{uuid.uuid4()}",
        retry_delay_seconds=retry_delay_seconds,
    )

from __future__ import annotations

import threading
import time
import uuid
from dataclasses import asdict, replace
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlmodel import Session, func, select
from utils.workbench_env import WorkbenchApiEnv
from utils.workbench_workflow_contracts import configure_workflow_context, post_import

import app.repositories.workflows as workflow_repository
from app.models import (
    AnalysisEvidence,
    Finding,
    ProviderSnapshot,
    Report,
    RuntimeServiceHeartbeat,
    WorkflowRun,
    WorkflowRunKind,
)
from app.models.base import get_datetime_utc
from app.repositories.workflows import WorkflowLeaseLostError, WorkflowRepository
from app.services import import_execution, provider_update_snapshot, reports
from app.services.analysis import AnalysisService
from app.services.decision_scope_lock import lock_project_decision_scope
from app.services.workflow_execution import WorkflowCancellationRequested, WorkflowExecutionContext
from app.workers import workflow_worker
from app.workers.workflow_handlers import WorkflowCancelled
from app.workers.workflow_worker import run_worker_once


@pytest.mark.parametrize("pause_stage", ["parse_upload", "enrich_score_explain"])
def test_real_import_exposes_progress_and_accepts_concurrent_cancellation(
    file_backed_workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    pause_stage: str,
) -> None:
    env = file_backed_workbench_api_env
    context = configure_workflow_context(env, tmp_path)
    entered, release = threading.Event(), threading.Event()
    outcomes: dict[str, Any] = {}
    lease_clock_started_at: float | None = None
    target = import_execution if pause_stage == "parse_upload" else AnalysisService
    method = "_parse_prepared_upload" if pause_stage == "parse_upload" else "analyze_import"
    original = getattr(target, method)

    def paused(*args: Any, **kwargs: Any) -> Any:
        nonlocal lease_clock_started_at
        lease_clock_started_at = time.monotonic()
        entered.set()
        assert release.wait(5), "Concurrent API inspection exceeded its safety bound"
        return original(*args, **kwargs)

    monkeypatch.setattr(target, method, paused)
    queued = post_import(
        env,
        context,
        drain=False,
        data={
            "input_type": "cve-list",
            "provider_snapshot_file": "demo_provider_snapshot.json",
            "locked_provider_data": "true",
        },
        files={"file": ("sample.txt", b"CVE-2021-44228\n", "text/plain")},
    )
    identity = queued["workflow"]["id"]
    lease_clock_origin = get_datetime_utc()

    def lease_now() -> datetime:
        # A one-second lease measures renewal during the paused computation,
        # not unrelated scheduler or initialization delays before it begins.
        started_at = lease_clock_started_at
        elapsed = 0.0 if started_at is None else time.monotonic() - started_at
        return lease_clock_origin + timedelta(seconds=elapsed)

    monkeypatch.setattr(workflow_repository, "get_datetime_utc", lease_now)

    def run() -> None:
        try:
            outcomes.update(
                asdict(
                    run_worker_once(
                        engine=env.engine,
                        settings=env.client.app.state.workbench_settings,
                        worker_id="concurrent-import-worker",
                        lease_seconds=1,
                    )
                )
            )
        except BaseException as exc:
            outcomes["error"] = exc

    worker = threading.Thread(target=run)
    worker.start()
    try:
        assert entered.wait(3), {
            "worker": dict(outcomes),
            "workflow": env.client.get(
                f"/api/v1/workflows/{identity}", headers=context.headers
            ).json(),
        }
        visible = env.client.get(f"/api/v1/workflows/{identity}", headers=context.headers)
        assert visible.status_code == 200
        assert visible.json()["current_stage"] == pause_stage
        original_lease = visible.json()["lease_expires_at"]
        with Session(env.engine) as observer:
            original_liveness = observer.get(
                RuntimeServiceHeartbeat, ("workflow-worker", "concurrent-import-worker")
            ).last_seen_at
        # Cross the original lease lifetime while real computation is blocked.
        # The independent heartbeat must keep this attempt unreclaimable.
        minimum_pause_end = time.monotonic() + 1.1
        deadline = minimum_pause_end + 1.4
        renewed = False
        while time.monotonic() < deadline:
            current = env.client.get(
                f"/api/v1/workflows/{identity}", headers=context.headers
            ).json()
            if (
                time.monotonic() >= minimum_pause_end
                and current["lease_expires_at"] > original_lease
            ):
                renewed = True
                break
            threading.Event().wait(0.05)
        assert renewed, "Lease was not renewed during computation"
        with Session(env.engine) as lease_observer:
            assert WorkflowRepository(lease_observer).release_expired_leases() == []
            heartbeat = lease_observer.get(
                RuntimeServiceHeartbeat, ("workflow-worker", "concurrent-import-worker")
            )
            assert heartbeat.last_seen_at > original_liveness
            lease_observer.commit()
        started = time.monotonic()
        cancelled = env.client.post(f"/api/v1/workflows/{identity}/cancel", headers=context.headers)
        assert time.monotonic() - started < 1.0
        assert cancelled.status_code == 200, cancelled.text
        assert cancelled.json()["cancellation_requested"] is True
    finally:
        release.set()
        worker.join(5)
    assert not worker.is_alive()
    assert "error" not in outcomes, outcomes
    assert outcomes["cancelled"] == 1, outcomes
    final = env.client.get(f"/api/v1/workflows/{identity}", headers=context.headers).json()
    assert final["status"] == "cancelled"
    with Session(env.engine) as session:
        assert session.exec(select(func.count()).select_from(Finding)).one() == 0
        assert session.exec(select(func.count()).select_from(AnalysisEvidence)).one() == 0


@pytest.mark.parametrize("family", ["report", "provider"])
def test_other_workflow_families_cancel_during_computation_without_artifact_publication(
    file_backed_workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    family: str,
) -> None:
    env = file_backed_workbench_api_env
    context = configure_workflow_context(env, tmp_path)
    entered, release = threading.Event(), threading.Event()
    outcomes: dict[str, Any] = {}
    if family == "report":
        imported = post_import(
            env,
            context,
            data={
                "input_type": "cve-list",
                "provider_snapshot_file": "demo_provider_snapshot.json",
                "locked_provider_data": "true",
            },
            files={"file": ("sample.txt", b"CVE-2021-44228\n", "text/plain")},
        )
        queued = env.client.post(
            f"/api/v1/runs/{imported['id']}/report-jobs",
            headers=context.headers,
            json={"format": "markdown"},
        )
        target, name, expected_stage = reports, "render_markdown_report", "render"
    else:
        env.client.app.state.workbench_settings = replace(
            env.client.app.state.workbench_settings,
            PROVIDER_SNAPSHOT_DIR=str(tmp_path / "snapshots"),
            PROVIDER_CACHE_DIR=str(tmp_path / "cache"),
        )
        queued = env.client.post(
            "/api/v1/providers/update-jobs",
            headers=context.headers,
            json={"sources": ["kev"], "cve_ids": ["CVE-2021-44228"], "cache_only": True},
        )
        target, name, expected_stage = (
            provider_update_snapshot,
            "_provider_records_for_snapshot",
            "provider_lock_acquired",
        )
    assert queued.status_code == 200, queued.text
    identity = queued.json()["id"] if family == "report" else queued.json()["workflow"]["id"]
    original = getattr(target, name)

    def paused(*args: Any, **kwargs: Any) -> Any:
        entered.set()
        assert release.wait(5)
        return original(*args, **kwargs)

    monkeypatch.setattr(target, name, paused)

    def run() -> None:
        try:
            outcomes.update(
                asdict(
                    run_worker_once(
                        engine=env.engine,
                        settings=env.client.app.state.workbench_settings,
                        worker_id="other-family-worker",
                    )
                )
            )
        except BaseException as exc:
            outcomes["error"] = exc

    worker = threading.Thread(target=run)
    worker.start()
    try:
        assert entered.wait(3), outcomes
        visible = env.client.get(f"/api/v1/workflows/{identity}", headers=context.headers).json()
        assert visible["current_stage"] == expected_stage
        cancellation = env.client.post(
            f"/api/v1/workflows/{identity}/cancel", headers=context.headers
        )
        assert cancellation.status_code == 200, cancellation.text
        assert cancellation.json()["cancellation_requested"] is True
    finally:
        release.set()
        worker.join(5)
    assert not worker.is_alive()
    assert "error" not in outcomes, outcomes
    assert outcomes["cancelled"] == 1, outcomes
    with Session(env.engine) as session:
        assert session.get(WorkflowRun, uuid.UUID(identity)).status == "cancelled"
        assert session.exec(select(func.count()).select_from(Report)).one() == 0
        if family == "provider":
            assert session.exec(select(func.count()).select_from(ProviderSnapshot)).one() == 0
    assert not list(context.report_dir.rglob("*.md"))
    assert not list((tmp_path / "snapshots").glob("provider-snapshot-*.json"))


def test_import_publication_failure_rolls_back_all_decisions(
    file_backed_workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    env = file_backed_workbench_api_env
    context = configure_workflow_context(env, tmp_path)
    original = WorkflowExecutionContext.succeed

    def fail_after_result(self: WorkflowExecutionContext, **kwargs: Any) -> Any:
        original(self, **kwargs)
        raise RuntimeError("Injected failure after decision/result writes, before commit")

    monkeypatch.setattr(WorkflowExecutionContext, "succeed", fail_after_result)
    queued = post_import(
        env,
        context,
        drain=False,
        data={
            "input_type": "cve-list",
            "provider_snapshot_file": "demo_provider_snapshot.json",
            "locked_provider_data": "true",
        },
        files={"file": ("sample.txt", b"CVE-2021-44228\n", "text/plain")},
    )
    result = run_worker_once(
        engine=env.engine,
        settings=env.client.app.state.workbench_settings,
        worker_id="failed-publisher",
    )
    assert result.completed == 0
    with Session(env.engine) as session:
        assert session.exec(select(func.count()).select_from(Finding)).one() == 0
        assert session.exec(select(func.count()).select_from(AnalysisEvidence)).one() == 0
        assert session.get(WorkflowRun, uuid.UUID(queued["workflow"]["id"])).status != "succeeded"


def test_committed_cancellation_bypasses_worker_identity_cache(
    file_backed_workbench_api_env: WorkbenchApiEnv,
) -> None:
    engine = file_backed_workbench_api_env.engine
    with Session(engine) as session:
        repo = WorkflowRepository(session)
        workflow = repo.create_workflow_run(
            kind=WorkflowRunKind.IMPORT, title="Cancel", handler="test"
        )
        identity = workflow.id
        session.commit()
        repo.claim_due_workflows(worker_id="owner")
        session.commit()
    with Session(engine) as worker:
        context = WorkflowExecutionContext.for_workflow(
            WorkflowRepository(worker), identity, worker_id="owner"
        )
        cached = context.workflow()
        with Session(engine) as api:
            WorkflowRepository(api).request_cancel(identity)
            api.commit()
        assert cached.cancellation_requested is False
        with pytest.raises(WorkflowCancellationRequested):
            context.check_cancelled()


def test_reused_worker_id_cannot_publish_a_superseded_attempt(
    file_backed_workbench_api_env: WorkbenchApiEnv,
) -> None:
    engine = file_backed_workbench_api_env.engine
    now = get_datetime_utc()
    with Session(engine) as session:
        repo = WorkflowRepository(session)
        workflow = repo.create_workflow_run(
            kind=WorkflowRunKind.IMPORT, title="Fence", handler="test", max_attempts=2
        )
        identity = workflow.id
        session.commit()
        repo.claim_due_workflows(worker_id="reused", lease_seconds=1, now=now)
        session.commit()
    with Session(engine) as old:
        context = WorkflowExecutionContext.for_workflow(
            WorkflowRepository(old), identity, worker_id="reused"
        )
        assert context.attempt_count == 1
        old.commit()
        with Session(engine) as newer:
            repo = WorkflowRepository(newer)
            repo.release_expired_leases(now=now + timedelta(seconds=2))
            repo.claim_due_workflows(
                worker_id="reused", lease_seconds=300, now=now + timedelta(seconds=2)
            )
            newer.commit()
        with pytest.raises(WorkflowLeaseLostError):
            context.begin_publication()
        old.rollback()
    with Session(engine) as reader:
        workflow = reader.get(WorkflowRun, identity)
        assert workflow.status == "running"
        assert workflow.attempt_count == 2


def test_import_rejects_changed_project_revision_without_partial_decisions(
    file_backed_workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    env = file_backed_workbench_api_env
    context = configure_workflow_context(env, tmp_path)
    original = AnalysisService.analyze_import

    def change_during_analysis(self: Any, **kwargs: Any) -> Any:
        with Session(env.engine) as editor:
            lock_project_decision_scope(editor, uuid.UUID(context.project_id))
            editor.commit()
        return original(self, **kwargs)

    monkeypatch.setattr(AnalysisService, "analyze_import", change_during_analysis)
    queued = post_import(
        env,
        context,
        drain=False,
        data={
            "input_type": "cve-list",
            "provider_snapshot_file": "demo_provider_snapshot.json",
            "locked_provider_data": "true",
        },
        files={"file": ("sample.txt", b"CVE-2021-44228\n", "text/plain")},
    )
    result = run_worker_once(
        engine=env.engine,
        settings=env.client.app.state.workbench_settings,
        worker_id="stale-input-worker",
    )
    assert result.completed == 0
    final = env.client.get(
        f"/api/v1/workflows/{queued['workflow']['id']}", headers=context.headers
    ).json()
    assert final["status"] != "succeeded"
    with Session(env.engine) as session:
        assert session.exec(select(func.count()).select_from(Finding)).one() == 0
        assert session.exec(select(func.count()).select_from(AnalysisEvidence)).one() == 0


def test_superseded_worker_cannot_finalize_successor_cancellation(
    file_backed_workbench_api_env: WorkbenchApiEnv,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    env = file_backed_workbench_api_env
    with Session(env.engine) as session:
        workflow = WorkflowRepository(session).create_workflow_run(
            kind=WorkflowRunKind.REPORT_GENERATION, title="Cancellation fence", handler="test"
        )
        identity = workflow.id
        session.commit()

    def supersede_then_cancel(_session: Session, **_kwargs: Any) -> None:
        with Session(env.engine) as successor:
            row = successor.get(WorkflowRun, identity)
            assert row is not None
            row.attempt_count += 1
            row.cancellation_requested = True
            successor.add(row)
            successor.commit()
        raise WorkflowCancelled("Old attempt observed cancellation after losing its claim")

    monkeypatch.setattr(workflow_worker, "execute_workflow_handler", supersede_then_cancel)
    outcome = run_worker_once(
        engine=env.engine,
        settings=env.client.app.state.workbench_settings,
        worker_id="reused-worker",
    )
    assert outcome.cancelled == 0
    with Session(env.engine) as observer:
        row = observer.get(WorkflowRun, identity)
        assert row.status == "running"
        assert row.attempt_count == 2
        assert row.cancellation_requested is True


def test_cancelled_import_can_retry_from_its_managed_upload(
    file_backed_workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    env = file_backed_workbench_api_env
    context = configure_workflow_context(env, tmp_path)
    queued = post_import(
        env,
        context,
        drain=False,
        data={
            "input_type": "cve-list",
            "provider_snapshot_file": "demo_provider_snapshot.json",
            "locked_provider_data": "true",
        },
        files={"file": ("sample.txt", b"CVE-2021-44228\n", "text/plain")},
    )
    identity = queued["workflow"]["id"]
    cancelled = env.client.post(f"/api/v1/workflows/{identity}/cancel", headers=context.headers)
    assert cancelled.status_code == 200
    assert cancelled.json()["status"] == "cancelled"
    retry = env.client.post(f"/api/v1/workflows/{identity}/retry", headers=context.headers)
    assert retry.status_code == 200, retry.text
    outcome = run_worker_once(
        engine=env.engine,
        settings=env.client.app.state.workbench_settings,
        worker_id="manual-retry-worker",
    )
    assert outcome.completed == 1
    final = env.client.get(
        f"/api/v1/workflows/{retry.json()['id']}", headers=context.headers
    ).json()
    assert final["status"] == "succeeded"
    with Session(env.engine) as session:
        assert session.exec(select(func.count()).select_from(Finding)).one() == 1
        assert session.exec(select(func.count()).select_from(AnalysisEvidence)).one() == 1

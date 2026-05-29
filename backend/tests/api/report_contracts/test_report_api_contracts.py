from __future__ import annotations

import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlmodel import Session, select
from utils.workbench_contracts import (
    _configure_report_dir,
    _create_report_via_worker,
    _queue_report_workflow,
    _seed_reportable_run,
    _seed_secondary_project_report,
    _seed_status_run,
)
from utils.workbench_env import (
    WorkbenchApiEnv,
    create_project_via_api,
    local_api_headers,
    seed_secondary_project_graph,
)

from app import models as app_models


def test_vpw048_report_local_project_visibility_and_invalid_run_state(
    secondary_workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    _configure_report_dir(secondary_workbench_api_env, tmp_path)
    headers = local_api_headers(secondary_workbench_api_env.client)
    secondary_project = seed_secondary_project_graph(
        secondary_workbench_api_env.engine,
        secondary_workbench_api_env.app_models,
        secondary_workbench_api_env.repositories,
    )
    missing_id = uuid.UUID("00000000-0000-4000-8000-000000000404")
    pending_run_id = _seed_status_run(secondary_workbench_api_env, "pending")
    failed_run_id = _seed_status_run(secondary_workbench_api_env, "failed")
    secondary_report_id = _seed_secondary_project_report(
        secondary_workbench_api_env, secondary_project
    )

    assert (
        secondary_workbench_api_env.client.post(
            f"/api/v1/runs/{missing_id}/reports",
            headers=headers,
            json={"format": "markdown"},
        ).status_code
        == 404
    )
    assert (
        secondary_workbench_api_env.client.post(
            f"/api/v1/runs/{secondary_project['run_id']}/reports",
            headers=headers,
            json={"format": "markdown"},
        ).status_code
        == 200
    )
    assert (
        secondary_workbench_api_env.client.get(
            f"/api/v1/reports/{secondary_report_id}/download",
            headers=headers,
        ).status_code
        == 404
    )
    for run_id in (pending_run_id, failed_run_id):
        response = secondary_workbench_api_env.client.post(
            f"/api/v1/runs/{run_id}/reports",
            headers=headers,
            json={"format": "markdown"},
        )
        assert response.status_code == 422
        assert "completed" in response.json()["detail"]
    with Session(secondary_workbench_api_env.engine) as session:
        failure_events = session.exec(
            select(secondary_workbench_api_env.app_models.AuditEvent).where(
                secondary_workbench_api_env.app_models.AuditEvent.action == "report.job.create",
                secondary_workbench_api_env.app_models.AuditEvent.status == "failure",
            )
        ).all()
    assert {event.resource_id for event in failure_events} == {
        str(pending_run_id),
        str(failed_run_id),
    }
    assert {event.resource_type for event in failure_events} == {"analysis_run"}
    assert all(event.detail_json["format"] == "markdown" for event in failure_events)


def test_vpw048_download_rejects_path_escape_and_checksum_mismatch(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    _configure_report_dir(workbench_api_env, tmp_path)
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    run_id = _seed_reportable_run(workbench_api_env, uuid.UUID(project["id"]))
    created = _create_report_via_worker(
        workbench_api_env,
        run_id,
        headers=headers,
        payload={"format": "markdown"},
    )
    report_id = uuid.UUID(created["id"])

    with Session(workbench_api_env.engine) as session:
        report = session.get(workbench_api_env.app_models.Report, report_id)
        assert report is not None
        report_path = Path(report.path)
    report_path.write_text("tampered report\n", encoding="utf-8")

    tampered = workbench_api_env.client.get(created["download_url"], headers=headers)
    assert tampered.status_code == 409
    assert tampered.json()["detail"] == "Report artifact checksum mismatch"

    outside_path = tmp_path / "outside-report.md"
    outside_path.write_text("outside root\n", encoding="utf-8")
    with Session(workbench_api_env.engine) as session:
        report = session.get(workbench_api_env.app_models.Report, report_id)
        assert report is not None
        report.path = str(outside_path)
        session.add(report)
        session.commit()

    escaped = workbench_api_env.client.get(created["download_url"], headers=headers)
    assert escaped.status_code == 404
    assert escaped.json()["detail"] == "Report artifact not found"


def test_report_generation_rejects_artifacts_over_configured_size_limit(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    previous_settings = workbench_api_env.client.app.state.workbench_settings
    try:
        report_dir = _configure_report_dir(workbench_api_env, tmp_path, MAX_REPORT_MB=0)
        headers = local_api_headers(workbench_api_env.client)
        project = create_project_via_api(workbench_api_env.client, headers)
        run_id = _seed_reportable_run(workbench_api_env, uuid.UUID(project["id"]))

        workflow = _queue_report_workflow(
            workbench_api_env,
            run_id,
            headers=headers,
            payload={"format": "markdown"},
        )
        from utils.import_contracts import drain_workflow_queue

        drain_workflow_queue(workbench_api_env)
        response = workbench_api_env.client.get(
            f"/api/v1/workflows/{workflow['id']}",
            headers=headers,
        )

        assert response.status_code == 200
        assert response.json()["status"] == "failed"
        assert "configured report size limit" in response.json()["error_message"]
        with Session(workbench_api_env.engine) as session:
            reports = workbench_api_env.repositories.ReportRepository(session).list_run_reports(
                run_id
            )
        assert reports == []
        assert not report_dir.exists()
    finally:
        workbench_api_env.client.app.state.workbench_settings = previous_settings


def test_report_persistence_cleans_artifact_directory_when_record_creation_fails(
    monkeypatch: pytest.MonkeyPatch,
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    from app.services import report_service_persistence

    previous_settings = workbench_api_env.client.app.state.workbench_settings
    try:
        report_dir = _configure_report_dir(workbench_api_env, tmp_path)
        headers = local_api_headers(workbench_api_env.client)
        project = create_project_via_api(workbench_api_env.client, headers)
        run_id = _seed_reportable_run(workbench_api_env, uuid.UUID(project["id"]))

        def fail_create_report_record(*_args: object, **_kwargs: object) -> app_models.Report:
            raise RuntimeError("database write failed")

        monkeypatch.setattr(
            report_service_persistence,
            "create_report_record",
            fail_create_report_record,
        )
        active_settings = workbench_api_env.client.app.state.workbench_settings
        with Session(workbench_api_env.engine) as session:
            run = session.get(app_models.AnalysisRun, run_id)
            stored_project = session.get(app_models.Project, uuid.UUID(project["id"]))
            assert run is not None
            assert stored_project is not None

            with pytest.raises(RuntimeError, match="database write failed"):
                report_service_persistence.persist_text_report(
                    session,
                    active_settings,
                    run=run,
                    project=stored_project,
                    generated_at=datetime.now(UTC),
                    finding_count=0,
                    provider_snapshot_id=None,
                    content="temporary report\n",
                    kind="technical-markdown",
                    report_format="markdown",
                    filename="technical-report.md",
                    content_type="text/markdown; charset=utf-8",
                )

        assert not list(report_dir.rglob("technical-report.md"))
    finally:
        workbench_api_env.client.app.state.workbench_settings = previous_settings


def test_report_generation_prunes_oldest_reports_for_run(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    previous_settings = workbench_api_env.client.app.state.workbench_settings
    try:
        report_dir = _configure_report_dir(
            workbench_api_env,
            tmp_path,
            MAX_REPORT_MB=50,
            MAX_REPORTS_PER_RUN=2,
        )
        headers = local_api_headers(workbench_api_env.client)
        project = create_project_via_api(workbench_api_env.client, headers)
        run_id = _seed_reportable_run(workbench_api_env, uuid.UUID(project["id"]))

        created = []
        for _ in range(3):
            response = _create_report_via_worker(
                workbench_api_env,
                run_id,
                headers=headers,
                payload={"format": "markdown"},
            )
            created.append(response)

        with Session(workbench_api_env.engine) as session:
            reports = workbench_api_env.repositories.ReportRepository(session).list_run_reports(
                run_id
            )
            remaining_ids = {str(report.id) for report in reports}
            retention_event = session.exec(
                select(app_models.AuditEvent).where(
                    app_models.AuditEvent.action == "report.retention.delete"
                )
            ).one()

        assert len(reports) == 2
        assert remaining_ids == {created[1]["id"], created[2]["id"]}
        assert retention_event.resource_id == created[0]["id"]
        assert retention_event.project_id == uuid.UUID(project["id"])
        assert retention_event.detail_json == {
            "analysis_run_id": str(run_id),
            "retained_report_id": created[2]["id"],
            "format": "markdown",
            "kind": "technical-markdown",
            "filename": "technical-report.md",
            "artifact_deleted": True,
            "max_reports_per_run": 2,
        }
        assert not (report_dir / project["id"] / str(run_id) / created[0]["id"]).exists()
        assert (report_dir / project["id"] / str(run_id) / created[1]["id"]).exists()
        assert (report_dir / project["id"] / str(run_id) / created[2]["id"]).exists()
    finally:
        workbench_api_env.client.app.state.workbench_settings = previous_settings

from __future__ import annotations

import asyncio
import uuid
from dataclasses import replace
from datetime import timedelta

import pytest
from sqlmodel import Session
from utils.workbench_env import WorkbenchApiEnv

from app import models as app_models
from app.models.base import get_datetime_utc
from app.services import import_background
from app.services.import_background import (
    _append_job_status,
    mark_import_run_background_failed,
    reconcile_stale_background_import_runs,
)
from app.services.import_errors import ImportServiceError
from app.services.import_execution import ImportUploadContent, ProjectImportUploadRequest


def _create_project_id(workbench_api_env: WorkbenchApiEnv) -> uuid.UUID:
    with Session(workbench_api_env.engine) as session:
        project = workbench_api_env.repositories.ProjectRepository(session).create_project(
            app_models.ProjectCreate(name=f"Mutation Project {uuid.uuid4()}")
        )
        session.commit()
        return project.id


def test_background_import_reconciliation_ignores_non_background_runs(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    project_id = _create_project_id(workbench_api_env)
    active_settings = replace(
        workbench_api_env.client.app.state.workbench_settings,
        BACKGROUND_IMPORT_STALE_MINUTES=1,
    )

    with Session(workbench_api_env.engine) as session:
        run = workbench_api_env.repositories.RunRepository(session).create_analysis_run(
            project_id=project_id,
            input_type="cve-list",
            filename="request-cves.txt",
            status=app_models.AnalysisRunStatus.PENDING,
            summary_json={
                "import_job": {
                    "id": "request-job",
                    "status": "pending",
                    "execution_mode": "request",
                    "status_history": [{"status": "pending"}],
                }
            },
        )
        run.started_at = get_datetime_utc() - timedelta(minutes=5)
        session.add(run)
        session.commit()
        run_id = run.id

    reconciled = reconcile_stale_background_import_runs(
        engine=workbench_api_env.engine,
        settings=active_settings,
    )

    assert reconciled == 0
    with Session(workbench_api_env.engine) as session:
        run = session.get(app_models.AnalysisRun, run_id)
        assert run is not None
        assert run.status == app_models.AnalysisRunStatus.PENDING
        assert "background_error" not in run.summary_json


def test_mark_background_failed_preserves_job_history_and_terminal_noops(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    project_id = _create_project_id(workbench_api_env)

    with Session(workbench_api_env.engine) as session:
        repository = workbench_api_env.repositories.RunRepository(session)
        running = repository.create_analysis_run(
            project_id=project_id,
            input_type="cve-list",
            filename="background-cves.txt",
            status=app_models.AnalysisRunStatus.RUNNING,
            summary_json={
                "import_job": {
                    "id": "stable-job-id",
                    "status": "running",
                    "execution_mode": "background",
                    "status_history": [{"status": "pending"}, {"status": "running"}],
                }
            },
        )
        terminal = repository.create_analysis_run(
            project_id=project_id,
            input_type="cve-list",
            filename="terminal-cves.txt",
            status=app_models.AnalysisRunStatus.SUCCEEDED,
            summary_json={
                "import_job": {
                    "id": "terminal-job-id",
                    "status": "succeeded",
                    "execution_mode": "background",
                    "status_history": [{"status": "succeeded"}],
                }
            },
        )
        session.commit()

        failed = mark_import_run_background_failed(
            session=session,
            run_id=running.id,
            error_message="background worker crashed",
        )
        terminal_noop = mark_import_run_background_failed(
            session=session,
            run_id=terminal.id,
            error_message="should not change",
        )

        assert failed is not None
        assert failed.status == app_models.AnalysisRunStatus.FAILED
        assert failed.error_message == "background worker crashed"
        assert failed.summary_json["import_job"]["id"] == "stable-job-id"
        assert [item["status"] for item in failed.summary_json["import_job"]["status_history"]] == [
            "pending",
            "running",
            "failed",
        ]
        assert terminal_noop is not None
        assert terminal_noop.status == app_models.AnalysisRunStatus.SUCCEEDED
        assert "background_error" not in terminal_noop.summary_json

    assert _append_job_status([{"status": "failed"}], "failed") == [{"status": "failed"}]


def test_background_import_runner_handles_service_and_unexpected_errors(
    workbench_api_env: WorkbenchApiEnv,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project_id = _create_project_id(workbench_api_env)
    settings = workbench_api_env.client.app.state.workbench_settings
    upload = ProjectImportUploadRequest(
        input_type="cve-list",
        file=ImportUploadContent(
            filename="background-cves.txt",
            content_type="text/plain",
            content=b"CVE-2024-3094\n",
        ),
    )

    async def raise_import_service_error(**_kwargs: object) -> None:
        raise ImportServiceError(status_code=400, detail="accepted import failure")

    with Session(workbench_api_env.engine) as session:
        service_error_run = workbench_api_env.repositories.RunRepository(
            session
        ).create_analysis_run(
            project_id=project_id,
            input_type="cve-list",
            filename="service-error.txt",
            status=app_models.AnalysisRunStatus.RUNNING,
            summary_json={
                "import_job": {
                    "id": "service-error-job",
                    "status": "running",
                    "execution_mode": "background",
                    "status_history": [{"status": "running"}],
                }
            },
        )
        session.commit()
        service_error_run_id = service_error_run.id

    monkeypatch.setattr(
        import_background,
        "execute_project_import_upload",
        raise_import_service_error,
    )
    asyncio.run(
        import_background.execute_project_import_upload_background(
            workbench_api_env.engine,
            settings,
            project_id,
            uuid.uuid4(),
            upload,
            service_error_run_id,
        )
    )
    with Session(workbench_api_env.engine) as session:
        run = session.get(app_models.AnalysisRun, service_error_run_id)
        assert run is not None
        assert run.status == app_models.AnalysisRunStatus.RUNNING
        assert "background_error" not in run.summary_json

    async def raise_unexpected_error(**_kwargs: object) -> None:
        raise RuntimeError("boom")

    with Session(workbench_api_env.engine) as session:
        unexpected_error_run = workbench_api_env.repositories.RunRepository(
            session
        ).create_analysis_run(
            project_id=project_id,
            input_type="cve-list",
            filename="unexpected-error.txt",
            status=app_models.AnalysisRunStatus.RUNNING,
            summary_json={
                "import_job": {
                    "id": "unexpected-error-job",
                    "status": "running",
                    "execution_mode": "background",
                    "status_history": [{"status": "running"}],
                }
            },
        )
        session.commit()
        unexpected_error_run_id = unexpected_error_run.id

    monkeypatch.setattr(
        import_background,
        "execute_project_import_upload",
        raise_unexpected_error,
    )
    asyncio.run(
        import_background.execute_project_import_upload_background(
            workbench_api_env.engine,
            settings,
            project_id,
            uuid.uuid4(),
            upload,
            unexpected_error_run_id,
        )
    )
    with Session(workbench_api_env.engine) as session:
        run = session.get(app_models.AnalysisRun, unexpected_error_run_id)
        assert run is not None
        assert run.status == app_models.AnalysisRunStatus.FAILED
        assert run.summary_json["background_error"]["stage"] == "background_import"

"""Provider update-job orchestration."""

from __future__ import annotations

import uuid
from datetime import timedelta

from sqlalchemy.engine import Engine
from sqlmodel import Session

from app.core.config import Settings
from app.models import (
    AnalysisRun,
    AnalysisRunStatus,
    ProviderUpdateJobCreate,
    WorkflowRunKind,
    WorkflowRunStatus,
)
from app.models.base import get_datetime_utc
from app.repositories import RunRepository, WorkflowRepository
from app.services.provider_update_constants import (
    PROVIDER_UPDATE_INPUT_TYPE,
    PROVIDER_UPDATE_LOCK_FILE,
    PROVIDER_UPDATE_LOCK_STALE_SECONDS,
    PROVIDER_UPDATE_PROJECT_NAME,
    VALID_PROVIDER_SOURCES,
)
from app.services.provider_update_errors import (
    ProviderUpdateConflict,
    ProviderUpdateRefreshError,
    ProviderUpdateValidationError,
)
from app.services.provider_update_inputs import (
    _dict_payload,
    _int_value,
    _normalize_sources,
    _other_running_update,
    _provider_update_cve_ids,
    _provider_update_project,
    _redacted_payload,
    _string_list,
)
from app.services.provider_update_locking import (
    _provider_update_lock,
    _provider_update_lock_is_stale,
    _reject_active_provider_update_lock,
)
from app.services.provider_update_snapshot import (
    _cached_provider_records,
    _latest_epss_date,
    _latest_kev_date,
    _latest_nvd_sync,
    _load_latest_snapshot_items,
    _provider_records_for_snapshot,
    _provider_refresh_failure,
    _provider_source_metadata,
    _write_provider_snapshot,
)
from app.services.run_workflow_metadata import (
    merge_summary_payload,
    set_workflow_error,
    set_workflow_summary,
    update_workflow_summary,
    workflow_summary_payload,
)


def create_provider_update_job(
    session: Session,
    *,
    settings: Settings,
    payload: ProviderUpdateJobCreate,
) -> AnalysisRun:
    """Create and synchronously execute a deterministic cache-friendly update job."""
    repository = RunRepository(session)
    if repository.get_running_provider_update_run() is not None:
        raise ProviderUpdateConflict(
            "Provider update already running; retry after the active job finishes."
        )

    selected_sources, cve_ids = _provider_update_request_inputs(session, payload=payload)
    run = _create_provider_update_run(
        repository,
        session=session,
        selected_sources=selected_sources,
        cve_ids=cve_ids,
        cache_only=payload.cache_only,
        status=AnalysisRunStatus.RUNNING,
        execution_mode="request",
    )
    return _execute_provider_update_run(
        session=session,
        repository=repository,
        run=run,
        settings=settings,
        selected_sources=selected_sources,
        cve_ids=cve_ids,
        cache_only=payload.cache_only,
        execution_mode="request",
        fail_conflicts=False,
    )


def enqueue_provider_update_job(
    session: Session,
    *,
    settings: Settings,
    payload: ProviderUpdateJobCreate,
) -> AnalysisRun:
    """Create a provider update job that can be resumed outside the request path."""
    repository = RunRepository(session)
    if repository.get_running_provider_update_run() is not None:
        raise ProviderUpdateConflict(
            "Provider update already running; retry after the active job finishes."
        )
    _reject_active_provider_update_lock(settings.provider_snapshot_dir_path)
    selected_sources, cve_ids = _provider_update_request_inputs(session, payload=payload)
    return _create_provider_update_run(
        repository,
        session=session,
        selected_sources=selected_sources,
        cve_ids=cve_ids,
        cache_only=payload.cache_only,
        status=AnalysisRunStatus.PENDING,
        execution_mode="background",
    )


def execute_provider_update_job_background(
    engine: Engine,
    settings: Settings,
    payload: ProviderUpdateJobCreate,
    run_id: uuid.UUID,
) -> None:
    """Resume a queued provider update job outside the request/response path."""
    with Session(engine) as session:
        try:
            resume_provider_update_job(
                session,
                settings=settings,
                payload=payload,
                run_id=run_id,
            )
            session.commit()
        except Exception:
            session.rollback()
            mark_provider_update_job_background_failed(session=session, run_id=run_id)


def resume_provider_update_job(
    session: Session,
    *,
    settings: Settings,
    payload: ProviderUpdateJobCreate,
    run_id: uuid.UUID,
    execution_mode: str = "background",
) -> AnalysisRun | None:
    """Execute a pending provider update job in the current session."""
    repository = RunRepository(session)
    run = repository.get_analysis_run(run_id)
    if run is None or run.input_type != PROVIDER_UPDATE_INPUT_TYPE:
        return None
    if run.status not in {AnalysisRunStatus.PENDING, AnalysisRunStatus.RUNNING}:
        return run

    selected_sources, cve_ids = _provider_update_request_inputs(session, payload=payload)
    run.status = AnalysisRunStatus.RUNNING
    update_workflow_summary(
        run,
        requested_sources=selected_sources,
        requested_cves=len(cve_ids),
        cache_only=payload.cache_only,
        execution_mode=execution_mode,
        mode="workbench-provider-update",
    )
    session.add(run)
    session.flush()
    return _execute_provider_update_run(
        session=session,
        repository=repository,
        run=run,
        settings=settings,
        selected_sources=selected_sources,
        cve_ids=cve_ids,
        cache_only=payload.cache_only,
        execution_mode=execution_mode,
        fail_conflicts=True,
    )


def reconcile_stale_provider_update_runs(
    *,
    engine: Engine,
    settings: Settings,
) -> int:
    """Fail stale provider update rows that could otherwise block future updates."""
    stale_before = get_datetime_utc() - timedelta(minutes=settings.PROVIDER_UPDATE_STALE_MINUTES)
    reconciled = 0
    with Session(engine) as session:
        repository = RunRepository(session)
        for run in repository.list_active_analysis_runs_started_before(stale_before):
            if run.input_type != PROVIDER_UPDATE_INPUT_TYPE:
                continue
            failed = mark_provider_update_job_background_failed(
                session=session,
                run_id=run.id,
                error_message=(
                    "Provider update did not finish before the Workbench process restarted."
                ),
            )
            if failed is not None and failed.status == AnalysisRunStatus.FAILED:
                reconciled += 1
    return reconciled


def mark_provider_update_job_background_failed(
    *,
    session: Session,
    run_id: uuid.UUID,
    error_message: str = "Provider update execution failed.",
) -> AnalysisRun | None:
    """Mark an unfinished provider update failed when background execution exits."""
    repository = RunRepository(session)
    run = repository.get_analysis_run(run_id)
    if run is None or run.status not in {AnalysisRunStatus.PENDING, AnalysisRunStatus.RUNNING}:
        return run
    metadata = workflow_summary_payload(run)
    failed = _mark_provider_update_run_failed(
        session=session,
        run=run,
        selected_sources=_string_list(metadata.get("requested_sources")),
        requested_cves=_int_value(metadata.get("requested_cves")),
        cache_only=bool(metadata.get("cache_only", True)),
        execution_mode=str(metadata.get("execution_mode") or "background"),
        error_message=error_message,
        detail="Provider refresh failed before replacing or mutating existing snapshots.",
    )
    session.commit()
    return failed


def _execute_provider_update_run(
    *,
    session: Session,
    repository: RunRepository,
    run: AnalysisRun,
    settings: Settings,
    selected_sources: list[str],
    cve_ids: list[str],
    cache_only: bool,
    execution_mode: str,
    fail_conflicts: bool,
) -> AnalysisRun:
    workflow_repository = WorkflowRepository(session)
    workflow = workflow_repository.ensure_analysis_workflow(
        kind=WorkflowRunKind.PROVIDER_UPDATE,
        analysis_run_id=run.id,
        project_id=run.project_id,
        title="Provider snapshot refresh",
        handler="app.services.provider_updates._execute_provider_update_run",
        status=WorkflowRunStatus.RUNNING,
        execution_mode=execution_mode,
        current_stage="refresh_snapshot",
        metadata_json={
            "requested_sources": selected_sources,
            "requested_cves": len(cve_ids),
            "cache_only": cache_only,
        },
    )
    workflow_repository.start_workflow(
        workflow.id,
        stage="refresh_snapshot",
        message="Refreshing provider snapshot.",
        progress_current=1,
        progress_total=3,
    )
    try:
        with _provider_update_lock(settings.provider_snapshot_dir_path):
            workflow_repository.record_stage(
                workflow.id,
                stage="provider_lock_acquired",
                message="Provider snapshot lock acquired.",
                progress_current=1,
                progress_total=3,
            )
            if _other_running_update(repository, run.id) is not None:
                raise ProviderUpdateConflict(
                    "Provider update already running; retry after the active job finishes."
                )
            snapshot, metadata = _write_provider_snapshot(
                repository,
                settings=settings,
                selected_sources=selected_sources,
                cve_ids=cve_ids,
                cache_only=cache_only,
            )
    except ProviderUpdateConflict as exc:
        if fail_conflicts:
            workflow_repository.finish_workflow(
                workflow.id,
                status=WorkflowRunStatus.FAILED,
                stage="conflict",
                message=str(exc),
                progress_current=1,
                progress_total=3,
                error_message=str(exc),
                error_json={"stage": "conflict", "error_type": exc.__class__.__name__},
            )
            return _mark_provider_update_run_failed(
                session=session,
                run=run,
                selected_sources=selected_sources,
                requested_cves=len(cve_ids),
                cache_only=cache_only,
                execution_mode=execution_mode,
                error_message=str(exc),
                detail="Provider refresh did not start because another job was active.",
            )
        raise
    except Exception as exc:
        workflow_repository.finish_workflow(
            workflow.id,
            status=WorkflowRunStatus.FAILED,
            stage="refresh_snapshot",
            message=str(exc),
            progress_current=1,
            progress_total=3,
            error_message=str(exc),
            error_json={"stage": "refresh_snapshot", "error_type": exc.__class__.__name__},
        )
        return _mark_provider_update_run_failed(
            session=session,
            run=run,
            selected_sources=selected_sources,
            requested_cves=len(cve_ids),
            cache_only=cache_only,
            execution_mode=execution_mode,
            error_message=str(exc),
            detail="Provider refresh failed before replacing or mutating existing snapshots.",
        )

    metadata = {
        **metadata,
        "requested_sources": selected_sources,
        "requested_cves": len(cve_ids),
        "cache_only": cache_only,
        "execution_mode": execution_mode,
        "provider_snapshot_id": str(snapshot.id),
    }
    run.provider_snapshot_id = snapshot.id
    run.status = AnalysisRunStatus.COMPLETED
    run.finished_at = get_datetime_utc()
    set_workflow_summary(run, _redacted_payload(metadata))
    workflow_repository.attach_artifact(
        workflow.id,
        artifact_kind="provider_snapshot",
        artifact_id=str(snapshot.id),
        metadata_json={
            "selected_sources": selected_sources,
            "requested_cves": len(cve_ids),
        },
    )
    workflow_repository.finish_workflow(
        workflow.id,
        status=WorkflowRunStatus.SUCCEEDED,
        stage="succeeded",
        message="Provider snapshot refresh succeeded.",
        progress_current=3,
        progress_total=3,
        metadata_json={"provider_snapshot_id": str(snapshot.id)},
    )
    session.add(run)
    session.flush()
    return run


def _provider_update_request_inputs(
    session: Session,
    *,
    payload: ProviderUpdateJobCreate,
) -> tuple[list[str], list[str]]:
    return _normalize_sources(payload.sources), _provider_update_cve_ids(session, payload=payload)


def _create_provider_update_run(
    repository: RunRepository,
    *,
    session: Session,
    selected_sources: list[str],
    cve_ids: list[str],
    cache_only: bool,
    status: AnalysisRunStatus,
    execution_mode: str,
) -> AnalysisRun:
    project = _provider_update_project(session)
    run = repository.create_analysis_run(
        project_id=project.id,
        input_type=PROVIDER_UPDATE_INPUT_TYPE,
        status=status,
        summary_json=merge_summary_payload(
            None,
            requested_sources=selected_sources,
            requested_cves=len(cve_ids),
            cache_only=cache_only,
            execution_mode=execution_mode,
            mode="workbench-provider-update",
        ),
    )
    queued = status == AnalysisRunStatus.PENDING
    WorkflowRepository(session).ensure_analysis_workflow(
        kind=WorkflowRunKind.PROVIDER_UPDATE,
        analysis_run_id=run.id,
        project_id=project.id,
        title="Provider snapshot refresh",
        handler=(
            "app.services.provider_updates.resume_provider_update_job"
            if queued
            else "app.services.provider_updates._execute_provider_update_run"
        ),
        status=_workflow_status_for_run(status),
        execution_mode="worker" if queued else execution_mode,
        current_stage="queued" if status == AnalysisRunStatus.PENDING else "created",
        metadata_json={
            "requested_sources": selected_sources,
            "requested_cves": len(cve_ids),
            "cache_only": cache_only,
        },
        payload_json={
            "run_id": str(run.id),
            "sources": selected_sources,
            "cve_ids": cve_ids,
            "cache_only": cache_only,
        }
        if queued
        else None,
        max_retries=2 if queued else 0,
        queue_name="default" if queued else None,
    )
    return run


def _mark_provider_update_run_failed(
    *,
    session: Session,
    run: AnalysisRun,
    selected_sources: list[str],
    requested_cves: int,
    cache_only: bool,
    execution_mode: str,
    error_message: str,
    detail: str,
) -> AnalysisRun:
    failed_metadata = {
        "requested_sources": selected_sources,
        "requested_cves": requested_cves,
        "cache_only": cache_only,
        "execution_mode": execution_mode,
        "snapshot_created": False,
        "detail": detail,
    }
    run.status = AnalysisRunStatus.FAILED
    run.finished_at = get_datetime_utc()
    run.error_message = error_message
    set_workflow_error(run, None, **_redacted_payload({"detail": error_message}))
    set_workflow_summary(run, _redacted_payload(failed_metadata))
    workflow_repository = WorkflowRepository(session)
    workflow = workflow_repository.get_latest_analysis_workflow(
        analysis_run_id=run.id,
        kind=WorkflowRunKind.PROVIDER_UPDATE,
    )
    if workflow is not None and workflow.status != WorkflowRunStatus.FAILED:
        workflow_repository.finish_workflow(
            workflow.id,
            status=WorkflowRunStatus.FAILED,
            stage="failed",
            message=error_message,
            error_message=error_message,
            error_json={"stage": "provider_update", "detail": detail},
        )
    session.add(run)
    session.flush()
    return run


def _workflow_status_for_run(status: AnalysisRunStatus | str) -> WorkflowRunStatus:
    normalized = AnalysisRunStatus(status)
    if normalized == AnalysisRunStatus.RUNNING:
        return WorkflowRunStatus.RUNNING
    if normalized == AnalysisRunStatus.FAILED:
        return WorkflowRunStatus.FAILED
    if normalized == AnalysisRunStatus.CANCELLED:
        return WorkflowRunStatus.CANCELLED
    if normalized in {AnalysisRunStatus.SUCCEEDED, AnalysisRunStatus.COMPLETED}:
        return WorkflowRunStatus.SUCCEEDED
    if normalized == AnalysisRunStatus.COMPLETED_WITH_ERRORS:
        return WorkflowRunStatus.COMPLETED_WITH_ERRORS
    return WorkflowRunStatus.PENDING


__all__ = [
    "create_provider_update_job",
    "enqueue_provider_update_job",
    "execute_provider_update_job_background",
    "resume_provider_update_job",
    "reconcile_stale_provider_update_runs",
    "mark_provider_update_job_background_failed",
    "_execute_provider_update_run",
    "_provider_update_request_inputs",
    "_create_provider_update_run",
    "_mark_provider_update_run_failed",
    "PROVIDER_UPDATE_INPUT_TYPE",
    "PROVIDER_UPDATE_PROJECT_NAME",
    "PROVIDER_UPDATE_LOCK_FILE",
    "PROVIDER_UPDATE_LOCK_STALE_SECONDS",
    "VALID_PROVIDER_SOURCES",
    "ProviderUpdateConflict",
    "ProviderUpdateValidationError",
    "ProviderUpdateRefreshError",
    "_normalize_sources",
    "_provider_update_cve_ids",
    "_provider_update_project",
    "_other_running_update",
    "_dict_payload",
    "_string_list",
    "_int_value",
    "_redacted_payload",
    "_provider_update_lock",
    "_reject_active_provider_update_lock",
    "_provider_update_lock_is_stale",
    "_write_provider_snapshot",
    "_provider_refresh_failure",
    "_load_latest_snapshot_items",
    "_provider_records_for_snapshot",
    "_cached_provider_records",
    "_provider_source_metadata",
    "_latest_nvd_sync",
    "_latest_epss_date",
    "_latest_kev_date",
]

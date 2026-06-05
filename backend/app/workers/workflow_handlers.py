"""Handler registry for DB-backed durable workflow jobs."""

from __future__ import annotations

import asyncio
import uuid
from pathlib import Path
from typing import Any

from sqlmodel import Session

from app.core.config import Settings
from app.core.local_actor import configured_local_actor
from app.models import (
    AnalysisRun,
    Project,
    ProviderUpdateJobCreate,
    WorkflowRun,
    WorkflowRunKind,
    WorkflowRunStatus,
)
from app.repositories import WorkflowRepository
from app.services.import_errors import ImportServiceError
from app.services.import_execution import execute_project_import_upload
from app.services.import_execution_types import ImportUploadContent, ProjectImportUploadRequest
from app.services.provider_updates import resume_provider_update_job
from app.services.reports import ReportGenerationError, ReportService
from app.services.workflow_execution import (
    WorkflowCancellationRequested,
    WorkflowExecutionContext,
)
from app.services.workflows import finish_cancelled_workflow


class WorkflowCancelled(RuntimeError):
    """Raised when a worker sees a cooperative cancellation request."""


class WorkflowHandlerError(RuntimeError):
    """Raised when a queued workflow payload cannot be executed."""


class WorkflowNonRetryableError(RuntimeError):
    """Raised when a workflow failed because of deterministic user input."""


def execute_workflow_handler(
    session: Session,
    *,
    settings: Settings,
    workflow: WorkflowRun,
    worker_id: str | None = None,
    lease_seconds: int = 300,
) -> None:
    """Dispatch a claimed workflow to the concrete family handler."""
    repository = WorkflowRepository(session)
    context = WorkflowExecutionContext.for_workflow(
        repository,
        workflow.id,
        worker_id=worker_id,
        lease_seconds=lease_seconds,
    )
    try:
        _raise_if_cancelled(repository, workflow.id)
        if workflow.kind == WorkflowRunKind.IMPORT:
            _execute_import_workflow(session, settings=settings, workflow=workflow, context=context)
        elif workflow.kind == WorkflowRunKind.PROVIDER_UPDATE:
            _execute_provider_update_workflow(
                session,
                settings=settings,
                workflow=workflow,
                context=context,
            )
        elif workflow.kind == WorkflowRunKind.REPORT_GENERATION:
            _execute_report_generation_workflow(
                session,
                settings=settings,
                workflow=workflow,
                context=context,
            )
        else:  # pragma: no cover - enum exhaustiveness guard
            raise WorkflowHandlerError(f"Unsupported workflow kind: {workflow.kind}")
        _raise_if_cancelled(repository, workflow.id)
    except WorkflowCancellationRequested as exc:
        raise WorkflowCancelled(str(exc)) from exc
    refreshed = repository.require_workflow(workflow.id)
    if refreshed.status == WorkflowRunStatus.FAILED:
        raise WorkflowHandlerError(refreshed.error_message or "Workflow execution failed.")


def _execute_import_workflow(
    session: Session,
    *,
    settings: Settings,
    workflow: WorkflowRun,
    context: WorkflowExecutionContext | None = None,
) -> None:
    if workflow.analysis_run_id is None or workflow.project_id is None:
        raise WorkflowHandlerError("Import workflow is missing run/project linkage.")
    run = session.get(AnalysisRun, workflow.analysis_run_id)
    if run is None:
        raise WorkflowHandlerError(f"Analysis run not found: {workflow.analysis_run_id}")
    context = context or WorkflowExecutionContext.for_workflow(
        WorkflowRepository(session),
        workflow.id,
    )
    upload = _stored_import_upload_request(
        settings,
        run=run,
        workflow=workflow,
        payload=workflow.payload_json,
    )
    try:
        asyncio.run(
            execute_project_import_upload(
                project_id=workflow.project_id,
                session=session,
                local_actor=configured_local_actor(settings),
                settings=settings,
                upload=upload,
                existing_run_id=run.id,
                workflow_context=context,
            )
        )
    except ImportServiceError as exc:
        raise WorkflowNonRetryableError(str(exc)) from exc


def _execute_provider_update_workflow(
    session: Session,
    *,
    settings: Settings,
    workflow: WorkflowRun,
    context: WorkflowExecutionContext | None = None,
) -> None:
    if workflow.analysis_run_id is None:
        raise WorkflowHandlerError("Provider update workflow is missing run linkage.")
    context = context or WorkflowExecutionContext.for_workflow(
        WorkflowRepository(session),
        workflow.id,
    )
    payload = workflow.payload_json or {}
    job_payload = ProviderUpdateJobCreate(
        sources=_string_list(payload.get("sources")) or ["nvd", "epss", "kev"],
        cve_ids=_string_list(payload.get("cve_ids")),
        max_cves=payload.get("max_cves") if isinstance(payload.get("max_cves"), int) else None,
        cache_only=bool(payload.get("cache_only", True)),
    )
    resume_provider_update_job(
        session,
        settings=settings,
        payload=job_payload,
        run_id=workflow.analysis_run_id,
        workflow_context=context,
    )


def _execute_report_generation_workflow(
    session: Session,
    *,
    settings: Settings,
    workflow: WorkflowRun,
    context: WorkflowExecutionContext | None = None,
) -> None:
    payload = workflow.payload_json or {}
    context = context or WorkflowExecutionContext.for_workflow(
        WorkflowRepository(session),
        workflow.id,
    )
    run_id = _uuid_value(payload.get("run_id")) or workflow.analysis_run_id
    if run_id is None:
        raise WorkflowHandlerError("Report workflow is missing run linkage.")
    run = session.get(AnalysisRun, run_id)
    if run is None:
        raise WorkflowHandlerError(f"Analysis run not found: {run_id}")
    project = session.get(Project, run.project_id)
    if project is None:
        raise WorkflowHandlerError(f"Project not found: {run.project_id}")
    report_format = str(payload.get("format") or "markdown")
    attack_filter = str(payload.get("attack_filter") or "all")
    try:
        ReportService(session, settings).create_report_for_workflow(
            run=run,
            project=project,
            workflow_id=workflow.id,
            report_format=report_format,
            attack_filter=attack_filter,
            workflow_context=context,
        )
    except ReportGenerationError as exc:
        raise WorkflowNonRetryableError(str(exc)) from exc


def _stored_import_upload_request(
    settings: Settings,
    *,
    run: AnalysisRun,
    workflow: WorkflowRun | None = None,
    payload: dict[str, Any],
) -> ProjectImportUploadRequest:
    summary = dict(workflow.result_ref_json or {}) if workflow is not None else {}
    input_upload = _dict_value(summary.get("input_upload"))
    if not input_upload:
        raise WorkflowHandlerError("Import run has no stored input upload.")
    asset_context_upload = _dict_value(summary.get("asset_context_upload"))
    vex_upload = _dict_value(summary.get("vex_upload"))
    return ProjectImportUploadRequest(
        input_type=str(payload.get("input_type") or run.input_type),
        file=_upload_content(settings, input_upload),
        asset_context_file=_optional_upload_content(settings, asset_context_upload),
        vex_file=_optional_upload_content(settings, vex_upload),
        provider_snapshot_file=_optional_string(payload.get("provider_snapshot_file")),
        locked_provider_data=bool(payload.get("locked_provider_data", False)),
        attack_source=str(payload.get("attack_source") or "none"),
        attack_mapping_file=_optional_string(payload.get("attack_mapping_file")),
        attack_technique_metadata_file=_optional_string(
            payload.get("attack_technique_metadata_file")
        ),
    )


def _upload_content(settings: Settings, upload: dict[str, Any]) -> ImportUploadContent:
    storage_ref = _optional_string(upload.get("storage_ref") or upload.get("path"))
    if storage_ref is None:
        raise WorkflowHandlerError("Stored upload reference is missing.")
    return ImportUploadContent(
        filename=_optional_string(upload.get("original_filename") or upload.get("stored_filename")),
        content_type=_optional_string(upload.get("content_type")),
        content=_read_upload_ref(settings, storage_ref),
    )


def _optional_upload_content(
    settings: Settings,
    upload: dict[str, Any],
) -> ImportUploadContent | None:
    if not upload:
        return None
    return _upload_content(settings, upload)


def _read_upload_ref(settings: Settings, storage_ref: str) -> bytes:
    root = settings.import_upload_dir_path.resolve(strict=False)
    path = (root / storage_ref).resolve(strict=False)
    if not path.is_relative_to(root):
        raise WorkflowHandlerError("Stored upload reference escapes upload root.")
    if not path.is_file():
        raise WorkflowHandlerError(f"Stored upload not found: {Path(storage_ref).name}")
    return path.read_bytes()


def _raise_if_cancelled(repository: WorkflowRepository, workflow_id: uuid.UUID) -> None:
    workflow = repository.require_workflow(workflow_id)
    if workflow.cancellation_requested:
        finish_cancelled_workflow(
            repository.session,
            workflow_id,
            message="Workflow cancelled by user request.",
        )
        raise WorkflowCancelled("Workflow cancelled by user request.")


def _dict_value(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def _optional_string(value: Any) -> str | None:
    if isinstance(value, str) and value.strip():
        return value
    return None


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if isinstance(item, str) and item.strip()]


def _uuid_value(value: Any) -> uuid.UUID | None:
    if isinstance(value, uuid.UUID):
        return value
    if isinstance(value, str):
        try:
            return uuid.UUID(value)
        except ValueError:
            return None
    return None

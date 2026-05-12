"""Application service for Workbench import upload execution."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any, Literal

from sqlmodel import Session

from app.core.config import Settings
from app.core.local_actor import LocalWorkbenchActor
from app.domain.import_asset_context import (
    canonicalize_occurrence_asset_context as _canonicalize_occurrence_asset_context,
)
from app.importers import ImporterParseError, ImporterValidationError, build_importer_registry
from app.models import AnalysisRun, AnalysisRunStatus
from app.repositories import RunRepository
from app.services.analysis import AnalysisService, WorkbenchAnalysisError
from app.services.import_execution_context import (
    _apply_workbench_asset_context,
    _apply_workbench_vex,
)
from app.services.import_execution_failures import (
    raise_analysis_failure as _raise_analysis_failure,
)
from app.services.import_execution_parse_failures import (
    raise_parse_failure as _raise_parse_failure,
)
from app.services.import_execution_parse_failures import (
    raise_sidecar_parse_failure as _raise_sidecar_parse_failure,
)
from app.services.import_execution_persistence import _persist_workbench_occurrences
from app.services.import_execution_summary import (
    _job_payload,
    _job_status_entry,
    _record_import_audit,
)
from app.services.import_execution_types import (
    ImportUploadContent,
    PreparedImportUpload,
    ProjectImportUploadRequest,
)
from app.services.import_execution_uploads import (
    apply_stored_upload_summaries as _apply_stored_upload_summaries,
)
from app.services.import_execution_uploads import (
    mark_import_run_running as _mark_import_run_running,
)
from app.services.import_execution_uploads import (
    prepare_import_upload as _prepare_import_upload,
)
from app.services.import_execution_uploads import (
    resolve_import_run as _resolve_import_run,
)
from app.services.import_execution_uploads import (
    store_prepared_uploads as _store_prepared_uploads,
)

__all__ = [
    "ImportUploadContent",
    "ProjectImportUploadRequest",
    "execute_project_import_upload",
]


@dataclass(frozen=True, slots=True)
class _ImportFailureContext:
    session: Session
    run_repo: RunRepository
    run: AnalysisRun
    local_actor: LocalWorkbenchActor
    project_id: uuid.UUID
    job_id: str
    job_history: list[dict[str, str]]
    ignored_lines: int
    input_type: str
    execution_mode: str


def _parse_prepared_upload(prepared: PreparedImportUpload) -> list[Any]:
    occurrences = build_importer_registry().parse(
        prepared.input_type,
        prepared.upload_bytes,
        filename=prepared.stored_filename,
    )
    return [_canonicalize_occurrence_asset_context(item) for item in occurrences]


async def execute_project_import_upload(
    *,
    project_id: uuid.UUID,
    session: Session,
    local_actor: LocalWorkbenchActor,
    settings: Settings,
    upload: ProjectImportUploadRequest,
    defer_execution: bool = False,
    existing_run_id: uuid.UUID | None = None,
    execution_mode: Literal["request", "background"] = "request",
) -> AnalysisRun:
    """Securely upload, normalize, and persist one Workbench import file."""
    prepared = _prepare_import_upload(upload, settings=settings)
    run_repo = RunRepository(session)
    resolved_run = _resolve_import_run(
        run_repo=run_repo,
        project_id=project_id,
        prepared=prepared,
        existing_run_id=existing_run_id,
        execution_mode=execution_mode,
    )
    run = resolved_run.run
    if resolved_run.already_finished:
        return run

    artifacts = _store_prepared_uploads(
        settings,
        project_id=project_id,
        run_id=run.id,
        prepared=prepared,
    )
    _apply_stored_upload_summaries(
        run,
        resolved_run=resolved_run,
        artifacts=artifacts,
        execution_mode=execution_mode,
    )
    if defer_execution:
        session.commit()
        session.refresh(run)
        return run

    job_history = _mark_import_run_running(
        run,
        job_id=resolved_run.job_id,
        job_history=resolved_run.job_history,
        execution_mode=execution_mode,
    )
    session.flush()
    failure_context = _ImportFailureContext(
        session=session,
        run_repo=run_repo,
        run=run,
        local_actor=local_actor,
        project_id=project_id,
        job_id=resolved_run.job_id,
        job_history=job_history,
        ignored_lines=prepared.ignored_lines,
        input_type=prepared.input_type,
        execution_mode=execution_mode,
    )

    try:
        occurrences = _parse_prepared_upload(prepared)
    except (ImporterParseError, ImporterValidationError) as exc:
        _raise_parse_failure(
            session=failure_context.session,
            run_repo=failure_context.run_repo,
            run=failure_context.run,
            local_actor=failure_context.local_actor,
            project_id=failure_context.project_id,
            job_id=failure_context.job_id,
            job_history=failure_context.job_history,
            ignored_lines=failure_context.ignored_lines,
            input_type=failure_context.input_type,
            filename=prepared.stored_filename,
            exc=exc,
            execution_mode=failure_context.execution_mode,
        )

    asset_context_summary: dict[str, Any] | None = None
    if artifacts.asset_context_path is not None:
        try:
            occurrences, asset_context_summary = _apply_workbench_asset_context(
                occurrences,
                asset_context_path=artifacts.asset_context_path,
            )
        except ValueError as exc:
            _raise_sidecar_parse_failure(
                session=failure_context.session,
                run_repo=failure_context.run_repo,
                run=failure_context.run,
                local_actor=failure_context.local_actor,
                project_id=failure_context.project_id,
                job_id=failure_context.job_id,
                job_history=failure_context.job_history,
                ignored_lines=failure_context.ignored_lines,
                input_type=failure_context.input_type,
                error_key="asset_context_error",
                response_message="Asset context parsing failed.",
                filename=prepared.asset_context.stored_filename,
                stage="asset_context_parse",
                exc=exc,
                execution_mode=failure_context.execution_mode,
            )

    vex_summary: dict[str, Any] | None = None
    if artifacts.vex_path is not None:
        try:
            occurrences, vex_summary = _apply_workbench_vex(
                occurrences,
                vex_path=artifacts.vex_path,
            )
        except ValueError as exc:
            _raise_sidecar_parse_failure(
                session=failure_context.session,
                run_repo=failure_context.run_repo,
                run=failure_context.run,
                local_actor=failure_context.local_actor,
                project_id=failure_context.project_id,
                job_id=failure_context.job_id,
                job_history=failure_context.job_history,
                ignored_lines=failure_context.ignored_lines,
                input_type=failure_context.input_type,
                error_key="vex_error",
                response_message="VEX parsing failed.",
                filename=prepared.vex.stored_filename,
                stage="vex_parse",
                exc=exc,
                execution_mode=failure_context.execution_mode,
            )

    try:
        analysis_result = AnalysisService(session, settings).analyze_import(
            input_path=artifacts.upload_path,
            input_type=prepared.input_type,
            asset_context_file=artifacts.asset_context_path,
            provider_snapshot_file=prepared.provider_snapshot_path,
            locked_provider_data=prepared.locked_provider_data,
            attack_source=prepared.attack_source,
            attack_mapping_file=prepared.attack_mapping_path,
            attack_technique_metadata_file=prepared.attack_metadata_path,
            vex_files=[artifacts.vex_path] if artifacts.vex_path is not None else [],
        )
    except WorkbenchAnalysisError as exc:
        _raise_analysis_failure(
            session=failure_context.session,
            run_repo=failure_context.run_repo,
            run=failure_context.run,
            local_actor=failure_context.local_actor,
            project_id=failure_context.project_id,
            job_id=failure_context.job_id,
            job_history=failure_context.job_history,
            ignored_lines=failure_context.ignored_lines,
            input_type=failure_context.input_type,
            exc=exc,
            execution_mode=failure_context.execution_mode,
        )

    persist_summary = _persist_workbench_occurrences(
        session=session,
        project_id=project_id,
        run_id=run.id,
        occurrences=occurrences,
        analysis_result=analysis_result,
    )
    run.provider_snapshot_id = analysis_result.provider_snapshot_id
    finished_run = run_repo.finish_analysis_run(
        run.id,
        status=AnalysisRunStatus.SUCCEEDED,
        summary_json={
            **run.summary_json,
            "import_job": _job_payload(
                job_id=resolved_run.job_id,
                status="succeeded",
                status_history=[*job_history, _job_status_entry("succeeded")],
                execution_mode=execution_mode,
            ),
            **analysis_result.summary_json,
            **persist_summary,
            "asset_context": asset_context_summary,
            "vex": vex_summary,
            "ignored_lines": prepared.ignored_lines,
            "input_sha256": prepared.upload_sha256,
            "parse_errors": [],
        },
    )
    _record_import_audit(
        session,
        local_actor=local_actor,
        project_id=project_id,
        run_id=finished_run.id,
        status="success",
        stage="succeeded",
        input_type=prepared.input_type,
    )
    session.commit()
    return finished_run

"""Application service for Workbench import upload execution."""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass
from typing import Any, Literal

from sqlmodel import Session

from app.core.config import Settings
from app.domain.import_asset_context import (
    canonicalize_occurrence_asset_context as _canonicalize_occurrence_asset_context,
)
from app.importers import ImporterParseError, ImporterValidationError, build_importer_registry
from app.models import (
    AnalysisRun,
    AnalysisRunStatus,
    User,
)
from app.repositories import RunRepository
from app.services.analysis import AnalysisService, WorkbenchAnalysisError
from app.services.import_artifacts import (
    resolve_workbench_attack_artifact_path as _resolve_workbench_attack_artifact_path,
)
from app.services.import_artifacts import (
    resolve_workbench_provider_snapshot_path as _resolve_workbench_provider_snapshot_path,
)
from app.services.import_artifacts import (
    validate_attack_import_options as _validate_attack_import_options,
)
from app.services.import_errors import ImportServiceError
from app.services.import_execution_context import (
    _apply_workbench_asset_context,
    _apply_workbench_vex,
    _parse_errors,
)
from app.services.import_execution_failures import (
    raise_analysis_failure as _raise_analysis_failure,
)
from app.services.import_execution_persistence import _persist_workbench_occurrences
from app.services.import_execution_summary import (
    _job_payload,
    _job_status_entry,
    _record_import_audit,
)
from app.services.import_uploads import (
    has_optional_upload as _has_optional_upload,
)
from app.services.import_uploads import (
    ignored_line_count as _ignored_line_count,
)
from app.services.import_uploads import (
    normalize_input_type as _normalize_input_type,
)
from app.services.import_uploads import (
    optional_upload_summary as _optional_upload_summary,
)
from app.services.import_uploads import (
    reject_unsafe_upload_filename as _reject_unsafe_upload_filename,
)
from app.services.import_uploads import (
    sanitize_context_filename as _sanitize_context_filename,
)
from app.services.import_uploads import (
    sanitize_filename as _sanitize_filename,
)
from app.services.import_uploads import (
    sanitize_parser_error_message as _sanitize_parser_error_message,
)
from app.services.import_uploads import (
    sanitize_vex_filename as _sanitize_vex_filename,
)
from app.services.import_uploads import (
    store_upload as _store_upload,
)
from app.services.import_uploads import (
    upload_storage_ref as _upload_storage_ref,
)
from app.services.import_uploads import (
    upload_summary as _upload_summary,
)
from app.services.import_uploads import (
    upload_summary_with_path as _upload_summary_with_path,
)
from app.services.import_uploads import (
    validate_aggregate_upload_size as _validate_aggregate_upload_size,
)
from app.services.import_uploads import (
    validate_asset_context_upload as _validate_asset_context_upload,
)
from app.services.import_uploads import (
    validate_input_type as _validate_input_type,
)
from app.services.import_uploads import (
    validate_mime_hint as _validate_mime_hint,
)
from app.services.import_uploads import (
    validate_upload_suffix as _validate_upload_suffix,
)
from app.services.import_uploads import (
    validate_vex_upload as _validate_vex_upload,
)


@dataclass(frozen=True, slots=True)
class ImportUploadContent:
    """HTTP-independent upload payload accepted by the import service."""

    filename: str | None
    content_type: str | None
    content: bytes


@dataclass(frozen=True, slots=True)
class ProjectImportUploadRequest:
    """Workbench import request normalized at the route boundary."""

    input_type: str
    file: ImportUploadContent
    asset_context_file: ImportUploadContent | None = None
    vex_file: ImportUploadContent | None = None
    provider_snapshot_file: str | None = None
    locked_provider_data: bool = False
    attack_source: str = "none"
    attack_mapping_file: str | None = None
    attack_technique_metadata_file: str | None = None


def _append_job_status(
    status_history: list[dict[str, str]],
    status: str,
) -> list[dict[str, str]]:
    if status_history and status_history[-1].get("status") == status:
        return status_history
    return [*status_history, _job_status_entry(status)]


async def execute_project_import_upload(
    *,
    project_id: uuid.UUID,
    session: Session,
    current_user: User,
    settings: Settings,
    upload: ProjectImportUploadRequest,
    defer_execution: bool = False,
    existing_run_id: uuid.UUID | None = None,
    execution_mode: Literal["request", "background"] = "request",
) -> AnalysisRun:
    """Securely upload, normalize, and persist one Workbench import file."""
    normalized_input_type = _normalize_input_type(upload.input_type)
    _validate_input_type(normalized_input_type)
    file = upload.file
    original_filename = file.filename or "upload"
    _reject_unsafe_upload_filename(original_filename)
    stored_filename = _sanitize_filename(original_filename)
    _validate_upload_suffix(stored_filename, input_type=normalized_input_type)
    _validate_mime_hint(file.content_type, input_type=normalized_input_type)
    asset_context_upload = (
        upload.asset_context_file
        if _has_optional_upload(
            upload.asset_context_file.filename if upload.asset_context_file is not None else None
        )
        else None
    )
    asset_context_original_filename = (
        asset_context_upload.filename if asset_context_upload is not None else None
    )
    asset_context_stored_filename: str | None = None
    if asset_context_upload is not None and asset_context_original_filename is not None:
        _reject_unsafe_upload_filename(asset_context_original_filename)
        asset_context_stored_filename = _sanitize_context_filename(
            asset_context_original_filename,
            reserved_filename=stored_filename,
        )
        _validate_asset_context_upload(
            asset_context_stored_filename,
            asset_context_upload.content_type,
        )
    vex_upload = (
        upload.vex_file
        if _has_optional_upload(upload.vex_file.filename if upload.vex_file is not None else None)
        else None
    )
    vex_original_filename = vex_upload.filename if vex_upload is not None else None
    vex_stored_filename: str | None = None
    if vex_upload is not None and vex_original_filename is not None:
        _reject_unsafe_upload_filename(vex_original_filename)
        vex_stored_filename = _sanitize_vex_filename(
            vex_original_filename,
            reserved_filenames={stored_filename, asset_context_stored_filename},
        )
        _validate_vex_upload(vex_stored_filename, vex_upload.content_type)
    provider_snapshot_path = _resolve_workbench_provider_snapshot_path(
        upload.provider_snapshot_file,
        settings=settings,
    )
    attack_mapping_path = _resolve_workbench_attack_artifact_path(
        upload.attack_mapping_file,
        settings=settings,
    )
    attack_metadata_path = _resolve_workbench_attack_artifact_path(
        upload.attack_technique_metadata_file,
        settings=settings,
    )
    normalized_attack_source = _validate_attack_import_options(
        attack_source=upload.attack_source,
        attack_mapping_path=attack_mapping_path,
        attack_metadata_path=attack_metadata_path,
    )

    _validate_aggregate_upload_size(
        settings=settings,
        payloads=[
            file.content,
            asset_context_upload.content if asset_context_upload is not None else None,
            vex_upload.content if vex_upload is not None else None,
        ],
    )
    upload_bytes = file.content
    asset_context_bytes = asset_context_upload.content if asset_context_upload is not None else None
    vex_bytes = vex_upload.content if vex_upload is not None else None
    upload_sha256 = hashlib.sha256(upload_bytes).hexdigest()
    asset_context_sha256 = (
        hashlib.sha256(asset_context_bytes).hexdigest() if asset_context_bytes is not None else None
    )
    vex_sha256 = hashlib.sha256(vex_bytes).hexdigest() if vex_bytes is not None else None
    ignored_lines = _ignored_line_count(normalized_input_type, upload_bytes)
    run_repo = RunRepository(session)
    job_id = str(uuid.uuid4())
    job_history = [_job_status_entry("pending")]
    if existing_run_id is not None:
        run = run_repo.get_analysis_run(existing_run_id)
        if run is None:
            raise ImportServiceError(
                status_code=404,
                detail="Analysis run not found",
            )
        if run.status not in {AnalysisRunStatus.PENDING, AnalysisRunStatus.RUNNING}:
            return run
        existing_job = run.summary_json.get("import_job")
        if isinstance(existing_job, dict):
            job_id = str(existing_job.get("id") or job_id)
            raw_history = existing_job.get("status_history")
            if isinstance(raw_history, list) and raw_history:
                job_history = [item for item in raw_history if isinstance(item, dict)]
    else:
        run = run_repo.create_analysis_run(
            project_id=project_id,
            input_type=normalized_input_type,
            filename=stored_filename,
            status=AnalysisRunStatus.PENDING,
            summary_json={
                "import_job": _job_payload(
                    job_id=job_id,
                    status="pending",
                    status_history=job_history,
                    execution_mode=execution_mode,
                ),
                "input_upload": _upload_summary(
                    input_type=normalized_input_type,
                    original_filename=original_filename,
                    stored_filename=stored_filename,
                    content_type=file.content_type,
                    size_bytes=len(upload_bytes),
                    sha256=upload_sha256,
                    path=None,
                ),
                "asset_context_upload": _optional_upload_summary(
                    input_type="asset-context-csv",
                    original_filename=asset_context_original_filename,
                    stored_filename=asset_context_stored_filename,
                    content_type=asset_context_upload.content_type
                    if asset_context_upload is not None
                    else None,
                    size_bytes=len(asset_context_bytes)
                    if asset_context_bytes is not None
                    else None,
                    sha256=asset_context_sha256,
                    path=None,
                ),
                "vex_upload": _optional_upload_summary(
                    input_type="vex-json",
                    original_filename=vex_original_filename,
                    stored_filename=vex_stored_filename,
                    content_type=vex_upload.content_type if vex_upload is not None else None,
                    size_bytes=len(vex_bytes) if vex_bytes is not None else None,
                    sha256=vex_sha256,
                    path=None,
                ),
                "created_findings": 0,
                "updated_findings": 0,
                "ignored_lines": ignored_lines,
                "parse_errors": [],
            },
        )
    upload_path = _store_upload(
        settings,
        project_id=project_id,
        run_id=run.id,
        filename=stored_filename,
        content=upload_bytes,
    )
    asset_context_path = (
        _store_upload(
            settings,
            project_id=project_id,
            run_id=run.id,
            filename=asset_context_stored_filename or "asset_context.csv",
            content=asset_context_bytes,
        )
        if asset_context_bytes is not None
        else None
    )
    vex_path = (
        _store_upload(
            settings,
            project_id=project_id,
            run_id=run.id,
            filename=vex_stored_filename or "openvex.json",
            content=vex_bytes,
        )
        if vex_bytes is not None
        else None
    )
    upload_ref = _upload_storage_ref(
        project_id=project_id,
        run_id=run.id,
        filename=stored_filename,
    )
    asset_context_ref = (
        _upload_storage_ref(
            project_id=project_id,
            run_id=run.id,
            filename=asset_context_stored_filename or "asset_context.csv",
        )
        if asset_context_path is not None
        else None
    )
    vex_ref = (
        _upload_storage_ref(
            project_id=project_id,
            run_id=run.id,
            filename=vex_stored_filename or "openvex.json",
        )
        if vex_path is not None
        else None
    )
    run.summary_json = {
        **run.summary_json,
        "import_job": _job_payload(
            job_id=job_id,
            status="pending",
            status_history=job_history,
            execution_mode=execution_mode,
        ),
        "input_upload": {
            **run.summary_json["input_upload"],
            "path": upload_ref,
            "storage_ref": upload_ref,
        },
        "asset_context_upload": _upload_summary_with_path(
            run.summary_json.get("asset_context_upload"),
            path=asset_context_ref,
        ),
        "vex_upload": _upload_summary_with_path(
            run.summary_json.get("vex_upload"),
            path=vex_ref,
        ),
    }
    if defer_execution:
        session.commit()
        session.refresh(run)
        return run

    run.status = AnalysisRunStatus.RUNNING
    job_history = _append_job_status(job_history, "running")
    run.summary_json = {
        **run.summary_json,
        "import_job": _job_payload(
            job_id=job_id,
            status="running",
            status_history=job_history,
            execution_mode=execution_mode,
        ),
    }
    session.flush()

    try:
        occurrences = build_importer_registry().parse(
            normalized_input_type,
            upload_bytes,
            filename=stored_filename,
        )
        occurrences = [_canonicalize_occurrence_asset_context(item) for item in occurrences]
    except (ImporterParseError, ImporterValidationError) as exc:
        parse_errors = _parse_errors(
            exc, filename=stored_filename, input_type=normalized_input_type
        )
        failed_history = [*job_history, _job_status_entry("failed")]
        failed_run = run_repo.finish_analysis_run(
            run.id,
            status=AnalysisRunStatus.FAILED,
            error_message=_sanitize_parser_error_message(str(exc)),
            error_json={
                "parse_errors": parse_errors,
                "created_findings": 0,
                "updated_findings": 0,
                "ignored_lines": ignored_lines,
                "import_job": _job_payload(
                    job_id=job_id,
                    status="failed",
                    status_history=failed_history,
                    execution_mode=execution_mode,
                ),
            },
            summary_json={
                **run.summary_json,
                "import_job": _job_payload(
                    job_id=job_id,
                    status="failed",
                    status_history=failed_history,
                    execution_mode=execution_mode,
                ),
                "parse_errors": parse_errors,
                "created_findings": 0,
                "updated_findings": 0,
                "ignored_lines": ignored_lines,
            },
        )
        _record_import_audit(
            session,
            current_user=current_user,
            project_id=project_id,
            run_id=failed_run.id,
            status="failure",
            stage="parse",
            input_type=normalized_input_type,
        )
        session.commit()
        raise ImportServiceError(
            status_code=422,
            detail={
                "message": "Import parsing failed.",
                "analysis_run_id": str(failed_run.id),
                "ignored_lines": ignored_lines,
                "parse_errors": parse_errors,
            },
        ) from exc

    asset_context_summary: dict[str, Any] | None = None
    if asset_context_path is not None:
        try:
            occurrences, asset_context_summary = _apply_workbench_asset_context(
                occurrences,
                asset_context_path=asset_context_path,
            )
        except ValueError as exc:
            error_message = _sanitize_parser_error_message(str(exc))
            asset_context_error = {
                "message": error_message,
                "filename": asset_context_stored_filename,
                "stage": "asset_context_parse",
                "error_type": exc.__class__.__name__,
            }
            failed_history = [*job_history, _job_status_entry("failed")]
            failed_run = run_repo.finish_analysis_run(
                run.id,
                status=AnalysisRunStatus.FAILED,
                error_message=error_message,
                error_json={
                    "asset_context_error": asset_context_error,
                    "created_findings": 0,
                    "updated_findings": 0,
                    "ignored_lines": ignored_lines,
                    "import_job": _job_payload(
                        job_id=job_id,
                        status="failed",
                        status_history=failed_history,
                        execution_mode=execution_mode,
                    ),
                },
                summary_json={
                    **run.summary_json,
                    "import_job": _job_payload(
                        job_id=job_id,
                        status="failed",
                        status_history=failed_history,
                        execution_mode=execution_mode,
                    ),
                    "asset_context_error": asset_context_error,
                    "parse_errors": [],
                    "created_findings": 0,
                    "updated_findings": 0,
                    "ignored_lines": ignored_lines,
                },
            )
            _record_import_audit(
                session,
                current_user=current_user,
                project_id=project_id,
                run_id=failed_run.id,
                status="failure",
                stage="asset_context_parse",
                input_type=normalized_input_type,
            )
            session.commit()
            raise ImportServiceError(
                status_code=422,
                detail={
                    "message": "Asset context parsing failed.",
                    "analysis_run_id": str(failed_run.id),
                    "asset_context_error": asset_context_error,
                },
            ) from exc

    vex_summary: dict[str, Any] | None = None
    if vex_path is not None:
        try:
            occurrences, vex_summary = _apply_workbench_vex(
                occurrences,
                vex_path=vex_path,
            )
        except ValueError as exc:
            error_message = _sanitize_parser_error_message(str(exc))
            vex_error = {
                "message": error_message,
                "filename": vex_stored_filename,
                "stage": "vex_parse",
                "error_type": exc.__class__.__name__,
            }
            failed_history = [*job_history, _job_status_entry("failed")]
            failed_run = run_repo.finish_analysis_run(
                run.id,
                status=AnalysisRunStatus.FAILED,
                error_message=error_message,
                error_json={
                    "vex_error": vex_error,
                    "created_findings": 0,
                    "updated_findings": 0,
                    "ignored_lines": ignored_lines,
                    "import_job": _job_payload(
                        job_id=job_id,
                        status="failed",
                        status_history=failed_history,
                        execution_mode=execution_mode,
                    ),
                },
                summary_json={
                    **run.summary_json,
                    "import_job": _job_payload(
                        job_id=job_id,
                        status="failed",
                        status_history=failed_history,
                        execution_mode=execution_mode,
                    ),
                    "vex_error": vex_error,
                    "parse_errors": [],
                    "created_findings": 0,
                    "updated_findings": 0,
                    "ignored_lines": ignored_lines,
                },
            )
            _record_import_audit(
                session,
                current_user=current_user,
                project_id=project_id,
                run_id=failed_run.id,
                status="failure",
                stage="vex_parse",
                input_type=normalized_input_type,
            )
            session.commit()
            raise ImportServiceError(
                status_code=422,
                detail={
                    "message": "VEX parsing failed.",
                    "analysis_run_id": str(failed_run.id),
                    "vex_error": vex_error,
                },
            ) from exc

    try:
        analysis_result = AnalysisService(session, settings).analyze_import(
            input_path=upload_path,
            input_type=normalized_input_type,
            asset_context_file=asset_context_path,
            provider_snapshot_file=provider_snapshot_path,
            locked_provider_data=upload.locked_provider_data,
            attack_source=normalized_attack_source,
            attack_mapping_file=attack_mapping_path,
            attack_technique_metadata_file=attack_metadata_path,
            vex_files=[vex_path] if vex_path is not None else [],
        )
    except WorkbenchAnalysisError as exc:
        _raise_analysis_failure(
            session=session,
            run_repo=run_repo,
            run=run,
            current_user=current_user,
            project_id=project_id,
            job_id=job_id,
            job_history=job_history,
            ignored_lines=ignored_lines,
            input_type=normalized_input_type,
            exc=exc,
            execution_mode=execution_mode,
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
                job_id=job_id,
                status="succeeded",
                status_history=[*job_history, _job_status_entry("succeeded")],
                execution_mode=execution_mode,
            ),
            **analysis_result.summary_json,
            **persist_summary,
            "asset_context": asset_context_summary,
            "vex": vex_summary,
            "ignored_lines": ignored_lines,
            "input_sha256": upload_sha256,
            "parse_errors": [],
        },
    )
    _record_import_audit(
        session,
        current_user=current_user,
        project_id=project_id,
        run_id=finished_run.id,
        status="success",
        stage="succeeded",
        input_type=normalized_input_type,
    )
    session.commit()
    return finished_run

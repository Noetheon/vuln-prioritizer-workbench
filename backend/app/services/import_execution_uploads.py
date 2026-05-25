"""Upload preparation and storage stages for Workbench import execution."""

from __future__ import annotations

import hashlib
import uuid
from pathlib import Path
from typing import Any

from app.core.config import Settings
from app.models import AnalysisRun, AnalysisRunStatus
from app.repositories import RunRepository
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
from app.services.import_execution_summary import _job_payload, _job_status_entry
from app.services.import_execution_types import (
    ImportUploadContent,
    PreparedImportUpload,
    PreparedSidecarUpload,
    ProjectImportUploadRequest,
    ResolvedImportRun,
    StoredImportArtifacts,
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


def prepare_import_upload(
    upload: ProjectImportUploadRequest,
    *,
    settings: Settings,
) -> PreparedImportUpload:
    """Prepare import upload function."""
    input_type = _normalize_input_type(upload.input_type)
    _validate_input_type(input_type)
    file = upload.file
    original_filename = file.filename or "upload"
    _reject_unsafe_upload_filename(original_filename)
    stored_filename = _sanitize_filename(original_filename)
    _validate_upload_suffix(stored_filename, input_type=input_type)
    _validate_mime_hint(file.content_type, input_type=input_type)

    asset_context = _prepare_asset_context_upload(
        upload.asset_context_file,
        reserved_filename=stored_filename,
    )
    vex = _prepare_vex_upload(
        upload.vex_file,
        reserved_filenames={stored_filename, asset_context.stored_filename},
    )
    _validate_aggregate_upload_size(
        settings=settings,
        payloads=[file.content, asset_context.content, vex.content],
    )

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
    attack_source = _validate_attack_import_options(
        attack_source=upload.attack_source,
        attack_mapping_path=attack_mapping_path,
        attack_metadata_path=attack_metadata_path,
    )

    return PreparedImportUpload(
        input_type=input_type,
        file=file,
        original_filename=original_filename,
        stored_filename=stored_filename,
        upload_bytes=file.content,
        upload_sha256=hashlib.sha256(file.content).hexdigest(),
        ignored_lines=_ignored_line_count(input_type, file.content),
        asset_context=asset_context,
        vex=vex,
        provider_snapshot_path=provider_snapshot_path,
        attack_mapping_path=attack_mapping_path,
        attack_metadata_path=attack_metadata_path,
        attack_source=attack_source,
        locked_provider_data=upload.locked_provider_data,
    )


def resolve_import_run(
    *,
    run_repo: RunRepository,
    project_id: uuid.UUID,
    prepared: PreparedImportUpload,
    existing_run_id: uuid.UUID | None,
    execution_mode: str,
) -> ResolvedImportRun:
    """Resolve import run function."""
    if existing_run_id is not None:
        run = run_repo.get_analysis_run(existing_run_id)
        if run is None:
            raise ImportServiceError(
                status_code=404,
                detail="Analysis run not found",
            )
        job_id, job_history = _extract_existing_job_state(run)
        return ResolvedImportRun(
            run=run,
            job_id=job_id,
            job_history=job_history,
            already_finished=run.status
            not in {AnalysisRunStatus.PENDING, AnalysisRunStatus.RUNNING},
        )

    job_id = str(uuid.uuid4())
    job_history = [_job_status_entry("pending")]
    run = run_repo.create_analysis_run(
        project_id=project_id,
        input_type=prepared.input_type,
        filename=prepared.stored_filename,
        status=AnalysisRunStatus.PENDING,
        summary_json=_initial_run_summary(
            prepared,
            job_id=job_id,
            job_history=job_history,
            execution_mode=execution_mode,
        ),
    )
    return ResolvedImportRun(run=run, job_id=job_id, job_history=job_history)


def store_prepared_uploads(
    settings: Settings,
    *,
    project_id: uuid.UUID,
    run_id: uuid.UUID,
    prepared: PreparedImportUpload,
) -> StoredImportArtifacts:
    """Store prepared uploads function."""
    upload_path = _store_upload(
        settings,
        project_id=project_id,
        run_id=run_id,
        filename=prepared.stored_filename,
        content=prepared.upload_bytes,
    )
    upload_ref = _upload_storage_ref(
        project_id=project_id,
        run_id=run_id,
        filename=prepared.stored_filename,
    )
    asset_context_path, asset_context_ref = _store_sidecar_upload(
        settings,
        project_id=project_id,
        run_id=run_id,
        sidecar=prepared.asset_context,
    )
    vex_path, vex_ref = _store_sidecar_upload(
        settings,
        project_id=project_id,
        run_id=run_id,
        sidecar=prepared.vex,
    )
    return StoredImportArtifacts(
        upload_path=upload_path,
        asset_context_path=asset_context_path,
        vex_path=vex_path,
        upload_ref=upload_ref,
        asset_context_ref=asset_context_ref,
        vex_ref=vex_ref,
    )


def apply_stored_upload_summaries(
    run: AnalysisRun,
    *,
    resolved_run: ResolvedImportRun,
    artifacts: StoredImportArtifacts,
    execution_mode: str,
) -> None:
    """Apply stored upload summaries function."""
    run.summary_json = {
        **run.summary_json,
        "import_job": _job_payload(
            job_id=resolved_run.job_id,
            status="pending",
            status_history=resolved_run.job_history,
            execution_mode=execution_mode,
        ),
        "input_upload": {
            **run.summary_json["input_upload"],
            "path": artifacts.upload_ref,
            "storage_ref": artifacts.upload_ref,
        },
        "asset_context_upload": _upload_summary_with_path(
            run.summary_json.get("asset_context_upload"),
            path=artifacts.asset_context_ref,
        ),
        "vex_upload": _upload_summary_with_path(
            run.summary_json.get("vex_upload"),
            path=artifacts.vex_ref,
        ),
    }


def mark_import_run_running(
    run: AnalysisRun,
    *,
    job_id: str,
    job_history: list[dict[str, str]],
    execution_mode: str,
) -> list[dict[str, str]]:
    """Mark import run running function."""
    run.status = AnalysisRunStatus.RUNNING
    running_history = _append_job_status(job_history, "running")
    run.summary_json = {
        **run.summary_json,
        "import_job": _job_payload(
            job_id=job_id,
            status="running",
            status_history=running_history,
            execution_mode=execution_mode,
        ),
    }
    return running_history


def _append_job_status(
    status_history: list[dict[str, str]],
    status: str,
) -> list[dict[str, str]]:
    """Append job status function."""
    if status_history and status_history[-1].get("status") == status:
        return status_history
    return [*status_history, _job_status_entry(status)]


def _prepare_asset_context_upload(
    upload: ImportUploadContent | None,
    *,
    reserved_filename: str,
) -> PreparedSidecarUpload:
    """Prepare asset context upload function."""
    payload = _present_optional_upload(upload)
    if payload is None or payload.filename is None:
        return _empty_sidecar("asset-context-csv", default_filename="asset_context.csv")

    _reject_unsafe_upload_filename(payload.filename)
    stored_filename = _sanitize_context_filename(
        payload.filename,
        reserved_filename=reserved_filename,
    )
    _validate_asset_context_upload(stored_filename, payload.content_type)
    return _prepared_sidecar(
        payload,
        stored_filename=stored_filename,
        summary_input_type="asset-context-csv",
        default_filename="asset_context.csv",
    )


def _prepare_vex_upload(
    upload: ImportUploadContent | None,
    *,
    reserved_filenames: set[str | None],
) -> PreparedSidecarUpload:
    """Prepare vex upload function."""
    payload = _present_optional_upload(upload)
    if payload is None or payload.filename is None:
        return _empty_sidecar("vex-json", default_filename="openvex.json")

    _reject_unsafe_upload_filename(payload.filename)
    stored_filename = _sanitize_vex_filename(
        payload.filename,
        reserved_filenames=reserved_filenames,
    )
    _validate_vex_upload(stored_filename, payload.content_type)
    return _prepared_sidecar(
        payload,
        stored_filename=stored_filename,
        summary_input_type="vex-json",
        default_filename="openvex.json",
    )


def _present_optional_upload(upload: ImportUploadContent | None) -> ImportUploadContent | None:
    """Present optional upload function."""
    if upload is None or not _has_optional_upload(upload.filename):
        return None
    return upload


def _empty_sidecar(summary_input_type: str, *, default_filename: str) -> PreparedSidecarUpload:
    """Empty sidecar function."""
    return PreparedSidecarUpload(
        payload=None,
        original_filename=None,
        stored_filename=None,
        content=None,
        sha256=None,
        summary_input_type=summary_input_type,
        default_filename=default_filename,
    )


def _prepared_sidecar(
    payload: ImportUploadContent,
    *,
    stored_filename: str,
    summary_input_type: str,
    default_filename: str,
) -> PreparedSidecarUpload:
    """Prepared sidecar function."""
    return PreparedSidecarUpload(
        payload=payload,
        original_filename=payload.filename,
        stored_filename=stored_filename,
        content=payload.content,
        sha256=hashlib.sha256(payload.content).hexdigest(),
        summary_input_type=summary_input_type,
        default_filename=default_filename,
    )


def _optional_summary(sidecar: PreparedSidecarUpload) -> dict[str, Any] | None:
    """Optional summary function."""
    return _optional_upload_summary(
        input_type=sidecar.summary_input_type,
        original_filename=sidecar.original_filename,
        stored_filename=sidecar.stored_filename,
        content_type=sidecar.payload.content_type if sidecar.payload is not None else None,
        size_bytes=len(sidecar.content) if sidecar.content is not None else None,
        sha256=sidecar.sha256,
        path=None,
    )


def _initial_run_summary(
    prepared: PreparedImportUpload,
    *,
    job_id: str,
    job_history: list[dict[str, str]],
    execution_mode: str,
) -> dict[str, Any]:
    """Initial run summary function."""
    return {
        "import_job": _job_payload(
            job_id=job_id,
            status="pending",
            status_history=job_history,
            execution_mode=execution_mode,
        ),
        "input_upload": _upload_summary(
            input_type=prepared.input_type,
            original_filename=prepared.original_filename,
            stored_filename=prepared.stored_filename,
            content_type=prepared.file.content_type,
            size_bytes=len(prepared.upload_bytes),
            sha256=prepared.upload_sha256,
            path=None,
        ),
        "asset_context_upload": _optional_summary(prepared.asset_context),
        "vex_upload": _optional_summary(prepared.vex),
        "created_findings": 0,
        "updated_findings": 0,
        "ignored_lines": prepared.ignored_lines,
        "parse_errors": [],
    }


def _extract_existing_job_state(run: AnalysisRun) -> tuple[str, list[dict[str, str]]]:
    """Extract existing job state function."""
    job_id = str(uuid.uuid4())
    job_history = [_job_status_entry("pending")]
    existing_job = run.summary_json.get("import_job")
    if not isinstance(existing_job, dict):
        return job_id, job_history

    job_id = str(existing_job.get("id") or job_id)
    raw_history = existing_job.get("status_history")
    if isinstance(raw_history, list) and raw_history:
        job_history = [item for item in raw_history if isinstance(item, dict)]
    return job_id, job_history


def _store_sidecar_upload(
    settings: Settings,
    *,
    project_id: uuid.UUID,
    run_id: uuid.UUID,
    sidecar: PreparedSidecarUpload,
) -> tuple[Path | None, str | None]:
    """Store sidecar upload function."""
    if sidecar.content is None:
        return None, None
    filename = sidecar.stored_filename or sidecar.default_filename
    path = _store_upload(
        settings,
        project_id=project_id,
        run_id=run_id,
        filename=filename,
        content=sidecar.content,
    )
    ref = _upload_storage_ref(project_id=project_id, run_id=run_id, filename=filename)
    return path, ref

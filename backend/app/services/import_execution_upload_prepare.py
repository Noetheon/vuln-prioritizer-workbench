"""Upload validation and preparation for Workbench imports."""

from __future__ import annotations

import hashlib
from typing import Any

from app.core.config import Settings
from app.services.import_artifacts import (
    resolve_workbench_attack_artifact_path as _resolve_workbench_attack_artifact_path,
)
from app.services.import_artifacts import (
    resolve_workbench_provider_snapshot_path as _resolve_workbench_provider_snapshot_path,
)
from app.services.import_artifacts import (
    validate_attack_import_options as _validate_attack_import_options,
)
from app.services.import_execution_types import (
    ImportUploadContent,
    PreparedImportUpload,
    PreparedSidecarUpload,
    ProjectImportUploadRequest,
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
    upload_summary as _upload_summary,
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
    """Validate and normalize a Workbench import upload request."""
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


def initial_upload_summary(prepared: PreparedImportUpload) -> dict[str, Any]:
    """Return the initial upload metadata stored on an analysis run."""
    return {
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
        "ignored_lines": prepared.ignored_lines,
    }


def _prepare_asset_context_upload(
    upload: ImportUploadContent | None,
    *,
    reserved_filename: str,
) -> PreparedSidecarUpload:
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
    if upload is None or not _has_optional_upload(upload.filename):
        return None
    return upload


def _empty_sidecar(summary_input_type: str, *, default_filename: str) -> PreparedSidecarUpload:
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
    return _optional_upload_summary(
        input_type=sidecar.summary_input_type,
        original_filename=sidecar.original_filename,
        stored_filename=sidecar.stored_filename,
        content_type=sidecar.payload.content_type if sidecar.payload is not None else None,
        size_bytes=len(sidecar.content) if sidecar.content is not None else None,
        sha256=sidecar.sha256,
        path=None,
    )

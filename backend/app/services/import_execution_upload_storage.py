"""Persist prepared Workbench import uploads to local storage."""

from __future__ import annotations

import uuid
from pathlib import Path

from app.core.config import Settings
from app.services.import_execution_types import (
    PreparedImportUpload,
    PreparedSidecarUpload,
    StoredImportArtifacts,
)
from app.services.import_uploads import (
    store_upload as _store_upload,
)
from app.services.import_uploads import (
    upload_storage_ref as _upload_storage_ref,
)


def store_prepared_uploads(
    settings: Settings,
    *,
    project_id: uuid.UUID,
    run_id: uuid.UUID,
    prepared: PreparedImportUpload,
) -> StoredImportArtifacts:
    """Persist the main upload and optional sidecar uploads."""
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


def _store_sidecar_upload(
    settings: Settings,
    *,
    project_id: uuid.UUID,
    run_id: uuid.UUID,
    sidecar: PreparedSidecarUpload,
) -> tuple[Path | None, str | None]:
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

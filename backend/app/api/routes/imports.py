"""Template import upload API routes."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile

from app.api.deps import ScopedImportUser, SessionDep
from app.api.routes.workbench_access import require_visible_project
from app.core.app_state import workbench_settings
from app.core.config import Settings
from app.models import AnalysisRun, AnalysisRunPublic
from app.services.import_errors import ImportServiceError
from app.services.import_execution import (
    ImportUploadContent,
    ProjectImportUploadRequest,
    execute_project_import_upload,
)
from app.services.import_uploads import has_optional_upload, read_bounded_upload

router = APIRouter(tags=["imports"])


async def _read_optional_upload(
    upload: UploadFile | None,
    *,
    settings: Settings,
    remaining_bytes: int,
) -> ImportUploadContent | None:
    if upload is None or not has_optional_upload(upload.filename):
        return None
    content = await read_bounded_upload(
        upload,
        settings=settings,
        max_bytes=remaining_bytes,
    )
    return ImportUploadContent(
        filename=upload.filename,
        content_type=upload.content_type,
        content=content,
    )


async def _build_project_import_upload_request(
    *,
    settings: Settings,
    input_type: str,
    file: UploadFile,
    asset_context_file: UploadFile | None,
    vex_file: UploadFile | None,
    provider_snapshot_file: str | None,
    locked_provider_data: bool,
    attack_source: str,
    attack_mapping_file: str | None,
    attack_technique_metadata_file: str | None,
) -> ProjectImportUploadRequest:
    primary_content = await read_bounded_upload(file, settings=settings)
    remaining_bytes = settings.max_upload_bytes - len(primary_content)
    asset_context_content = await _read_optional_upload(
        asset_context_file,
        settings=settings,
        remaining_bytes=remaining_bytes,
    )
    if asset_context_content is not None:
        remaining_bytes -= len(asset_context_content.content)
    vex_content = await _read_optional_upload(
        vex_file,
        settings=settings,
        remaining_bytes=remaining_bytes,
    )
    return ProjectImportUploadRequest(
        input_type=input_type,
        file=ImportUploadContent(
            filename=file.filename,
            content_type=file.content_type,
            content=primary_content,
        ),
        asset_context_file=asset_context_content,
        vex_file=vex_content,
        provider_snapshot_file=provider_snapshot_file,
        locked_provider_data=locked_provider_data,
        attack_source=attack_source,
        attack_mapping_file=attack_mapping_file,
        attack_technique_metadata_file=attack_technique_metadata_file,
    )


@router.post("/projects/{project_id}/imports", response_model=AnalysisRunPublic)
async def import_project_upload(
    project_id: uuid.UUID,
    request: Request,
    session: SessionDep,
    current_user: ScopedImportUser,
    input_type: str = Form(...),
    file: UploadFile = File(...),
    asset_context_file: UploadFile | None = File(None),
    vex_file: UploadFile | None = File(None),
    provider_snapshot_file: str | None = Form(None),
    locked_provider_data: bool = Form(False),
    attack_source: str = Form("none"),
    attack_mapping_file: str | None = Form(None),
    attack_technique_metadata_file: str | None = Form(None),
) -> AnalysisRun:
    """Accept one upload request and delegate import execution to the service layer."""
    require_visible_project(session, current_user, project_id)
    settings = workbench_settings(request)
    try:
        upload = await _build_project_import_upload_request(
            settings=settings,
            input_type=input_type,
            file=file,
            asset_context_file=asset_context_file,
            vex_file=vex_file,
            provider_snapshot_file=provider_snapshot_file,
            locked_provider_data=locked_provider_data,
            attack_source=attack_source,
            attack_mapping_file=attack_mapping_file,
            attack_technique_metadata_file=attack_technique_metadata_file,
        )
        return await execute_project_import_upload(
            project_id=project_id,
            session=session,
            current_user=current_user,
            settings=settings,
            upload=upload,
        )
    except ImportServiceError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc

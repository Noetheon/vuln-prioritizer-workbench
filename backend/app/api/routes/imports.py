"""Workbench import upload API routes."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, BackgroundTasks, File, Form, HTTPException, Request, UploadFile

from app.api.deps import ScopedImportUser, SessionDep
from app.api.routes.import_uploads import build_project_import_upload_request
from app.api.routes.workbench_access import require_visible_project
from app.core.app_state import workbench_engine, workbench_settings
from app.models import AnalysisRun, AnalysisRunPublic
from app.models.api_tokens import capture_api_token_context
from app.services.import_background import execute_project_import_upload_background
from app.services.import_errors import ImportServiceError
from app.services.import_execution import execute_project_import_upload

router = APIRouter(tags=["imports"])


@router.post("/projects/{project_id}/imports", response_model=AnalysisRunPublic)
async def import_project_upload(
    project_id: uuid.UUID,
    request: Request,
    session: SessionDep,
    current_user: ScopedImportUser,
    background_tasks: BackgroundTasks,
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
    api_token_context = capture_api_token_context(current_user)
    try:
        upload = await build_project_import_upload_request(
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
        if settings.ENVIRONMENT != "local":
            run = await execute_project_import_upload(
                project_id=project_id,
                session=session,
                current_user=current_user,
                settings=settings,
                upload=upload,
                defer_execution=True,
                execution_mode="background",
            )
            background_tasks.add_task(
                execute_project_import_upload_background,
                workbench_engine(request),
                settings,
                project_id,
                current_user.id,
                upload,
                run.id,
                api_token_context,
            )
            return run
        return await execute_project_import_upload(
            project_id=project_id,
            session=session,
            current_user=current_user,
            settings=settings,
            upload=upload,
            execution_mode="request",
        )
    except ImportServiceError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc

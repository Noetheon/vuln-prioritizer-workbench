"""Template import upload API routes."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, File, Form, Request, UploadFile

from app.api.deps import ScopedImportUser, SessionDep
from app.models import AnalysisRun, AnalysisRunPublic
from app.services.import_execution import execute_project_import_upload

router = APIRouter(tags=["imports"])


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
    return await execute_project_import_upload(
        project_id=project_id,
        request=request,
        session=session,
        current_user=current_user,
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

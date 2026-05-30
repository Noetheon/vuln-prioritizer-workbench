"""Workbench import upload API routes."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile

from app.api.deps import LocalActor, SessionDep
from app.api.routes.import_uploads import build_project_import_upload_request
from app.api.routes.workbench_access import require_project
from app.core.app_state import workbench_settings
from app.models import AnalysisRunPublic, WorkflowRunKind
from app.repositories import WorkflowRepository
from app.services.import_errors import ImportServiceError
from app.services.import_execution import execute_project_import_upload
from app.services.import_execution_types import ProjectImportUploadRequest
from app.services.run_workflow_projection import analysis_run_public
from app.services.workflows import latest_analysis_workflow_public

router = APIRouter(tags=["imports"])


@router.post("/projects/{project_id}/imports", response_model=AnalysisRunPublic)
async def import_project_upload(
    project_id: uuid.UUID,
    request: Request,
    session: SessionDep,
    local_actor: LocalActor,
    input_type: str = Form(...),
    file: UploadFile = File(...),
    asset_context_file: UploadFile | None = File(None),
    vex_file: UploadFile | None = File(None),
    provider_snapshot_file: str | None = Form(None),
    locked_provider_data: bool = Form(False),
    attack_source: str = Form("none"),
    attack_mapping_file: str | None = Form(None),
    attack_technique_metadata_file: str | None = Form(None),
) -> AnalysisRunPublic:
    """Accept one upload request and queue a worker-first import workflow."""
    require_project(session, project_id)
    settings = workbench_settings(request)
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
        run = await execute_project_import_upload(
            project_id=project_id,
            session=session,
            local_actor=local_actor,
            settings=settings,
            upload=upload,
            defer_execution=True,
            execution_mode="worker",
        )
        workflow = WorkflowRepository(session).get_latest_analysis_workflow(
            analysis_run_id=run.id,
            kind=WorkflowRunKind.IMPORT,
        )
        if workflow is None:
            raise HTTPException(status_code=500, detail="Import workflow could not be queued.")
        WorkflowRepository(session).set_workflow_payload(
            workflow.id,
            payload_json=_import_queue_payload(upload, run_id=run.id),
            queue_name="default",
            max_retries=2,
        )
        session.commit()
        session.refresh(run)
        return analysis_run_public(
            run,
            session=session,
            workflow=latest_analysis_workflow_public(
                session,
                analysis_run_id=run.id,
                kind=WorkflowRunKind.IMPORT,
            ),
        )
    except ImportServiceError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc


def _import_queue_payload(
    upload: ProjectImportUploadRequest,
    *,
    run_id: uuid.UUID,
) -> dict[str, object]:
    return {
        "run_id": str(run_id),
        "input_type": upload.input_type,
        "provider_snapshot_file": upload.provider_snapshot_file,
        "locked_provider_data": upload.locked_provider_data,
        "attack_source": upload.attack_source,
        "attack_mapping_file": upload.attack_mapping_file,
        "attack_technique_metadata_file": upload.attack_technique_metadata_file,
    }

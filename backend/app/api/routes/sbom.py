"""SBOM assessment replay and verified source-evidence download endpoints."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict

from app.api.deps import LocalActor, SessionDep
from app.api.routes.workbench_access import require_project
from app.core.app_state import workbench_settings
from app.models import AnalysisRunPublic, WorkflowRunKind
from app.repositories import RunRepository
from app.services.audit import record_audit_event
from app.services.import_errors import ImportServiceError
from app.services.run_workflow_projection import analysis_run_public
from app.services.sbom_rescans import queue_sbom_rescan, sbom_evidence_zip
from app.services.workflows import latest_analysis_workflow_public

router = APIRouter(tags=["imports"])


class SbomRescanCreate(BaseModel):
    """Choose whether the scanner may update its local vulnerability database."""

    model_config = ConfigDict(extra="forbid")
    sbom_db_update: bool = True


@router.post(
    "/runs/{run_id}/sbom-rescans",
    response_model=AnalysisRunPublic,
    status_code=202,
    operation_id="imports-rescan_sbom",
)
async def rescan_sbom(
    run_id: uuid.UUID,
    request: Request,
    session: SessionDep,
    local_actor: LocalActor,
    body: SbomRescanCreate | None = None,
) -> AnalysisRunPublic:
    """Queue another vulnerability assessment of the recorded SBOM bytes."""
    run = RunRepository(session).get_analysis_run(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Analysis run not found")
    require_project(session, run.project_id)
    try:
        queued = await queue_sbom_rescan(
            session=session,
            settings=workbench_settings(request),
            local_actor=local_actor,
            run=run,
            sbom_db_update=(body or SbomRescanCreate()).sbom_db_update,
        )
    except ImportServiceError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc
    return analysis_run_public(
        queued,
        session=session,
        workflow=latest_analysis_workflow_public(
            session, analysis_run_id=queued.id, kind=WorkflowRunKind.IMPORT
        ),
    )


@router.get(
    "/runs/{run_id}/sbom-evidence",
    operation_id="imports-download_sbom_evidence",
    response_class=Response,
    responses={
        200: {"content": {"application/zip": {"schema": {"type": "string", "format": "binary"}}}}
    },
)
def download_sbom_evidence(
    run_id: uuid.UUID,
    request: Request,
    session: SessionDep,
    local_actor: LocalActor,
) -> Response:
    """Download the source SBOM, scanner report, assessment, and their checksums."""
    run = RunRepository(session).get_analysis_run(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Analysis run not found")
    require_project(session, run.project_id)
    try:
        content = sbom_evidence_zip(session=session, settings=workbench_settings(request), run=run)
    except ImportServiceError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc
    record_audit_event(
        session,
        action="sbom.evidence_download",
        resource_type="analysis_run",
        resource_id=run.id,
        actor=local_actor,
        project_id=run.project_id,
    )
    session.commit()
    return Response(
        content=content,
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="sbom-evidence-{run.id}.zip"',
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )

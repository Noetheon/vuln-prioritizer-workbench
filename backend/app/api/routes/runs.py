"""Analysis run API routes for the Workbench domain."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, HTTPException, Query

from app.api.deps import LocalActor, SessionDep
from app.api.routes.workbench_access import require_project
from app.models import (
    AnalysisRunPublic,
    AnalysisRunsPublic,
    AnalysisRunSummaryPublic,
    AnalysisRunWorkflowMetadataPublic,
    WorkflowRunKind,
)
from app.repositories import RunRepository
from app.services.run_workflow_projection import (
    analysis_run_public,
    analysis_run_summary_public,
    analysis_run_workflow_metadata_public,
)
from app.services.workflows import latest_analysis_workflow_public

router = APIRouter(tags=["runs"])


@router.get(
    "/projects/{project_id}/runs",
    response_model=AnalysisRunsPublic,
    operation_id="runs-read_project_runs_without_trailing_slash",
    include_in_schema=False,
)
@router.get(
    "/projects/{project_id}/runs/",
    response_model=AnalysisRunsPublic,
    operation_id="runs-read_project_runs",
)
def read_project_runs(
    project_id: uuid.UUID,
    session: SessionDep,
    local_actor: LocalActor,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> AnalysisRunsPublic:
    """List analysis runs for a visible project."""
    require_project(session, project_id)
    runs, count = RunRepository(session).list_analysis_runs_page(
        project_id,
        limit=limit,
        offset=offset,
    )
    return AnalysisRunsPublic(
        data=[
            analysis_run_public(
                run,
                workflow=latest_analysis_workflow_public(
                    session,
                    analysis_run_id=run.id,
                    kind=WorkflowRunKind.IMPORT,
                ),
            )
            for run in runs
        ],
        count=count,
    )


@router.get("/runs/{run_id}", response_model=AnalysisRunPublic)
def read_run(
    run_id: uuid.UUID,
    session: SessionDep,
    local_actor: LocalActor,
) -> AnalysisRunPublic:
    """Read one analysis run if its project is visible."""
    run = RunRepository(session).get_analysis_run(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Analysis run not found")
    require_project(session, run.project_id)
    return analysis_run_public(
        run,
        workflow=latest_analysis_workflow_public(
            session,
            analysis_run_id=run.id,
            kind=WorkflowRunKind.IMPORT,
        ),
    )


@router.get("/runs/{run_id}/summary", response_model=AnalysisRunSummaryPublic)
def read_run_summary(
    run_id: uuid.UUID,
    session: SessionDep,
    local_actor: LocalActor,
) -> AnalysisRunSummaryPublic:
    """Read a UI-stable summary for one visible analysis run."""
    run = RunRepository(session).get_analysis_run(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Analysis run not found")
    require_project(session, run.project_id)
    return analysis_run_summary_public(
        run,
        workflow=latest_analysis_workflow_public(
            session,
            analysis_run_id=run.id,
            kind=WorkflowRunKind.IMPORT,
        ),
    )


@router.get(
    "/runs/{run_id}/workflow-metadata",
    response_model=AnalysisRunWorkflowMetadataPublic,
)
def read_run_workflow_metadata(
    run_id: uuid.UUID,
    session: SessionDep,
    local_actor: LocalActor,
) -> AnalysisRunWorkflowMetadataPublic:
    """Read redacted workflow metadata diagnostics for one visible analysis run."""
    run = RunRepository(session).get_analysis_run(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Analysis run not found")
    require_project(session, run.project_id)
    return analysis_run_workflow_metadata_public(run)

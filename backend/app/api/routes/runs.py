"""Analysis run API routes for the Workbench domain."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, HTTPException, Query

from app.api.deps import LocalActor, SessionDep
from app.api.routes.workbench_access import require_project
from app.models import (
    PROJECT_STATE_INPUT_TYPE,
    AnalysisRunPublic,
    AnalysisRunsPublic,
    AnalysisRunSummaryPublic,
    WorkflowRunKind,
)
from app.repositories import RunRepository
from app.services.project_state import (
    current_project_state,
    is_project_state_run,
    recorded_state_fingerprint,
)
from app.services.run_workflow_projection import (
    analysis_run_public,
    analysis_run_summary_public,
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
    include_state_snapshots: bool = Query(
        default=False,
        description="Also list recorded project states that reports were generated from.",
    ),
) -> AnalysisRunsPublic:
    """List analysis runs for a visible project."""
    require_project(session, project_id)
    runs, count = RunRepository(session).list_analysis_runs_page(
        project_id,
        limit=limit,
        offset=offset,
        include_state_snapshots=include_state_snapshots,
    )
    data = [
        analysis_run_public(
            run,
            session=session,
            workflow=latest_analysis_workflow_public(
                session,
                analysis_run_id=run.id,
                kind=WorkflowRunKind.IMPORT,
            ),
        )
        for run in runs
    ]
    if any(is_project_state_run(run) for run in runs):
        fingerprint = current_project_state(session, project_id).fingerprint
        data = [
            item.model_copy(
                update={"project_state_current": recorded_state_fingerprint(item) == fingerprint}
            )
            if item.input_type == PROJECT_STATE_INPUT_TYPE
            else item
            for item in data
        ]
    return AnalysisRunsPublic(data=data, count=count)


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
        session=session,
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
        session=session,
        workflow=latest_analysis_workflow_public(
            session,
            analysis_run_id=run.id,
            kind=WorkflowRunKind.IMPORT,
        ),
    )

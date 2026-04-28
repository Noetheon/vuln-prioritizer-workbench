"""Analysis run API routes for the Workbench domain."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, HTTPException

from app.api.deps import CurrentUser, SessionDep
from app.api.routes.workbench_access import require_visible_project
from app.models import AnalysisRun, AnalysisRunPublic, AnalysisRunsPublic
from app.repositories import RunRepository

router = APIRouter(tags=["runs"])


@router.get("/projects/{project_id}/runs/", response_model=AnalysisRunsPublic)
def read_project_runs(
    project_id: uuid.UUID,
    session: SessionDep,
    current_user: CurrentUser,
) -> AnalysisRunsPublic:
    """List analysis runs for a visible project."""
    require_visible_project(session, current_user, project_id)
    runs = RunRepository(session).list_analysis_runs(project_id)
    return AnalysisRunsPublic(
        data=[AnalysisRunPublic.model_validate(run) for run in runs],
        count=len(runs),
    )


@router.get("/runs/{run_id}", response_model=AnalysisRunPublic)
def read_run(run_id: uuid.UUID, session: SessionDep, current_user: CurrentUser) -> AnalysisRun:
    """Read one analysis run if its project is visible."""
    run = RunRepository(session).get_analysis_run(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Analysis run not found")
    require_visible_project(session, current_user, run.project_id)
    return run

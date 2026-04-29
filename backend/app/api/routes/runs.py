"""Analysis run API routes for the Workbench domain."""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, HTTPException

from app.api.deps import CurrentUser, SessionDep
from app.api.routes.workbench_access import require_visible_project
from app.models import (
    AnalysisRun,
    AnalysisRunPublic,
    AnalysisRunsPublic,
    AnalysisRunSummaryPublic,
    ImportParseErrorPublic,
)
from app.repositories import RunRepository

router = APIRouter(tags=["runs"])


@router.get(
    "/projects/{project_id}/runs",
    response_model=AnalysisRunsPublic,
    operation_id="runs-read_project_runs_without_trailing_slash",
)
@router.get(
    "/projects/{project_id}/runs/",
    response_model=AnalysisRunsPublic,
    operation_id="runs-read_project_runs",
)
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


@router.get("/runs/{run_id}/summary", response_model=AnalysisRunSummaryPublic)
def read_run_summary(
    run_id: uuid.UUID,
    session: SessionDep,
    current_user: CurrentUser,
) -> AnalysisRunSummaryPublic:
    """Read a UI-stable summary for one visible analysis run."""
    run = RunRepository(session).get_analysis_run(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Analysis run not found")
    require_visible_project(session, current_user, run.project_id)
    return _analysis_run_summary(run)


def _analysis_run_summary(run: AnalysisRun) -> AnalysisRunSummaryPublic:
    summary_json = dict(run.summary_json or {})
    error_json = dict(run.error_json or {})
    dedup_summary = _dict_value(summary_json.get("dedup_summary"))
    parse_errors = _parse_errors(summary_json, error_json)
    return AnalysisRunSummaryPublic(
        id=run.id,
        project_id=run.project_id,
        input_type=run.input_type,
        filename=run.filename,
        status=run.status,
        started_at=run.started_at,
        finished_at=run.finished_at,
        created_findings=_int_value(
            summary_json.get("created_findings", dedup_summary.get("created_findings"))
        ),
        updated_findings=_int_value(
            summary_json.get(
                "updated_findings",
                dedup_summary.get("updated_findings", dedup_summary.get("reused_findings")),
            )
        ),
        ignored_lines=_int_value(summary_json.get("ignored_lines")),
        occurrence_count=_int_value(summary_json.get("occurrence_count")),
        finding_count=_int_value(summary_json.get("finding_count")),
        parse_errors=[ImportParseErrorPublic.model_validate(item) for item in parse_errors],
        import_job=_dict_value(summary_json.get("import_job") or error_json.get("import_job")),
        input_upload=_dict_value(summary_json.get("input_upload")),
        dedup_summary=dedup_summary,
        summary_json=summary_json,
        error_json=error_json,
    )


def _parse_errors(
    summary_json: dict[str, Any],
    error_json: dict[str, Any],
) -> list[dict[str, Any]]:
    errors = summary_json.get("parse_errors") or error_json.get("parse_errors") or []
    if not isinstance(errors, list):
        return []
    return [item for item in errors if isinstance(item, dict)]


def _dict_value(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def _int_value(value: Any) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str) and value.isdecimal():
        return int(value)
    return 0

"""Analysis run API routes for the Workbench domain."""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, HTTPException

from app.api.deps import ScopedReadUser, SessionDep
from app.api.errors import redact_public_payload
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
    current_user: ScopedReadUser,
) -> AnalysisRunsPublic:
    """List analysis runs for a visible project."""
    require_visible_project(session, current_user, project_id)
    runs = RunRepository(session).list_analysis_runs(project_id)
    return AnalysisRunsPublic(
        data=[_analysis_run_public(run) for run in runs],
        count=len(runs),
    )


@router.get("/runs/{run_id}", response_model=AnalysisRunPublic)
def read_run(
    run_id: uuid.UUID,
    session: SessionDep,
    current_user: ScopedReadUser,
) -> AnalysisRunPublic:
    """Read one analysis run if its project is visible."""
    run = RunRepository(session).get_analysis_run(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Analysis run not found")
    require_visible_project(session, current_user, run.project_id)
    return _analysis_run_public(run)


@router.get("/runs/{run_id}/summary", response_model=AnalysisRunSummaryPublic)
def read_run_summary(
    run_id: uuid.UUID,
    session: SessionDep,
    current_user: ScopedReadUser,
) -> AnalysisRunSummaryPublic:
    """Read a UI-stable summary for one visible analysis run."""
    run = RunRepository(session).get_analysis_run(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Analysis run not found")
    require_visible_project(session, current_user, run.project_id)
    return _analysis_run_summary(run)


def _analysis_run_summary(run: AnalysisRun) -> AnalysisRunSummaryPublic:
    summary_json = _dict_value(redact_public_payload(run.summary_json or {}))
    error_json = _dict_value(redact_public_payload(run.error_json or {}))
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
        counts_by_priority=_priority_counts(summary_json.get("counts_by_priority")),
        kev_hits=_int_value(summary_json.get("kev_hits")),
        provider_snapshot_id=run.provider_snapshot_id,
        provider_degraded=bool(summary_json.get("provider_degraded", False)),
        parse_errors=[ImportParseErrorPublic.model_validate(item) for item in parse_errors],
        import_job=_dict_value(summary_json.get("import_job") or error_json.get("import_job")),
        input_upload=_dict_value(summary_json.get("input_upload")),
        dedup_summary=dedup_summary,
        analysis_decision_scope=_str_value(summary_json.get("analysis_decision_scope")),
        persistence_scope=_str_value(summary_json.get("persistence_scope")),
        summary_json=summary_json,
        error_json=error_json,
    )


def _analysis_run_public(run: AnalysisRun) -> AnalysisRunPublic:
    public = AnalysisRunPublic.model_validate(run)
    return public.model_copy(
        update={
            "summary_json": _dict_value(redact_public_payload(run.summary_json or {})),
            "error_json": _dict_value(redact_public_payload(run.error_json or {})),
            "error_message": redact_public_payload(run.error_message),
        }
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


def _str_value(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _priority_counts(value: Any) -> dict[str, int]:
    raw = _dict_value(value)
    return {key: _int_value(raw.get(key)) for key in ("Critical", "High", "Medium", "Low")}


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

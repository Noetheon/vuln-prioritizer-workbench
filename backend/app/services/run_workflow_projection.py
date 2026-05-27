"""Public projections for versioned run workflow metadata."""

from __future__ import annotations

from typing import Any

from app.models import (
    AnalysisRun,
    AnalysisRunPublic,
    AnalysisRunSummaryPublic,
    AnalysisRunWorkflowMetadataPublic,
    ImportParseErrorPublic,
)
from app.services.run_workflow_metadata import (
    public_workflow_fields,
    redact_public_payload,
    redacted_workflow_error_or_none,
    redacted_workflow_error_payload,
    redacted_workflow_summary,
    redacted_workflow_summary_payload,
    workflow_error,
    workflow_summary,
)


def analysis_run_public(run: AnalysisRun) -> AnalysisRunPublic:
    """Return a public analysis-run response with typed workflow metadata."""
    return AnalysisRunPublic(
        id=run.id,
        project_id=run.project_id,
        provider_snapshot_id=run.provider_snapshot_id,
        input_type=run.input_type,
        filename=run.filename,
        status=run.status,
        started_at=run.started_at,
        finished_at=run.finished_at,
        error_message=redact_public_payload(run.error_message),
        **public_workflow_fields(run),
    )


def analysis_run_summary_public(run: AnalysisRun) -> AnalysisRunSummaryPublic:
    """Return the typed run-summary response for one visible analysis run."""
    summary = workflow_summary(run)
    error = workflow_error(run)
    public_fields = public_workflow_fields(run)
    provider_degraded = bool(public_fields.pop("provider_degraded", False))
    for key in (
        "created_findings",
        "updated_findings",
        "ignored_lines",
        "rows_read",
        "occurrence_count",
        "finding_count",
        "counts_by_priority",
        "kev_hits",
        "warnings",
    ):
        public_fields.pop(key, None)
    summary_json = summary.to_legacy_json()
    dedup_summary = _dict_value(summary_json.get("dedup_summary"))
    parse_errors = (
        summary.parse_errors
        or error.parse_errors
        or _parse_errors(summary_json, error.to_legacy_json())
    )
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
        rows_read=_int_value(summary_json.get("rows_read")),
        occurrence_count=_int_value(summary_json.get("occurrence_count")),
        finding_count=_int_value(summary_json.get("finding_count")),
        counts_by_priority=_priority_counts(summary_json.get("counts_by_priority")),
        kev_hits=_int_value(summary_json.get("kev_hits")),
        provider_snapshot_id=run.provider_snapshot_id,
        provider_degraded=provider_degraded,
        warnings=_string_list(summary_json.get("warnings")),
        parse_errors=[
            ImportParseErrorPublic.model_validate(
                item.model_dump(mode="json") if hasattr(item, "model_dump") else item
            )
            for item in parse_errors
            if isinstance(item, dict) or hasattr(item, "model_dump")
        ],
        analysis_decision_scope=_str_value(summary_json.get("analysis_decision_scope")),
        persistence_scope=_str_value(summary_json.get("persistence_scope")),
        **public_fields,
    )


def analysis_run_workflow_metadata_public(run: AnalysisRun) -> AnalysisRunWorkflowMetadataPublic:
    """Return the explicit diagnostics view for one run workflow payload."""
    raw_summary = redacted_workflow_summary_payload(run)
    raw_error = redacted_workflow_error_payload(run)
    summary = redacted_workflow_summary(run)
    error = redacted_workflow_error_or_none(run)
    return AnalysisRunWorkflowMetadataPublic(
        id=run.id,
        project_id=run.project_id,
        status=run.status,
        workflow_schema_version=summary.schema_version,
        workflow_error_schema_version=error.schema_version if error is not None else None,
        summary=summary,
        error=error,
        raw_summary=raw_summary,
        raw_error=raw_error,
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


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str) and item]


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

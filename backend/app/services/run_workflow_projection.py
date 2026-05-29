"""Public v2 projections for analysis runs and workflow output."""

from __future__ import annotations

from typing import Any

from app.models import (
    AnalysisRun,
    AnalysisRunCountsPublic,
    AnalysisRunProviderSnapshotRefPublic,
    AnalysisRunPublic,
    AnalysisRunSummaryPublic,
    AnalysisRunUploadsPublic,
    ImportParseErrorPublic,
    WorkflowRunPublic,
)
from app.services.run_workflow_metadata import redact_public_payload


def analysis_run_public(
    run: AnalysisRun,
    *,
    workflow: WorkflowRunPublic | None = None,
) -> AnalysisRunPublic:
    """Return the v2 public analysis-run response."""
    result = _result_payload(workflow)
    diagnostics = _diagnostics_payload(workflow)
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
        result=result,
        diagnostics=diagnostics,
        uploads=_uploads(result),
        provider_snapshot=_provider_snapshot(run, result),
        counts=_counts(result),
        warnings=_string_list(result.get("warnings")),
        workflow=workflow,
    )


def analysis_run_summary_public(
    run: AnalysisRun,
    *,
    workflow: WorkflowRunPublic | None = None,
) -> AnalysisRunSummaryPublic:
    """Return the v2 run-summary response for one visible analysis run."""
    result = _result_payload(workflow)
    diagnostics = _diagnostics_payload(workflow)
    counts = _counts(result)
    return AnalysisRunSummaryPublic(
        id=run.id,
        project_id=run.project_id,
        input_type=run.input_type,
        filename=run.filename,
        status=run.status,
        started_at=run.started_at,
        finished_at=run.finished_at,
        created_findings=counts.created_findings,
        updated_findings=counts.updated_findings,
        ignored_lines=counts.ignored_lines,
        rows_read=counts.rows_read,
        occurrence_count=counts.occurrence_count,
        finding_count=counts.finding_count,
        counts_by_priority=counts.counts_by_priority,
        kev_hits=counts.kev_hits,
        provider_snapshot_id=run.provider_snapshot_id,
        provider_degraded=_bool_value(result.get("provider_degraded")),
        warnings=_string_list(result.get("warnings")),
        parse_errors=_parse_errors(diagnostics),
        result=result,
        diagnostics=diagnostics,
        uploads=_uploads(result),
        provider_snapshot=_provider_snapshot(run, result),
        analysis_decision_scope=_str_value(result.get("analysis_decision_scope")),
        persistence_scope=_str_value(result.get("persistence_scope")),
        workflow=workflow,
    )


def _result_payload(workflow: WorkflowRunPublic | None) -> dict[str, Any]:
    if workflow is None:
        return {}
    return _dict_value(workflow.result)


def _diagnostics_payload(workflow: WorkflowRunPublic | None) -> dict[str, Any]:
    if workflow is None:
        return {}
    diagnostics = _dict_value(workflow.diagnostics)
    if diagnostics:
        return diagnostics
    return _dict_value(workflow.error_details)


def _uploads(result: dict[str, Any]) -> AnalysisRunUploadsPublic:
    return AnalysisRunUploadsPublic(
        input=_dict_or_none(result.get("input_upload")),
        asset_context=_dict_or_none(result.get("asset_context_upload")),
        vex=_dict_or_none(result.get("vex_upload")),
    )


def _provider_snapshot(
    run: AnalysisRun,
    result: dict[str, Any],
) -> AnalysisRunProviderSnapshotRefPublic | None:
    if run.provider_snapshot_id is None and not any(
        result.get(key)
        for key in ("provider_snapshot_file", "provider_snapshot_hash", "locked_provider_data")
    ):
        return None
    return AnalysisRunProviderSnapshotRefPublic(
        id=run.provider_snapshot_id,
        file=_str_value(result.get("provider_snapshot_file")),
        hash=_str_value(result.get("provider_snapshot_hash")),
        locked=_bool_value(result.get("locked_provider_data")),
        degraded=_bool_value(result.get("provider_degraded")),
    )


def _counts(result: dict[str, Any]) -> AnalysisRunCountsPublic:
    dedup_summary = _dict_value(result.get("dedup_summary"))
    return AnalysisRunCountsPublic(
        created_findings=_int_value(
            result.get("created_findings", dedup_summary.get("created_findings"))
        ),
        updated_findings=_int_value(
            result.get(
                "updated_findings",
                dedup_summary.get("updated_findings", dedup_summary.get("reused_findings")),
            )
        ),
        ignored_lines=_int_value(result.get("ignored_lines")),
        rows_read=_int_value(result.get("rows_read")),
        occurrence_count=_int_value(result.get("occurrence_count")),
        finding_count=_int_value(result.get("finding_count")),
        counts_by_priority=_priority_counts(result.get("counts_by_priority")),
        kev_hits=_int_value(result.get("kev_hits")),
        suppressed_by_vex=_int_value(result.get("suppressed_by_vex")),
        attack_mapped_cves=_int_value(result.get("attack_mapped_cves")),
    )


def _parse_errors(diagnostics: dict[str, Any]) -> list[ImportParseErrorPublic]:
    errors = diagnostics.get("parse_errors") or []
    if not isinstance(errors, list):
        return []
    return [
        ImportParseErrorPublic.model_validate(item) for item in errors if isinstance(item, dict)
    ]


def _dict_value(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def _dict_or_none(value: Any) -> dict[str, Any] | None:
    payload = _dict_value(value)
    return payload or None


def _str_value(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _priority_counts(value: Any) -> dict[str, int]:
    raw = _dict_value(value)
    return {key: _int_value(raw.get(key)) for key in ("Critical", "High", "Medium", "Low")}


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str) and item]


def _bool_value(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes"}
    return False


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

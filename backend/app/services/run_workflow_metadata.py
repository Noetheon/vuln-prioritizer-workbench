"""Typed accessors for persisted run workflow metadata."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from app.contracts.run_workflow import (
    RunWorkflowErrorV1,
    RunWorkflowJob,
    RunWorkflowSummaryV1,
    merge_workflow_error,
    merge_workflow_summary,
    workflow_error_from_legacy,
    workflow_public_fields,
    workflow_summary_from_legacy,
)
from app.models import AnalysisRun
from vuln_prioritizer.security_redaction import redact_value


def workflow_summary(run: AnalysisRun) -> RunWorkflowSummaryV1:
    """Return a typed summary contract for a persisted run."""
    return workflow_summary_from_legacy(raw_workflow_summary_payload(run))


def workflow_error(run: AnalysisRun) -> RunWorkflowErrorV1:
    """Return a typed error contract for a persisted run."""
    return workflow_error_from_legacy(raw_workflow_error_payload(run))


def workflow_error_or_none(run: AnalysisRun) -> RunWorkflowErrorV1 | None:
    """Return typed error metadata only when the run has an error payload."""
    raw_error = raw_workflow_error_payload(run)
    return workflow_error_from_legacy(raw_error) if raw_error else None


def redacted_workflow_summary(run: AnalysisRun) -> RunWorkflowSummaryV1:
    """Return a typed summary contract after public redaction."""
    return workflow_summary_from_legacy(redacted_workflow_summary_payload(run))


def redacted_workflow_error_or_none(run: AnalysisRun) -> RunWorkflowErrorV1 | None:
    """Return typed error metadata after public redaction when an error exists."""
    raw_error = redacted_workflow_error_payload(run)
    return workflow_error_from_legacy(raw_error) if raw_error else None


def workflow_summary_payload(run: AnalysisRun) -> dict[str, Any]:
    """Return validated summary metadata as the internal legacy-compatible mapping."""
    return workflow_summary(run).to_legacy_json()


def workflow_summary_payload_or_empty(run: AnalysisRun) -> dict[str, Any]:
    """Return validated summary metadata only when the run has a summary payload."""
    raw_summary = raw_workflow_summary_payload(run)
    return workflow_summary_from_legacy(raw_summary).to_legacy_json() if raw_summary else {}


def workflow_error_payload(run: AnalysisRun) -> dict[str, Any]:
    """Return validated error metadata as the internal legacy-compatible mapping."""
    return workflow_error(run).to_legacy_json()


def workflow_error_payload_or_empty(run: AnalysisRun) -> dict[str, Any]:
    """Return validated error metadata only when the run has an error payload."""
    error = workflow_error_or_none(run)
    return error.to_legacy_json() if error is not None else {}


def workflow_import_job(run: AnalysisRun) -> RunWorkflowJob | None:
    """Return the active import/provider job from summary or error metadata."""
    return workflow_summary(run).import_job or workflow_error(run).import_job


def workflow_import_job_payload(run: AnalysisRun) -> dict[str, Any] | None:
    """Return the active job payload as a mutable mapping for service transitions."""
    job = workflow_import_job(run)
    return job.model_dump(mode="json") if job is not None else None


def public_workflow_fields(run: AnalysisRun) -> dict[str, Any]:
    """Return redacted typed workflow fields for normal public API responses."""
    summary = redacted_workflow_summary_payload(run)
    error = redacted_workflow_error_payload(run)
    return workflow_public_fields(summary, error)


def redacted_workflow_summary_payload(run: AnalysisRun) -> dict[str, Any]:
    """Return redacted raw summary metadata for explicit diagnostics projections."""
    return _dict_value(redact_public_payload(raw_workflow_summary_payload(run)))


def redacted_workflow_error_payload(run: AnalysisRun) -> dict[str, Any]:
    """Return redacted raw error metadata for explicit diagnostics projections."""
    return _dict_value(redact_public_payload(raw_workflow_error_payload(run)))


def raw_workflow_summary_payload(run: AnalysisRun) -> dict[str, Any]:
    """Return the internal persisted summary mapping."""
    return _dict_value(run.summary_json)


def raw_workflow_error_payload(run: AnalysisRun) -> dict[str, Any]:
    """Return the internal persisted error mapping."""
    return _dict_value(run.error_json)


def set_workflow_summary(
    run: AnalysisRun,
    payload: Mapping[str, Any] | None,
    **updates: Any,
) -> dict[str, Any]:
    """Replace summary metadata after validating it through the workflow contract."""
    run.summary_json = merge_workflow_summary(payload, **updates)
    return run.summary_json


def update_workflow_summary(run: AnalysisRun, **updates: Any) -> dict[str, Any]:
    """Merge summary metadata updates into a persisted run."""
    return set_workflow_summary(run, raw_workflow_summary_payload(run), **updates)


def set_workflow_error(
    run: AnalysisRun,
    payload: Mapping[str, Any] | None = None,
    **updates: Any,
) -> dict[str, Any]:
    """Replace error metadata after validating it through the workflow contract."""
    run.error_json = merge_workflow_error(payload, **updates)
    return run.error_json


def update_workflow_error(run: AnalysisRun, **updates: Any) -> dict[str, Any]:
    """Merge error metadata updates into a persisted run."""
    return set_workflow_error(run, raw_workflow_error_payload(run), **updates)


def merge_summary_payload(
    base: Mapping[str, Any] | None,
    **updates: Any,
) -> dict[str, Any]:
    """Return a validated summary mapping without mutating a run."""
    return merge_workflow_summary(base, **updates)


def merge_error_payload(
    base: Mapping[str, Any] | None = None,
    **updates: Any,
) -> dict[str, Any]:
    """Return a validated error mapping without mutating a run."""
    return merge_workflow_error(base, **updates)


def redact_public_payload(value: Any) -> Any:
    """Redact secrets and local paths from public workflow payload values."""
    redacted, _paths = redact_value(value)
    return redacted


def _dict_value(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}

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
from vuln_prioritizer.security_redaction import redact_value


def workflow_summary(payload: Mapping[str, Any] | None = None) -> RunWorkflowSummaryV1:
    """Return a typed workflow result contract."""
    return workflow_summary_from_legacy(_mapping_value(payload))


def workflow_error(payload: Mapping[str, Any] | None = None) -> RunWorkflowErrorV1:
    """Return a typed workflow diagnostic contract."""
    return workflow_error_from_legacy(_mapping_value(payload))


def workflow_error_or_none(payload: Mapping[str, Any] | None) -> RunWorkflowErrorV1 | None:
    """Return typed diagnostic metadata only when a payload exists."""
    raw_error = _mapping_value(payload)
    return workflow_error_from_legacy(raw_error) if raw_error else None


def redacted_workflow_summary(payload: Mapping[str, Any] | None) -> RunWorkflowSummaryV1:
    """Return a typed result contract after public redaction."""
    return workflow_summary_from_legacy(redacted_workflow_summary_payload(payload))


def redacted_workflow_error_or_none(
    payload: Mapping[str, Any] | None,
) -> RunWorkflowErrorV1 | None:
    """Return typed diagnostic metadata after public redaction when one exists."""
    raw_error = redacted_workflow_error_payload(payload)
    return workflow_error_from_legacy(raw_error) if raw_error else None


def workflow_summary_payload(payload: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Return validated workflow result metadata as a compact mapping."""
    return workflow_summary(payload).to_legacy_json()


def workflow_summary_payload_or_empty(payload: Mapping[str, Any] | None) -> dict[str, Any]:
    """Return validated result metadata only when a payload exists."""
    raw_summary = _mapping_value(payload)
    return workflow_summary_from_legacy(raw_summary).to_legacy_json() if raw_summary else {}


def workflow_error_payload(payload: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Return validated diagnostic metadata as a compact mapping."""
    return workflow_error(payload).to_legacy_json()


def workflow_error_payload_or_empty(payload: Mapping[str, Any] | None) -> dict[str, Any]:
    """Return validated diagnostic metadata only when a payload exists."""
    error = workflow_error_or_none(payload)
    return error.to_legacy_json() if error is not None else {}


def workflow_import_job(
    result: Mapping[str, Any] | None = None,
    diagnostics: Mapping[str, Any] | None = None,
) -> RunWorkflowJob | None:
    """Return the active import/provider job from workflow result or diagnostics."""
    return workflow_summary(result).import_job or workflow_error(diagnostics).import_job


def workflow_import_job_payload(
    result: Mapping[str, Any] | None = None,
    diagnostics: Mapping[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Return the active job payload as a mutable mapping for service transitions."""
    job = workflow_import_job(result, diagnostics)
    return job.model_dump(mode="json") if job is not None else None


def public_workflow_fields(
    result: Mapping[str, Any] | None,
    diagnostics: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Return redacted typed workflow fields for normal public API responses."""
    summary = redacted_workflow_summary_payload(result)
    error = redacted_workflow_error_payload(diagnostics)
    return workflow_public_fields(summary, error)


def redacted_workflow_summary_payload(payload: Mapping[str, Any] | None) -> dict[str, Any]:
    """Return redacted raw result metadata for explicit diagnostics projections."""
    return _dict_value(redact_public_payload(_mapping_value(payload)))


def redacted_workflow_error_payload(payload: Mapping[str, Any] | None) -> dict[str, Any]:
    """Return redacted raw diagnostic metadata for explicit diagnostics projections."""
    return _dict_value(redact_public_payload(_mapping_value(payload)))


def set_workflow_summary(
    payload: Mapping[str, Any] | None,
    **updates: Any,
) -> dict[str, Any]:
    """Return replaced result metadata after validating it through the workflow contract."""
    return merge_workflow_summary(payload, **updates)


def update_workflow_summary(
    payload: Mapping[str, Any] | None,
    **updates: Any,
) -> dict[str, Any]:
    """Merge result metadata updates into a mapping."""
    return set_workflow_summary(payload, **updates)


def set_workflow_error(
    payload: Mapping[str, Any] | None = None,
    **updates: Any,
) -> dict[str, Any]:
    """Return replaced diagnostic metadata after validating it through the workflow contract."""
    return merge_workflow_error(payload, **updates)


def update_workflow_error(
    payload: Mapping[str, Any] | None,
    **updates: Any,
) -> dict[str, Any]:
    """Merge diagnostic metadata updates into a mapping."""
    return set_workflow_error(payload, **updates)


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


def _mapping_value(value: Mapping[str, Any] | None) -> dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}

"""Versioned contract for Workbench run workflow metadata."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

RUN_WORKFLOW_SUMMARY_SCHEMA_VERSION: Literal["run-workflow-summary.v1"] = "run-workflow-summary.v1"
RUN_WORKFLOW_ERROR_SCHEMA_VERSION: Literal["run-workflow-error.v1"] = "run-workflow-error.v1"

PriorityCounts = dict[str, int]


def _empty_priority_counts() -> dict[str, int]:
    return {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}


class _WorkflowContractModel(BaseModel):
    """Base model that preserves older compatibility keys while typing known ones."""

    model_config = ConfigDict(extra="allow")

    def to_legacy_json(self) -> dict[str, Any]:
        """Return the JSON shape stored in legacy ``summary_json``/``error_json`` columns."""
        return self.model_dump(mode="json", exclude_none=True)


class RunWorkflowJobStatusEntry(_WorkflowContractModel):
    """One recorded status transition for an import or provider job."""

    status: str
    created_at: str | None = None


class RunWorkflowJob(_WorkflowContractModel):
    """Stable job metadata exposed on run summaries."""

    id: str
    status: str
    execution_mode: str = "request"
    updated_at: str | None = None
    status_history: list[RunWorkflowJobStatusEntry] = Field(default_factory=list)


class RunWorkflowUploadRef(_WorkflowContractModel):
    """Managed upload metadata without server-local filesystem paths."""

    input_type: str | None = None
    original_filename: str | None = None
    stored_filename: str | None = None
    content_type: str | None = None
    size_bytes: int | None = None
    sha256: str | None = None
    path: str | None = None
    storage_ref: str | None = None


class RunWorkflowParseError(_WorkflowContractModel):
    """Stable parser diagnostic item."""

    input_type: str
    filename: str | None = None
    message: str
    error_type: str
    line: int | None = None
    field: str | None = None
    value: str | None = None


class RunWorkflowFailure(_WorkflowContractModel):
    """Structured workflow failure metadata."""

    message: str
    stage: str
    error_type: str | None = None
    filename: str | None = None


class RunWorkflowDedupDecision(_WorkflowContractModel):
    """One sampled import deduplication decision."""

    action: str
    dedup_key: str | None = None
    finding_id: str | None = None
    cve: str | None = None
    source_id: str | None = None
    component_identity: str | None = None
    asset_ref: str | None = None


class RunWorkflowDedupSummary(_WorkflowContractModel):
    """Import deduplication summary for a Workbench run."""

    key_version: str | None = None
    created_findings: int = 0
    updated_findings: int = 0
    reused_findings: int = 0
    decision_count: int = 0
    decisions: list[RunWorkflowDedupDecision] = Field(default_factory=list)
    decision_sample_limit: int | None = None
    omitted_decisions: int = 0


class RunWorkflowSummaryV1(_WorkflowContractModel):
    """Typed v1 contract for Workbench import/run summary metadata."""

    schema_version: Literal["run-workflow-summary.v1"] = RUN_WORKFLOW_SUMMARY_SCHEMA_VERSION
    input_upload: RunWorkflowUploadRef | None = None
    asset_context_upload: RunWorkflowUploadRef | None = None
    vex_upload: RunWorkflowUploadRef | None = None
    import_job: RunWorkflowJob | None = None
    created_findings: int = 0
    updated_findings: int = 0
    ignored_lines: int = 0
    rows_read: int = 0
    occurrence_count: int = 0
    finding_count: int = 0
    counts_by_priority: PriorityCounts = Field(default_factory=_empty_priority_counts)
    kev_hits: int = 0
    provider_snapshot_id: str | None = None
    provider_snapshot_hash: str | None = None
    provider_snapshot_file: str | None = None
    locked_provider_data: bool = False
    provider_degraded: bool = False
    attack_enabled: bool = False
    attack_source: str | None = None
    attack_mapped_cves: int = 0
    attack_mapping_file: str | None = None
    attack_mapping_file_sha256: str | None = None
    attack_technique_metadata_file: str | None = None
    attack_technique_metadata_file_sha256: str | None = None
    asset_context: dict[str, Any] | None = None
    vex: dict[str, Any] | None = None
    suppressed_by_vex: int = 0
    under_investigation_count: int = 0
    vex_conflict_count: int = 0
    provider_data_quality_flags: dict[str, list[dict[str, Any]]] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)
    analysis_service: dict[str, Any] | None = None
    analysis_semantics: dict[str, Any] | None = None
    analysis_decision_scope: str | None = None
    persistence_scope: str | None = None
    input_sha256: str | None = None
    parse_errors: list[RunWorkflowParseError] = Field(default_factory=list)
    dedup_summary: RunWorkflowDedupSummary | None = None
    analysis_error: RunWorkflowFailure | None = None
    asset_context_error: RunWorkflowFailure | None = None
    vex_error: RunWorkflowFailure | None = None
    background_error: RunWorkflowFailure | None = None

    def to_legacy_json(self) -> dict[str, Any]:
        """Return summary JSON while preserving parser diagnostic null fields."""
        payload = super().to_legacy_json()
        payload["parse_errors"] = [item.model_dump(mode="json") for item in self.parse_errors]
        return payload


class RunWorkflowErrorV1(_WorkflowContractModel):
    """Typed v1 contract for Workbench run error metadata."""

    schema_version: Literal["run-workflow-error.v1"] = RUN_WORKFLOW_ERROR_SCHEMA_VERSION
    parse_errors: list[RunWorkflowParseError] = Field(default_factory=list)
    import_job: RunWorkflowJob | None = None
    analysis_error: RunWorkflowFailure | None = None
    asset_context_error: RunWorkflowFailure | None = None
    vex_error: RunWorkflowFailure | None = None
    background_error: RunWorkflowFailure | None = None
    created_findings: int = 0
    updated_findings: int = 0
    ignored_lines: int = 0

    def to_legacy_json(self) -> dict[str, Any]:
        """Return error JSON while preserving parser diagnostic null fields."""
        payload = super().to_legacy_json()
        payload["parse_errors"] = [item.model_dump(mode="json") for item in self.parse_errors]
        return payload


def workflow_summary_from_legacy(value: Mapping[str, Any] | None) -> RunWorkflowSummaryV1:
    """Parse existing summary JSON into the typed workflow summary contract."""
    payload = _mapping_payload(value)
    payload.setdefault("schema_version", RUN_WORKFLOW_SUMMARY_SCHEMA_VERSION)
    return RunWorkflowSummaryV1.model_validate(payload)


def workflow_error_from_legacy(value: Mapping[str, Any] | None) -> RunWorkflowErrorV1:
    """Parse existing error JSON into the typed workflow error contract."""
    payload = _mapping_payload(value)
    payload.setdefault("schema_version", RUN_WORKFLOW_ERROR_SCHEMA_VERSION)
    return RunWorkflowErrorV1.model_validate(payload)


def workflow_public_fields(
    summary_json: Mapping[str, Any] | None,
    error_json: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Return typed public fields derived from legacy workflow JSON columns."""
    summary = workflow_summary_from_legacy(summary_json)
    error = workflow_error_from_legacy(error_json)
    import_job = summary.import_job or error.import_job
    return {
        "workflow_schema_version": summary.schema_version,
        "workflow_error_schema_version": (
            error.schema_version if _mapping_payload(error_json) else None
        ),
        "input_upload": summary.input_upload,
        "asset_context_upload": summary.asset_context_upload,
        "vex_upload": summary.vex_upload,
        "import_job": import_job,
        "dedup_summary": summary.dedup_summary,
        "created_findings": summary.created_findings,
        "updated_findings": summary.updated_findings,
        "ignored_lines": summary.ignored_lines,
        "rows_read": summary.rows_read,
        "occurrence_count": summary.occurrence_count,
        "finding_count": summary.finding_count,
        "counts_by_priority": summary.counts_by_priority,
        "kev_hits": summary.kev_hits,
        "input_sha256": summary.input_sha256,
        "locked_provider_data": summary.locked_provider_data,
        "provider_snapshot_file": summary.provider_snapshot_file,
        "provider_snapshot_hash": summary.provider_snapshot_hash,
        "provider_degraded": summary.provider_degraded,
        "attack_source": summary.attack_source,
        "attack_mapped_cves": summary.attack_mapped_cves,
        "attack_mapping_file": summary.attack_mapping_file,
        "asset_context": summary.asset_context,
        "vex": summary.vex,
        "suppressed_by_vex": summary.suppressed_by_vex,
        "warnings": summary.warnings,
        "analysis_error": summary.analysis_error or error.analysis_error,
        "asset_context_error": summary.asset_context_error or error.asset_context_error,
        "vex_error": summary.vex_error or error.vex_error,
        "background_error": summary.background_error or error.background_error,
        "workflow_error": error if _mapping_payload(error_json) else None,
    }


def merge_workflow_summary(
    base: Mapping[str, Any] | None,
    **updates: Any,
) -> dict[str, Any]:
    """Merge updates through the typed summary contract before persistence."""
    payload = workflow_summary_from_legacy(base).to_legacy_json()
    payload.update({key: value for key, value in updates.items() if value is not None})
    return workflow_summary_from_legacy(payload).to_legacy_json()


def merge_workflow_error(
    base: Mapping[str, Any] | None = None,
    **updates: Any,
) -> dict[str, Any]:
    """Merge updates through the typed error contract before persistence."""
    payload = workflow_error_from_legacy(base).to_legacy_json()
    payload.update({key: value for key, value in updates.items() if value is not None})
    return workflow_error_from_legacy(payload).to_legacy_json()


def _mapping_payload(value: Mapping[str, Any] | None) -> dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}

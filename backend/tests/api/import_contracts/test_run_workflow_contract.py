from __future__ import annotations

from app.contracts.run_workflow import (
    RUN_WORKFLOW_ERROR_SCHEMA_VERSION,
    RUN_WORKFLOW_SUMMARY_SCHEMA_VERSION,
    merge_workflow_error,
    merge_workflow_summary,
    workflow_error_from_legacy,
    workflow_summary_from_legacy,
)


def test_run_workflow_summary_contract_parses_legacy_minimal_payload() -> None:
    summary = workflow_summary_from_legacy({"parsed": 1, "findings": 1})

    assert summary.schema_version == RUN_WORKFLOW_SUMMARY_SCHEMA_VERSION
    assert summary.created_findings == 0
    assert summary.to_legacy_json()["parsed"] == 1
    assert summary.to_legacy_json()["schema_version"] == RUN_WORKFLOW_SUMMARY_SCHEMA_VERSION


def test_run_workflow_summary_merge_preserves_known_and_extra_fields() -> None:
    payload = merge_workflow_summary(
        {"input_upload": {"sha256": "old"}, "custom": "kept"},
        input_upload={"sha256": "new", "storage_ref": "project/run/file.txt"},
        created_findings=2,
    )

    assert payload["schema_version"] == RUN_WORKFLOW_SUMMARY_SCHEMA_VERSION
    assert payload["input_upload"]["sha256"] == "new"
    assert payload["input_upload"]["storage_ref"] == "project/run/file.txt"
    assert payload["created_findings"] == 2
    assert payload["custom"] == "kept"


def test_run_workflow_error_contract_parses_legacy_detail_payload() -> None:
    error = workflow_error_from_legacy({"detail": "failed"})

    assert error.schema_version == RUN_WORKFLOW_ERROR_SCHEMA_VERSION
    assert error.to_legacy_json()["detail"] == "failed"


def test_run_workflow_error_merge_preserves_failure_payload() -> None:
    payload = merge_workflow_error(
        None,
        analysis_error={
            "message": "Provider failed",
            "stage": "enrich_score_explain",
            "error_type": "RuntimeError",
        },
        ignored_lines=3,
    )

    assert payload["schema_version"] == RUN_WORKFLOW_ERROR_SCHEMA_VERSION
    assert payload["analysis_error"]["stage"] == "enrich_score_explain"
    assert payload["ignored_lines"] == 3

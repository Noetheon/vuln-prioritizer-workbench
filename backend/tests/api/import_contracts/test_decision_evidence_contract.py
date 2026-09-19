from __future__ import annotations

from types import MappingProxyType

import pytest
from pydantic import ValidationError

from app.decision_core.builders import build_run_diagnostics
from app.decision_core.contracts import (
    ANALYSIS_EVIDENCE_SCHEMA_VERSION,
    FINDING_DECISION_EVIDENCE_SCHEMA_VERSION,
    RUN_DIAGNOSTICS_SCHEMA_VERSION,
    AnalysisEvidenceV2,
    FindingDecisionEvidenceV2,
    PriorityEvidenceV2,
    RunDiagnosticsV2,
)


def _finding_payload() -> dict[str, object]:
    return {
        "schema_version": FINDING_DECISION_EVIDENCE_SCHEMA_VERSION,
        "finding_id": "finding-1",
        "analysis_run_id": "run-1",
        "project_id": "project-1",
        "cve_id": "CVE-2024-0001",
        "dedup_key": "CVE-2024-0001:component",
        "status": "open",
        "priority": "high",
        "priority_rank": 2,
        "occurrence_scope": {"target_ref": "host-1"},
        "priority_evidence": {
            "priority_label": "High",
            "priority_rank": 2,
            "rationale": "KEV signal recorded.",
            "data_quality_confidence": "high",
            "data_quality_flags": [],
        },
        "provider": {
            "provider_snapshot_hash": "abc123",
            "provider_evidence": {"epss": 0.93, "in_kev": True},
        },
        "governance": {"suppressed_by_vex": False, "waived": False},
        "attack": {"mapped": True, "source": "catalog", "technique_ids": ["T1190"]},
        "remediation": {"recommended_action": "patch"},
        "occurrences": [
            {
                "analysis_run_id": "run-1",
                "source": "trivy",
                "scanner": "trivy",
                "target_ref": "host-1",
            }
        ],
    }


def test_decision_evidence_contract_validates_run_and_finding_graph() -> None:
    finding = FindingDecisionEvidenceV2.model_validate(_finding_payload())
    evidence = AnalysisEvidenceV2.model_validate(
        {
            "schema_version": ANALYSIS_EVIDENCE_SCHEMA_VERSION,
            "analysis_evidence_id": "evidence-1",
            "analysis_run_id": "run-1",
            "project_id": "project-1",
            "input_type": "trivy",
            "filename": "scan.json",
            "status": "succeeded",
            "counts": {
                "created_findings": 1,
                "finding_count": 1,
                "kev_hits": 1,
                "attack_mapped_cves": 1,
            },
            "provider": {
                "provider_snapshot_hash": "abc123",
                "kev_hits": 1,
            },
            "analysis_service": {
                "pipeline": "parse-persist-enrich-score-explain",
                "engine": "app.domain.engine.prepare_analysis",
                "kernel": "app.decision_core.producer",
            },
            "analysis_semantics": {
                "analysis_decision_scope": "cve_baseline_with_occurrence_overlays",
                "persistence_scope": "asset_component_occurrence",
                "occurrence_overlay_fields": [
                    "asset_context",
                    "component_identity",
                    "source_identity",
                    "vex_status",
                ],
                "finding_dedup_key_version": "vpw019-v1",
                "cve_count": 1,
                "occurrence_count": 1,
                "finding_count": 1,
                "same_cve_can_create_distinct_asset_findings": True,
            },
            "dedup_summary": {
                "key_version": "vpw019-v1",
                "created_findings": 1,
                "updated_findings": 0,
                "reused_findings": 0,
                "decision_count": 1,
                "decisions": [],
                "decision_sample_limit": 500,
                "omitted_decisions": 0,
            },
        }
    )

    assert evidence.schema_version == ANALYSIS_EVIDENCE_SCHEMA_VERSION
    assert evidence.analysis_evidence_id == "evidence-1"
    assert evidence.counts.finding_count == 1
    assert evidence.provider.provider_snapshot_hash == "abc123"
    assert evidence.analysis_service.kernel == "app.decision_core.producer"
    assert evidence.analysis_semantics.finding_dedup_key_version == "vpw019-v1"
    assert evidence.dedup_summary is not None
    assert evidence.dedup_summary.created_findings == 1
    assert finding.schema_version == FINDING_DECISION_EVIDENCE_SCHEMA_VERSION
    assert finding.priority_evidence.data_quality_confidence == "high"
    assert finding.attack.technique_ids == ["T1190"]


def test_decision_evidence_contract_rejects_legacy_free_json_fields() -> None:
    with pytest.raises(ValidationError):
        FindingDecisionEvidenceV2.model_validate(
            {
                **_finding_payload(),
                "explanation_json": {"legacy": True},
            }
        )

    with pytest.raises(ValidationError):
        AnalysisEvidenceV2.model_validate(
            {
                "schema_version": ANALYSIS_EVIDENCE_SCHEMA_VERSION,
                "analysis_run_id": "run-1",
                "project_id": "project-1",
                "input_type": "trivy",
                "status": "succeeded",
                "result": {"legacy": True},
            }
        )

    with pytest.raises(ValidationError):
        AnalysisEvidenceV2.model_validate(
            {
                "schema_version": ANALYSIS_EVIDENCE_SCHEMA_VERSION,
                "analysis_run_id": "run-1",
                "project_id": "project-1",
                "input_type": "trivy",
                "status": "succeeded",
                "findings": [_finding_payload()],
            }
        )


def test_run_diagnostics_v2_is_typed_and_strict() -> None:
    diagnostics = RunDiagnosticsV2.model_validate(
        {
            "schema_version": RUN_DIAGNOSTICS_SCHEMA_VERSION,
            "stage": "parse_upload",
            "message": "Invalid JSON",
            "error_type": "ImporterParseError",
            "parse_errors": [
                {
                    "input_type": "trivy",
                    "filename": "broken.json",
                    "message": "Invalid JSON",
                    "error_type": "ImporterParseError",
                    "line": 1,
                }
            ],
        }
    )

    assert diagnostics.schema_version == RUN_DIAGNOSTICS_SCHEMA_VERSION
    assert diagnostics.parse_errors[0].message == "Invalid JSON"

    with pytest.raises(ValidationError):
        PriorityEvidenceV2.model_validate(
            {
                "priority_label": "High",
                "priority_rank": 2,
                "legacy_reason": "not allowed",
            }
        )


def test_run_diagnostics_builder_preserves_distinct_failures_and_normalizes_lists() -> None:
    parse_error = {
        "input_type": "generic-occurrence-csv",
        "filename": "scan.csv",
        "message": "Invalid CVE identifier",
        "error_type": "ImporterParseError",
        "line": 7,
        "field": "cve_id",
        "value": "NOT-A-CVE",
    }
    second_parse_error = {
        "input_type": "trivy",
        "message": "Missing vulnerability ID",
        "error_type": "ImporterParseError",
        "filename": None,
        "line": None,
        "field": None,
        "value": None,
    }
    failures = {
        "analysis_error": {
            "message": "Provider snapshot unavailable",
            "stage": "enrich_score_explain",
            "error_type": "ProviderUnavailable",
            "filename": "snapshot.json",
        },
        "asset_context_error": {
            "message": "Unknown asset column",
            "stage": "parse_asset_context",
            "error_type": "AssetContextParseError",
            "filename": "assets.csv",
        },
        "vex_error": {
            "message": "Invalid VEX document",
            "stage": "parse_vex",
            "error_type": "VexParseError",
            "filename": "statement.json",
        },
    }
    diagnostics = build_run_diagnostics(
        MappingProxyType(
            {
                "stage": "parse_upload",
                "message": "Import failed",
                "error_type": "ImportServiceError",
                "parse_errors": [parse_error, None, "invalid entry", second_parse_error],
                **failures,
                "warnings": ["", None, "Cached data", 0, "Partial context", "Cached data"],
                "analysis_run_id": "run-1",
                "ignored_lines": 2,
            }
        )
    )

    assert diagnostics.model_dump() == {
        "schema_version": RUN_DIAGNOSTICS_SCHEMA_VERSION,
        "stage": "parse_upload",
        "message": "Import failed",
        "error_type": "ImportServiceError",
        "parse_errors": [parse_error, second_parse_error],
        **failures,
        "warnings": ["Cached data", "Partial context", "Cached data"],
    }
    assert diagnostics.to_jsonable()["parse_errors"][1] == {
        "input_type": "trivy",
        "message": "Missing vulnerability ID",
        "error_type": "ImporterParseError",
    }


@pytest.mark.parametrize(
    "payload",
    [
        None,
        {},
        {
            "stage": None,
            "message": None,
            "error_type": None,
            "parse_errors": None,
            "analysis_error": None,
            "asset_context_error": {},
            "vex_error": None,
            "warnings": None,
        },
        {
            "stage": "",
            "message": 42,
            "error_type": [],
            "parse_errors": "not a list",
            "analysis_error": [],
            "asset_context_error": "not a mapping",
            "vex_error": False,
            "warnings": "not a list",
        },
    ],
    ids=["absent", "empty", "null-fields", "non-diagnostic-values"],
)
def test_run_diagnostics_builder_defaults_do_not_fabricate_failures(
    payload: dict[str, object] | None,
) -> None:
    diagnostics = build_run_diagnostics(payload)

    assert diagnostics.model_dump() == {
        "schema_version": RUN_DIAGNOSTICS_SCHEMA_VERSION,
        "stage": None,
        "message": None,
        "error_type": None,
        "parse_errors": [],
        "analysis_error": None,
        "asset_context_error": None,
        "vex_error": None,
        "warnings": [],
    }
    assert diagnostics.to_jsonable() == {
        "schema_version": RUN_DIAGNOSTICS_SCHEMA_VERSION,
        "parse_errors": [],
        "warnings": [],
    }


@pytest.mark.parametrize("failure_field", ["analysis_error", "asset_context_error", "vex_error"])
@pytest.mark.parametrize(
    "failure, error_field, error_type",
    [
        ({"message": "Failure without a stage"}, "stage", "missing"),
        (
            {"message": "Failure", "stage": "parse_upload", "legacy_detail": "not allowed"},
            "legacy_detail",
            "extra_forbidden",
        ),
    ],
)
def test_run_diagnostics_builder_rejects_invalid_structured_failures(
    failure_field: str, failure: dict[str, str], error_field: str, error_type: str
) -> None:
    with pytest.raises(ValidationError) as captured:
        build_run_diagnostics({failure_field: failure})

    assert [(error["loc"], error["type"]) for error in captured.value.errors()] == [
        ((error_field,), error_type)
    ]


def test_run_diagnostics_builder_rejects_invalid_parse_error_records() -> None:
    with pytest.raises(ValidationError) as captured:
        build_run_diagnostics(
            {
                "parse_errors": [
                    {
                        "input_type": "trivy",
                        "message": "Invalid JSON",
                        "error_type": "ImporterParseError",
                        "line": "not a line number",
                    }
                ]
            }
        )

    assert [(error["loc"], error["type"]) for error in captured.value.errors()] == [
        (("line",), "int_parsing")
    ]

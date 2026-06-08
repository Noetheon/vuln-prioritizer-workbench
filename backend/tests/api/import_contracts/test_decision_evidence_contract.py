from __future__ import annotations

import pytest
from pydantic import ValidationError

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

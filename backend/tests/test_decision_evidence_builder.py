from __future__ import annotations

import uuid

from app.decision_core.builders import build_occurrence_evidence
from app.decision_core.contracts import AnalysisSemanticsV2


def test_occurrence_evidence_uses_canonical_workbench_v3_fields_only() -> None:
    run_id = uuid.uuid4()

    occurrence = build_occurrence_evidence(
        analysis_run_id=run_id,
        occurrence_id=uuid.uuid4(),
        source="generic-occurrence-csv",
        scanner=None,
        raw_reference="row:2",
        fix_version="5.6.1-r2",
        raw_evidence={
            "component": "legacy-xz",
            "version": "legacy-5.6.0",
            "severity": "legacy-critical",
            "component_name": "xz",
            "component_version": "5.6.0",
            "raw_severity": "CRITICAL",
            "purl": "pkg:apk/alpine/xz@5.6.0-r0",
            "target_ref": "build-host-1",
            "asset_exposure": "internet-facing",
            "exposure": "legacy-private",
            "asset_environment": "production",
            "environment": "legacy-development",
            "asset_criticality": "critical",
            "criticality": "legacy-low",
        },
        dedup={
            "dedup_key": "canonical",
            "observation_key": "vpw-observation-v1:abc",
            "observation_key_version": "observation-v1",
        },
    )

    assert occurrence.analysis_run_id == str(run_id)
    assert occurrence.component_name == "xz"
    assert occurrence.component_version == "5.6.0"
    assert occurrence.raw_severity == "CRITICAL"
    assert occurrence.purl == "pkg:apk/alpine/xz@5.6.0-r0"
    assert occurrence.target_ref == "build-host-1"
    assert occurrence.asset_exposure == "internet-facing"
    assert occurrence.asset_environment == "production"
    assert occurrence.asset_criticality == "critical"
    assert occurrence.dedup.key == "canonical"
    assert occurrence.dedup.observation_key == "vpw-observation-v1:abc"
    assert occurrence.dedup.observation_key_version == "observation-v1"

    legacy_only = build_occurrence_evidence(
        analysis_run_id=run_id,
        occurrence_id=None,
        source="generic-occurrence-csv",
        scanner=None,
        raw_reference="row:3",
        fix_version=None,
        raw_evidence={
            "component": "legacy-xz",
            "version": "legacy-5.6.0",
            "severity": "legacy-critical",
            "exposure": "private",
            "environment": "development",
            "criticality": "low",
        },
        dedup={},
    )

    assert legacy_only.component_name is None
    assert legacy_only.component_version is None
    assert legacy_only.raw_severity is None
    assert legacy_only.asset_exposure == "private"
    assert legacy_only.asset_environment == "development"
    assert legacy_only.asset_criticality == "low"


def test_analysis_semantics_supports_optional_replay_fingerprints() -> None:
    semantics = AnalysisSemanticsV2(
        analysis_decision_scope="occurrence",
        persistence_scope="finding-scope",
        finding_dedup_key_version="finding-scope-v2",
        decision_graph_schema_version="decision-graph.v1",
        normalized_input_sha256="a" * 64,
        policy_sha256="b" * 64,
        shared_facts_sha256="c" * 64,
        replay_sha256="d" * 64,
    )

    assert semantics.to_jsonable() == {
        "analysis_decision_scope": "occurrence",
        "persistence_scope": "finding-scope",
        "occurrence_overlay_fields": [],
        "finding_dedup_key_version": "finding-scope-v2",
        "decision_graph_schema_version": "decision-graph.v1",
        "normalized_input_sha256": "a" * 64,
        "policy_sha256": "b" * 64,
        "shared_facts_sha256": "c" * 64,
        "replay_sha256": "d" * 64,
        "cve_count": 0,
        "occurrence_count": 0,
        "finding_count": 0,
        "same_cve_can_create_distinct_asset_findings": True,
    }

    backward_compatible = AnalysisSemanticsV2(
        analysis_decision_scope="cve",
        persistence_scope="finding",
        finding_dedup_key_version="legacy-v1",
    ).to_jsonable()

    assert "decision_graph_schema_version" not in backward_compatible
    assert "normalized_input_sha256" not in backward_compatible
    assert "policy_sha256" not in backward_compatible
    assert "shared_facts_sha256" not in backward_compatible
    assert "replay_sha256" not in backward_compatible

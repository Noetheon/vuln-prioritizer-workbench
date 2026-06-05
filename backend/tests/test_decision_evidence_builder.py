from __future__ import annotations

import uuid

from app.services.decision_evidence_builder import build_occurrence_evidence


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
        },
        dedup={"dedup_key": "canonical"},
    )

    assert occurrence.analysis_run_id == str(run_id)
    assert occurrence.component_name == "xz"
    assert occurrence.component_version == "5.6.0"
    assert occurrence.raw_severity == "CRITICAL"
    assert occurrence.purl == "pkg:apk/alpine/xz@5.6.0-r0"
    assert occurrence.target_ref == "build-host-1"

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
        },
        dedup={},
    )

    assert legacy_only.component_name is None
    assert legacy_only.component_version is None
    assert legacy_only.raw_severity is None

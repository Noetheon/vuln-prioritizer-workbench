from __future__ import annotations

import json

from utils.report_contract_fixtures import _vpw050_snapshot_payload

from app.contracts.sbom import SbomAssessmentV1
from app.services.report_exports import render_analysis_result_json
from app.services.report_html import render_html_executive_report
from app.services.report_markdown import render_markdown_report


def test_partial_zero_cve_assessment_remains_visible_in_all_report_summaries() -> None:
    assessment = SbomAssessmentV1(
        scanner_version="0.110.0",
        scanned_at="2026-09-19T00:00:00Z",
        input_sha256="a" * 64,
        output_sha256="b" * 64,
        target_ref="<script>inventory</script>",
        input_format="cyclonedx-json",
        component_count=1,
        identified_component_count=0,
        version_missing_count=1,
        scanner_match_count=1,
        prioritized_match_count=0,
        unassigned_match_count=1,
        status="partial",
        warnings=["Advisory has no CVE mapping."],
    )
    payload = _vpw050_snapshot_payload().model_copy(
        update={
            "summary": {"sbom_assessment": assessment.model_dump(mode="json")},
            "findings": (),
        }
    )
    for renderer in (render_markdown_report, render_html_executive_report):
        output = renderer(payload)
        assert "SBOM Assessment" in output
        assert "partial" in output
        assert "Matches without CVE mapping" in output
        assert "Advisory has no CVE mapping." in output
        assert "Zero findings do not prove complete coverage" in output
        assert "<script>inventory</script>" not in output
    exported = json.loads(render_analysis_result_json(payload))
    assert exported["analysis_run"]["summary"]["sbom_assessment"]["unassigned_match_count"] == 1
    assert exported["findings"] == []

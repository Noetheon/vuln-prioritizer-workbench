"""Re-export facade for Workbench report renderers."""

# ruff: noqa: F401,F403,F405,I001,E501

from __future__ import annotations

from collections import Counter as Counter
from pathlib import Path
from typing import Any

import app.services.report_bundle as _report_bundle

# fmt: off
from app.services.report_exports import render_analysis_result_json, render_findings_csv
from app.services.report_formatting import safe_html
from app.services.report_html import EXECUTIVE_REPORT_CSS, _actionability_summary, _business_impact_summary, _decision_statement, _executive_summary_text, _get_remediation_campaigns, _html_asset_rollup_row, _html_governance_rollups, _html_metric, _html_provider_snapshot, _html_service_rollup_row, _html_top_risk_row, _html_waiver_debt_row, _provider_freshness_rows, _provider_freshness_status, render_html_executive_report
from app.services.report_markdown import _markdown_detection_coverage_section, _markdown_governance_section, render_markdown_report
from app.services.report_projection import _analysis_finding, _analysis_provider_snapshot, _asset_label, _component_label, _data_quality_confidence, _data_quality_flags, _decision_guidance, _decision_sla, _decision_text, _finding_payload, _flag_items, _governance_decision_statement, _governance_detail_clause, _occurrence_payload, _provider_snapshot_payload, _vulnerability_payload
from app.services.report_renderer_common import _boolish_signal, _counts_by_priority, _decision_guidance_from_payload, _dict_list, _governance_vex_summary, _list_value, _priority_label, _redact_bundle_value, _redacted_bundle_payload, _string_from_mapping, _vex_status_counts_from_explanation, _vex_statuses_label, _vex_statuses_label_from_explanation
# fmt: on

_asset_context_rows = _report_bundle._asset_context_rows
_bundle_file_entry = _report_bundle._bundle_file_entry
_bundle_input_hashes = _report_bundle._bundle_input_hashes
_governance_asset_context_export = _report_bundle._governance_asset_context_export
_governance_bundle_entries = _report_bundle._governance_bundle_entries
_governance_detection_coverage_export = _report_bundle._governance_detection_coverage_export
_governance_finding_row = _report_bundle._governance_finding_row
_governance_rollups_export = _report_bundle._governance_rollups_export
_governance_vex_export = _report_bundle._governance_vex_export
_governance_waivers_export = _report_bundle._governance_waivers_export
_json_bytes = _report_bundle._json_bytes
_safe_bundle_filename = _report_bundle._safe_bundle_filename
_write_deterministic_zip_member = _report_bundle._write_deterministic_zip_member
render_evidence_bundle_zip = _report_bundle.render_evidence_bundle_zip
verify_evidence_bundle_archive = _report_bundle.verify_evidence_bundle_archive


def verify_evidence_bundle_zip(
    bundle_path: Path,
    *,
    display_path: str | None = None,
) -> dict[str, Any]:
    """Verify evidence bundles while preserving facade-level test overrides."""
    original = _report_bundle.verify_evidence_bundle_archive
    _report_bundle.verify_evidence_bundle_archive = verify_evidence_bundle_archive
    try:
        return _report_bundle.verify_evidence_bundle_zip(
            bundle_path,
            display_path=display_path,
        )
    finally:
        _report_bundle.verify_evidence_bundle_archive = original


# fmt: off
__all__ = [
    "Counter", "EXECUTIVE_REPORT_CSS", "_actionability_summary", "_analysis_finding", "_analysis_provider_snapshot", "_asset_context_rows", "_asset_label", "_boolish_signal", "_bundle_file_entry", "_bundle_input_hashes", "_business_impact_summary", "_component_label", "_counts_by_priority", "_data_quality_confidence", "_data_quality_flags", "_decision_guidance", "_decision_guidance_from_payload", "_decision_sla", "_decision_statement", "_decision_text", "_dict_list", "_executive_summary_text", "_finding_payload", "_flag_items", "_get_remediation_campaigns", "_governance_asset_context_export", "_governance_bundle_entries", "_governance_decision_statement", "_governance_detail_clause", "_governance_detection_coverage_export", "_governance_finding_row", "_governance_rollups_export", "_governance_vex_export", "_governance_vex_summary", "_governance_waivers_export",
    "_html_asset_rollup_row", "_html_governance_rollups", "_html_metric", "_html_provider_snapshot", "_html_service_rollup_row", "_html_top_risk_row", "_html_waiver_debt_row", "_json_bytes", "_list_value", "_markdown_detection_coverage_section", "_markdown_governance_section", "_occurrence_payload", "_priority_label", "_provider_freshness_rows", "_provider_freshness_status", "_provider_snapshot_payload", "_redact_bundle_value", "_redacted_bundle_payload", "_safe_bundle_filename", "_string_from_mapping", "_vex_status_counts_from_explanation", "_vex_statuses_label", "_vex_statuses_label_from_explanation", "_vulnerability_payload", "_write_deterministic_zip_member", "render_analysis_result_json", "render_evidence_bundle_zip", "render_findings_csv", "render_html_executive_report", "render_markdown_report", "safe_html", "verify_evidence_bundle_archive", "verify_evidence_bundle_zip",
]
# fmt: on

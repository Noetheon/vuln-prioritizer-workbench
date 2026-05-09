"""Report generation facade and terminal rendering."""
# ruff: noqa: F401,F403,F405,I001,E501

from __future__ import annotations

# ruff: noqa: F403

from vuln_prioritizer.reporting_html import generate_html_report
from vuln_prioritizer.reporting_io import write_output
from vuln_prioritizer.reporting_markdown import (
    generate_compare_markdown,
    generate_explain_markdown,
    generate_markdown_report,
)
from vuln_prioritizer.reporting_payloads import (
    build_analysis_report_payload,
    build_snapshot_report_payload,
    generate_compare_json,
    generate_doctor_json,
    generate_evidence_bundle_manifest_json,
    generate_evidence_bundle_verification_json,
    generate_explain_json,
    generate_json_report,
    generate_rollup_json,
    generate_sarif_report,
    generate_snapshot_diff_json,
    generate_state_history_json,
    generate_state_import_json,
    generate_state_init_json,
    generate_state_service_history_json,
    generate_state_top_services_json,
    generate_state_trends_json,
    generate_state_waivers_json,
    generate_summary_markdown,
)
from vuln_prioritizer.reporting_snapshot import (
    generate_rollup_markdown,
    generate_snapshot_diff_markdown,
    render_rollup_table,
    render_snapshot_diff_table,
)
from vuln_prioritizer.reporting_state import (
    render_state_history_table,
    render_state_import_panel,
    render_state_init_panel,
    render_state_service_history_table,
    render_state_top_services_table,
    render_state_trends_table,
    render_state_waivers_table,
)
from vuln_prioritizer.reporting_terminal import (
    render_compare_table,
    render_evidence_bundle_verification_table,
    render_explain_view,
    render_findings_table,
    render_summary_panel,
)

__all__ = [
    "build_analysis_report_payload",
    "build_snapshot_report_payload",
    "generate_compare_json",
    "generate_compare_markdown",
    "generate_doctor_json",
    "generate_evidence_bundle_manifest_json",
    "generate_evidence_bundle_verification_json",
    "generate_explain_json",
    "generate_explain_markdown",
    "generate_html_report",
    "generate_json_report",
    "generate_markdown_report",
    "generate_rollup_json",
    "generate_rollup_markdown",
    "generate_sarif_report",
    "generate_snapshot_diff_json",
    "generate_snapshot_diff_markdown",
    "generate_state_history_json",
    "generate_state_import_json",
    "generate_state_init_json",
    "generate_state_service_history_json",
    "generate_state_top_services_json",
    "generate_state_trends_json",
    "generate_state_waivers_json",
    "generate_summary_markdown",
    "render_compare_table",
    "render_evidence_bundle_verification_table",
    "render_explain_view",
    "render_findings_table",
    "render_rollup_table",
    "render_snapshot_diff_table",
    "render_state_history_table",
    "render_state_import_panel",
    "render_state_init_panel",
    "render_state_service_history_table",
    "render_state_top_services_table",
    "render_state_trends_table",
    "render_state_waivers_table",
    "render_summary_panel",
    "write_output",
]

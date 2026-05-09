"""Executive report section and HTML fragment rendering facade."""
# ruff: noqa: F401,F403,F405,I001,E501

from __future__ import annotations

# ruff: noqa: F403

from vuln_prioritizer.reporting_executive_sections_charts import *
from vuln_prioritizer.reporting_executive_sections_chrome import *
from vuln_prioritizer.reporting_executive_sections_components import *
from vuln_prioritizer.reporting_executive_sections_evidence import *
from vuln_prioritizer.reporting_executive_sections_summary import *
from vuln_prioritizer.reporting_executive_sections_top import *

__all__ = [
    "_artifact_row",
    "_asset_signal_panel",
    "_attack_asset_matrix_html",
    "_attack_context_section",
    "_attack_heatmap",
    "_attack_mapped_findings_table",
    "_attack_value_items",
    "_bar_row",
    "_business_exposure_panel",
    "_compact_findings_table",
    "_coverage_average",
    "_coverage_card",
    "_coverage_row",
    "_decision_item",
    "_decision_principles_html",
    "_detail_pair",
    "_detection_coverage_html",
    "_distribution_rows",
    "_driver_row",
    "_evidence_contents_html",
    "_evidence_section",
    "_finding_dossiers_html",
    "_finding_table_row",
    "_focus_cards_html",
    "_governance_state_html",
    "_input_sources_html",
    "_kpi_card",
    "_leadership_items",
    "_mapping_confidence_html",
    "_method_card",
    "_mini_metric",
    "_missing_context_html",
    "_nav_icon_svg",
    "_nav_link",
    "_next_steps_html",
    "_overview_section",
    "_owner_action_table",
    "_pipeline_html",
    "_prioritization_flow_html",
    "_priority_findings_section",
    "_priority_interpretation_html",
    "_provider_cards_html",
    "_provider_freshness_table",
    "_provider_transparency_html",
    "_quadrant_scatter_svg",
    "_quality_matrix_html",
    "_quality_notes_html",
    "_ranked_finding_bars",
    "_remediation_priority_chart",
    "_remediation_section",
    "_risk_posture_section",
    "_rollup_panel",
    "_scatter_point_insight",
    "_scatter_svg",
    "_severity_signal_chart",
    "_shield_logo_svg",
    "_signal_donut",
    "_status_segment",
    "_summary_item",
    "_summary_items",
    "_technique_strip_html",
    "_threshold_legend_html",
    "_ttp_chain",
    "_waterfall_html",
    "_workspace_app_header_html",
    "_workspace_nav_html",
    "_workspace_nav_icon",
]

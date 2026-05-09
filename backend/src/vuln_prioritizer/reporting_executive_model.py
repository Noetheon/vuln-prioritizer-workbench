"""Executive report view model construction facade."""
# ruff: noqa: F401,F403,F405,I001,E501

from __future__ import annotations

# ruff: noqa: F403

from collections import Counter as Counter

# fmt: off
from vuln_prioritizer.reporting_executive_model_attack import _attack_asset_matrix_model, _attack_model, _attack_top_mapped_findings, _detection_coverage_model, _related_tactic_count
from vuln_prioritizer.reporting_executive_model_builder import build_executive_report_model
from vuln_prioritizer.reporting_executive_model_evidence import _artifact_model, _bundle_contents_model, _evidence_model, _input_sources_model, _mapping_confidence_model, _methodology_model, _provider_freshness_rows, _provider_transparency_model, _quality_rows, _workspace_nav
from vuln_prioritizer.reporting_executive_model_findings import _finding_dossier_model, _finding_row
from vuln_prioritizer.reporting_executive_model_helpers import _asset_counter, _attack_finding_notes, _counter_rows, _criticality_rank, _distribution_counter, _distribution_model, _executive_summary, _finding_asset, _finding_criticality, _finding_decision_guidance, _finding_decision_statement, _finding_decision_template, _finding_exposure, _finding_owner, _finding_service, _finding_signal_score, _finding_sla_label, _finding_sort_key, _first_occurrence_field, _kev_due_date, _kpi, _kpi_value, _occurrences, _owner_counter, _priority_counts, _provider_evidence_notes, _route_label, _service_counter, _status, _status_label, _vex_status
from vuln_prioritizer.reporting_executive_model_overview import _asset_risk_rows, _business_exposure_model, _kpis, _overview_metrics, _priority_distribution, _priority_interpretation, _priority_kpis, _provider_cards, _risk_driver_model, _scatter_points, _severity_signal_rows, _source_coverage
from vuln_prioritizer.reporting_executive_model_remediation import _focus_cards, _governance_model, _missing_context_model, _next_step_rows, _owner_action_rows, _priority_status_rows, _remediation_model
# fmt: on

# fmt: off
__all__ = [
    "Counter", "_artifact_model", "_asset_counter", "_asset_risk_rows", "_attack_asset_matrix_model", "_attack_finding_notes", "_attack_model", "_attack_top_mapped_findings", "_bundle_contents_model", "_business_exposure_model", "_counter_rows", "_criticality_rank", "_detection_coverage_model", "_distribution_counter", "_distribution_model", "_evidence_model", "_executive_summary", "_finding_asset", "_finding_criticality", "_finding_decision_guidance", "_finding_decision_statement", "_finding_decision_template", "_finding_dossier_model", "_finding_exposure", "_finding_owner", "_finding_row", "_finding_service", "_finding_signal_score", "_finding_sla_label", "_finding_sort_key", "_first_occurrence_field", "_focus_cards", "_governance_model",
    "_input_sources_model", "_kev_due_date", "_kpi", "_kpi_value", "_kpis", "_mapping_confidence_model", "_methodology_model", "_missing_context_model", "_next_step_rows", "_occurrences", "_overview_metrics", "_owner_action_rows", "_owner_counter", "_priority_counts", "_priority_distribution", "_priority_interpretation", "_priority_kpis", "_priority_status_rows", "_provider_cards", "_provider_evidence_notes", "_provider_freshness_rows", "_provider_transparency_model", "_quality_rows", "_related_tactic_count", "_remediation_model", "_risk_driver_model", "_route_label", "_scatter_points", "_service_counter", "_severity_signal_rows", "_source_coverage", "_status", "_status_label", "_vex_status", "_workspace_nav", "build_executive_report_model",
]
# fmt: on

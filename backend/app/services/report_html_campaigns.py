"""Compatibility facade for remediation campaign report helpers."""

from __future__ import annotations

from app.services.report_html_campaign_model import (
    CVE_ALIASES,
    _business_service_view_rows,
    _campaign_base_key,
    _campaign_decision_statement,
    _campaign_evidence_label,
    _campaign_group_key,
    _campaign_ranking_rationale,
    _campaign_requires_emergency,
    _campaign_scope_summary,
    _campaign_sort_key,
    _campaigns_label,
    _component_family,
    _evidence_signal_summary,
    _first_available_owner,
    _get_remediation_campaigns_helper,
    _normalized_campaign_action,
    _priority_class_for_campaign,
    _recommendation_view_rows,
)
from app.services.report_html_campaign_rendering import (
    _executive_verdict_summary_helper,
    _html_business_impact_table_helper,
    _html_business_services_prose_helper,
    _html_deduplicated_recommendations_helper,
    _html_evidence_signals_badges,
    _html_remediation_campaigns_helper,
)

__all__ = [
    "CVE_ALIASES",
    "_campaign_ranking_rationale",
    "_campaign_scope_summary",
    "_evidence_signal_summary",
    "_campaign_requires_emergency",
    "_campaign_decision_statement",
    "_first_available_owner",
    "_normalized_campaign_action",
    "_component_family",
    "_campaign_base_key",
    "_campaign_group_key",
    "_priority_class_for_campaign",
    "_campaign_sort_key",
    "_get_remediation_campaigns_helper",
    "_campaigns_label",
    "_campaign_evidence_label",
    "_business_service_view_rows",
    "_recommendation_view_rows",
    "_html_evidence_signals_badges",
    "_executive_verdict_summary_helper",
    "_html_business_services_prose_helper",
    "_html_business_impact_table_helper",
    "_html_remediation_campaigns_helper",
    "_html_deduplicated_recommendations_helper",
]

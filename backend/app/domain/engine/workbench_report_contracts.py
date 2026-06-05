"""Shared Workbench report contract constants used by API renderers."""

from __future__ import annotations

CSV_FINDINGS_COLUMNS = [
    "cve_id",
    "priority",
    "status",
    "kev",
    "epss",
    "cvss",
    "data_quality_confidence",
    "data_quality_flags",
    "component",
    "asset",
    "owner",
    "service",
    "vex_statuses",
    "suppressed_by_vex",
    "under_investigation",
    "waived",
    "waiver_status",
    "waiver_owner",
    "waiver_expires_on",
    "waiver_review_on",
    "attack_mapped",
    "attack_techniques",
    "defensive_context_sources",
    "decision_recommendation",
    "decision_sla",
    "decision_statement",
    "business_impact",
    "recommended_action",
]

__all__ = ["CSV_FINDINGS_COLUMNS"]

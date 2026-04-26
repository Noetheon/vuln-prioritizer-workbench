"""CLI-independent analysis orchestration facade."""

from __future__ import annotations

from vuln_prioritizer.services.analysis_attack import (
    build_attack_summary_from_findings,
    resolve_attack_options,
)
from vuln_prioritizer.services.analysis_filters import (
    PRIORITY_LABELS,
    build_active_filters,
    normalize_priority_filters,
)
from vuln_prioritizer.services.analysis_inputs import (
    load_asset_records_or_exit,
    load_context_profile_or_exit,
    load_provider_snapshot_or_exit,
    load_vex_statements_or_exit,
    load_waiver_rules_or_exit,
)
from vuln_prioritizer.services.analysis_models import (
    AnalysisInputError,
    AnalysisNoFindingsError,
    AnalysisRequest,
    ExplainRequest,
    ExplainResult,
    _enum_value,
    build_priority_policy,
)
from vuln_prioritizer.services.analysis_pipeline import (
    build_findings,
    prepare_analysis,
    prepare_explain,
    prepare_saved_explain,
    validate_requested_attack_mode,
)
from vuln_prioritizer.services.analysis_provider import (
    _parse_provider_timestamp,
    _provider_source_freshness_at,
    build_data_sources,
    build_provider_diagnostics,
    build_provider_freshness,
    count_epss_hits,
    count_kev_hits,
    count_nvd_hits,
    provider_degraded,
    stale_provider_sources,
)

__all__ = [
    "build_attack_summary_from_findings",
    "resolve_attack_options",
    "PRIORITY_LABELS",
    "build_active_filters",
    "normalize_priority_filters",
    "load_asset_records_or_exit",
    "load_context_profile_or_exit",
    "load_provider_snapshot_or_exit",
    "load_vex_statements_or_exit",
    "load_waiver_rules_or_exit",
    "AnalysisInputError",
    "AnalysisNoFindingsError",
    "AnalysisRequest",
    "ExplainRequest",
    "ExplainResult",
    "_enum_value",
    "build_priority_policy",
    "build_findings",
    "prepare_analysis",
    "prepare_explain",
    "prepare_saved_explain",
    "validate_requested_attack_mode",
    "_parse_provider_timestamp",
    "_provider_source_freshness_at",
    "build_data_sources",
    "build_provider_diagnostics",
    "build_provider_freshness",
    "count_epss_hits",
    "count_kev_hits",
    "count_nvd_hits",
    "provider_degraded",
    "stale_provider_sources",
]

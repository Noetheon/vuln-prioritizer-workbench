"""Runtime-independent analysis orchestration facade."""

from __future__ import annotations

from vuln_prioritizer.services.analysis_attack import (
    build_attack_summary_from_findings,
    resolve_attack_options,
)
from vuln_prioritizer.services.analysis_explain import (
    prepare_explain,
    prepare_saved_explain,
)
from vuln_prioritizer.services.analysis_filters import (
    PRIORITY_LABELS,
    build_active_filters,
    normalize_priority_filters,
)
from vuln_prioritizer.services.analysis_findings import (
    build_findings,
    validate_requested_attack_mode,
)
from vuln_prioritizer.services.analysis_inputs import (
    load_analysis_context_profile,
    load_analysis_provider_snapshot,
    load_analysis_waiver_rules,
    load_asset_records,
    load_vex_statements,
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
    prepare_analysis,
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
    "load_analysis_context_profile",
    "load_analysis_provider_snapshot",
    "load_analysis_waiver_rules",
    "load_asset_records",
    "load_vex_statements",
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

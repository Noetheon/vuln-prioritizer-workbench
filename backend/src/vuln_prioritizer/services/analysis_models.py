"""Analysis request/result models and public errors."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from vuln_prioritizer.inputs import (
    InputSpec,
)
from vuln_prioritizer.models import (
    AnalysisContext,
    AttackData,
    ComparisonFinding,
    EpssData,
    KevData,
    NvdData,
    PrioritizedFinding,
    PriorityPolicy,
)


class AnalysisInputError(ValueError):
    """Raised when analysis input cannot be accepted."""


class AnalysisNoFindingsError(RuntimeError):
    """Raised when analysis completed without any finding to render."""


def _enum_value(value: StrEnum | str) -> str:
    return value.value if isinstance(value, StrEnum) else value


@dataclass(frozen=True)
class AnalysisRequest:
    input_specs: list[InputSpec]
    output: Path | None
    format: StrEnum | str
    provider_snapshot_file: Path | None
    locked_provider_data: bool
    no_attack: bool
    attack_source: StrEnum | str
    attack_mapping_file: Path | None
    attack_technique_metadata_file: Path | None
    offline_attack_file: Path | None
    defensive_context_file: Path | None
    priority_filters: Sequence[StrEnum | str] | None
    kev_only: bool
    min_cvss: float | None
    min_epss: float | None
    sort_by: StrEnum | str
    policy: PriorityPolicy
    policy_profile: str
    policy_file: Path | None
    waiver_file: Path | None
    asset_context: Path | None
    target_kind: str
    target_ref: str | None
    vex_files: list[Path]
    show_suppressed: bool
    hide_waived: bool
    fail_on_provider_error: bool
    max_cves: int | None
    offline_kev_file: Path | None
    nvd_api_key_env: str
    no_cache: bool
    cache_dir: Path
    cache_ttl_hours: int
    max_provider_age_hours: int | None = None
    fail_on_stale_provider_data: bool = False


@dataclass(frozen=True)
class ExplainRequest:
    cve_id: str
    output: Path | None
    format: StrEnum | str
    provider_snapshot_file: Path | None
    locked_provider_data: bool
    no_attack: bool
    attack_source: StrEnum | str
    attack_mapping_file: Path | None
    attack_technique_metadata_file: Path | None
    policy: PriorityPolicy
    policy_profile: str
    policy_file: Path | None
    waiver_file: Path | None
    asset_context: Path | None
    target_kind: str
    target_ref: str | None
    vex_files: list[Path]
    show_suppressed: bool
    fail_on_provider_error: bool
    offline_kev_file: Path | None
    offline_attack_file: Path | None
    defensive_context_file: Path | None
    nvd_api_key_env: str
    no_cache: bool
    cache_dir: Path
    cache_ttl_hours: int


@dataclass(frozen=True)
class ExplainResult:
    finding: PrioritizedFinding
    nvd: NvdData
    epss: EpssData
    kev: KevData
    attack: AttackData
    comparison: ComparisonFinding
    context: AnalysisContext
    warnings: list[str]


def build_priority_policy(
    *,
    critical_epss_threshold: float,
    critical_cvss_threshold: float,
    high_epss_threshold: float,
    high_cvss_threshold: float,
    medium_epss_threshold: float,
    medium_cvss_threshold: float,
) -> PriorityPolicy:
    try:
        return PriorityPolicy(
            critical_epss_threshold=critical_epss_threshold,
            critical_cvss_threshold=critical_cvss_threshold,
            high_epss_threshold=high_epss_threshold,
            high_cvss_threshold=high_cvss_threshold,
            medium_epss_threshold=medium_epss_threshold,
            medium_cvss_threshold=medium_cvss_threshold,
        )
    except ValueError as exc:
        raise AnalysisInputError(str(exc)) from exc

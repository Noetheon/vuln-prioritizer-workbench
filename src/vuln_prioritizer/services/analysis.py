"""CLI-independent analysis orchestration."""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, cast

from pydantic import ValidationError

from vuln_prioritizer.attack_sources import (
    ATTACK_SOURCE_CTID_JSON,
    ATTACK_SOURCE_CTID_MAPPINGS_EXPLORER,
    ATTACK_SOURCE_LOCAL_CSV,
    ATTACK_SOURCE_NONE,
)
from vuln_prioritizer.config import DATA_SOURCES
from vuln_prioritizer.inputs import (
    InputLoader,
    InputSpec,
    build_inline_input,
    load_asset_context_file,
    load_vex_files,
)
from vuln_prioritizer.inputs.loader import AssetContextCatalog
from vuln_prioritizer.models import (
    AnalysisContext,
    AttackData,
    AttackSummary,
    ComparisonFinding,
    ContextPolicyProfile,
    EnrichmentResult,
    EpssData,
    KevData,
    NvdData,
    ParsedInput,
    PrioritizedFinding,
    PriorityPolicy,
    ProviderLookupDiagnostics,
    ProviderSnapshotReport,
    VexStatement,
    WaiverRule,
)
from vuln_prioritizer.provider_snapshot import load_provider_snapshot
from vuln_prioritizer.providers.nvd import has_nvd_content
from vuln_prioritizer.services.attack_enrichment import AttackEnrichmentService
from vuln_prioritizer.services.contextualization import (
    aggregate_provenance,
    load_context_profile,
)
from vuln_prioritizer.services.enrichment import EnrichmentService
from vuln_prioritizer.services.prioritization import PrioritizationService, SortField
from vuln_prioritizer.services.waivers import (
    apply_waivers,
    load_waiver_rules,
)
from vuln_prioritizer.utils import iso_utc_now

PRIORITY_LABELS = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
}


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


def load_asset_records_or_exit(
    asset_context: Path | None,
) -> AssetContextCatalog:
    try:
        return load_asset_context_file(asset_context)
    except ValueError as exc:
        raise AnalysisInputError(str(exc)) from exc


def load_vex_statements_or_exit(vex_files: list[Path]) -> list[VexStatement]:
    try:
        return load_vex_files(vex_files)
    except ValueError as exc:
        raise AnalysisInputError(str(exc)) from exc


def load_waiver_rules_or_exit(waiver_file: Path | None) -> list[WaiverRule]:
    try:
        return load_waiver_rules(waiver_file)
    except ValueError as exc:
        raise AnalysisInputError(str(exc)) from exc


def load_context_profile_or_exit(
    policy_profile: str,
    policy_file: Path | None,
) -> ContextPolicyProfile:
    try:
        return load_context_profile(policy_profile, policy_file)
    except ValueError as exc:
        raise AnalysisInputError(str(exc)) from exc


def load_provider_snapshot_or_exit(path: Path | None) -> ProviderSnapshotReport | None:
    if path is None:
        return None
    try:
        return load_provider_snapshot(path)
    except ValueError as exc:
        raise AnalysisInputError(str(exc)) from exc


def resolve_attack_options(
    *,
    no_attack: bool,
    attack_source: StrEnum | str,
    attack_mapping_file: Path | None,
    attack_technique_metadata_file: Path | None,
    offline_attack_file: Path | None,
) -> tuple[bool, str, Path | None, Path | None]:
    attack_source_value = _enum_value(attack_source)
    if no_attack:
        return False, ATTACK_SOURCE_NONE, None, None

    if attack_source_value == ATTACK_SOURCE_NONE:
        if offline_attack_file is not None:
            return True, ATTACK_SOURCE_LOCAL_CSV, offline_attack_file, None
        if attack_mapping_file is not None:
            return (
                True,
                ATTACK_SOURCE_CTID_JSON,
                attack_mapping_file,
                attack_technique_metadata_file,
            )
        return False, ATTACK_SOURCE_NONE, None, None

    if attack_source_value == ATTACK_SOURCE_LOCAL_CSV:
        return True, attack_source_value, attack_mapping_file or offline_attack_file, None

    return (
        True,
        attack_source_value,
        attack_mapping_file or offline_attack_file,
        attack_technique_metadata_file,
    )


def count_nvd_hits(enrichment: EnrichmentResult) -> int:
    return sum(1 for item in enrichment.nvd.values() if has_nvd_content(item))


def count_epss_hits(enrichment: EnrichmentResult) -> int:
    return sum(
        1
        for item in enrichment.epss.values()
        if item.epss is not None or item.percentile is not None or item.date is not None
    )


def count_kev_hits(enrichment: EnrichmentResult) -> int:
    return sum(1 for item in enrichment.kev.values() if item.in_kev)


def build_attack_summary_from_findings(findings: list[PrioritizedFinding]) -> AttackSummary:
    attack_items: list[AttackData] = []
    for finding in findings:
        mapping_types: list[str] = []
        capability_groups: list[str] = []
        for mapping in finding.attack_mappings:
            if mapping.mapping_type and mapping.mapping_type not in mapping_types:
                mapping_types.append(mapping.mapping_type)
            if mapping.capability_group and mapping.capability_group not in capability_groups:
                capability_groups.append(mapping.capability_group)
        attack_items.append(
            AttackData(
                cve_id=finding.cve_id,
                mapped=finding.attack_mapped,
                mappings=finding.attack_mappings,
                techniques=finding.attack_technique_details,
                mapping_types=mapping_types,
                capability_groups=capability_groups,
                attack_techniques=finding.attack_techniques,
                attack_tactics=finding.attack_tactics,
                attack_relevance=finding.attack_relevance,
            )
        )
    return AttackEnrichmentService().summarize(attack_items)


def build_data_sources(enrichment: EnrichmentResult) -> list[str]:
    sources = list(DATA_SOURCES)
    if enrichment.provider_snapshot_sources:
        sources.append(
            "Provider snapshot replay: " + ", ".join(sorted(enrichment.provider_snapshot_sources))
        )
    if enrichment.attack_source == ATTACK_SOURCE_CTID_MAPPINGS_EXPLORER:
        sources.append("CTID Mappings Explorer (local JSON artifact)")
    elif enrichment.attack_source == ATTACK_SOURCE_LOCAL_CSV:
        sources.append("Local ATT&CK CSV mapping")
    parsed_input = enrichment.parsed_input
    if parsed_input.source_stats:
        sources.append("Input formats: " + ", ".join(sorted(parsed_input.source_stats)))
    return sources


def normalize_priority_filters(priority_filters: Sequence[StrEnum | str] | None) -> set[str]:
    if not priority_filters:
        return set()
    return {PRIORITY_LABELS[_enum_value(item)] for item in priority_filters}


def build_active_filters(
    *,
    priority_filters: Sequence[StrEnum | str] | None,
    kev_only: bool,
    min_cvss: float | None,
    min_epss: float | None,
    show_suppressed: bool = False,
    hide_waived: bool = False,
) -> list[str]:
    active_filters: list[str] = []

    if priority_filters:
        ordered_labels = []
        for item in priority_filters:
            label = PRIORITY_LABELS[_enum_value(item)]
            if label not in ordered_labels:
                ordered_labels.append(label)
        active_filters.append("priority=" + ",".join(ordered_labels))
    if kev_only:
        active_filters.append("kev-only")
    if min_cvss is not None:
        active_filters.append(f"min-cvss>={min_cvss:.1f}")
    if min_epss is not None:
        active_filters.append(f"min-epss>={min_epss:.3f}")
    if show_suppressed:
        active_filters.append("show-suppressed")
    if hide_waived:
        active_filters.append("hide-waived")

    return active_filters


def validate_requested_attack_mode(
    *,
    attack_enabled: bool,
    attack_source: str,
    attack_mapping_file: Path | None,
    offline_attack_file: Path | None,
) -> None:
    if not attack_enabled or attack_source == ATTACK_SOURCE_NONE:
        return
    if attack_mapping_file is not None or offline_attack_file is not None:
        return
    raise AnalysisInputError(
        "ATT&CK mode requires --attack-mapping-file or legacy --offline-attack-file."
    )


def build_provider_diagnostics(
    enrichment: EnrichmentResult,
) -> dict[str, ProviderLookupDiagnostics]:
    return {
        "nvd": enrichment.nvd_diagnostics,
        "epss": enrichment.epss_diagnostics,
        "kev": enrichment.kev_diagnostics,
    }


def provider_degraded(enrichment: EnrichmentResult) -> bool:
    return any(
        diagnostics.degraded or diagnostics.failures > 0
        for diagnostics in (
            enrichment.nvd_diagnostics,
            enrichment.epss_diagnostics,
            enrichment.kev_diagnostics,
        )
    )


def build_provider_freshness(
    enrichment: EnrichmentResult,
) -> dict[str, str | int | float | bool | None]:
    nvd_last_modified = sorted(
        item.last_modified for item in enrichment.nvd.values() if item.last_modified
    )
    epss_dates = sorted(item.date for item in enrichment.epss.values() if item.date)
    kev_date_added = sorted(item.date_added for item in enrichment.kev.values() if item.date_added)
    kev_due_dates = sorted(item.due_date for item in enrichment.kev.values() if item.due_date)
    return {
        "nvd_last_modified_min": nvd_last_modified[0] if nvd_last_modified else None,
        "nvd_last_modified_max": nvd_last_modified[-1] if nvd_last_modified else None,
        "latest_epss_date": epss_dates[-1] if epss_dates else None,
        "kev_date_added_max": kev_date_added[-1] if kev_date_added else None,
        "kev_due_date_min": kev_due_dates[0] if kev_due_dates else None,
    }


def build_findings(
    cve_ids: list[str],
    *,
    policy: PriorityPolicy,
    parsed_input: ParsedInput,
    context_profile: ContextPolicyProfile,
    attack_enabled: bool,
    attack_source: str,
    attack_mapping_file: Path | None,
    attack_technique_metadata_file: Path | None,
    offline_kev_file: Path | None,
    offline_attack_file: Path | None,
    nvd_api_key_env: str,
    no_cache: bool,
    cache_dir: Path,
    cache_ttl_hours: int,
    provider_snapshot: ProviderSnapshotReport | None = None,
    locked_provider_data: bool = False,
) -> tuple[list[PrioritizedFinding], dict[str, int], EnrichmentResult]:
    validate_requested_attack_mode(
        attack_enabled=attack_enabled,
        attack_source=attack_source,
        attack_mapping_file=attack_mapping_file,
        offline_attack_file=offline_attack_file,
    )
    enricher = EnrichmentService(
        nvd_api_key_env=nvd_api_key_env,
        use_cache=not no_cache,
        cache_dir=cache_dir,
        cache_ttl_hours=cache_ttl_hours,
    )
    try:
        enrichment = enricher.enrich(
            cve_ids,
            attack_enabled=attack_enabled,
            attack_source=attack_source,
            offline_kev_file=offline_kev_file,
            attack_mapping_file=attack_mapping_file,
            attack_technique_metadata_file=attack_technique_metadata_file,
            offline_attack_file=offline_attack_file,
            provider_snapshot=provider_snapshot,
            locked_provider_data=locked_provider_data,
        )
    except (OSError, ValidationError, ValueError) as exc:
        raise AnalysisInputError(str(exc)) from exc
    enrichment.parsed_input = parsed_input
    provenance_by_cve = aggregate_provenance(parsed_input.unique_cves, parsed_input.occurrences)

    prioritizer = PrioritizationService(policy=policy)
    findings, counts = prioritizer.prioritize(
        cve_ids,
        nvd_data=enrichment.nvd,
        epss_data=enrichment.epss,
        kev_data=enrichment.kev,
        attack_data=enrichment.attack,
        provenance_by_cve=provenance_by_cve,
        context_profile=context_profile,
    )
    return findings, counts, enrichment


def prepare_analysis(request: AnalysisRequest) -> tuple[list[PrioritizedFinding], AnalysisContext]:
    attack_enabled, resolved_attack_source, resolved_mapping_file, resolved_metadata_file = (
        resolve_attack_options(
            no_attack=request.no_attack,
            attack_source=request.attack_source,
            attack_mapping_file=request.attack_mapping_file,
            attack_technique_metadata_file=request.attack_technique_metadata_file,
            offline_attack_file=request.offline_attack_file,
        )
    )
    try:
        asset_records = load_asset_records_or_exit(request.asset_context)
        vex_statements = load_vex_statements_or_exit(request.vex_files)
        if request.locked_provider_data and request.provider_snapshot_file is None:
            raise AnalysisInputError("--locked-provider-data requires --provider-snapshot-file.")
        provider_snapshot = load_provider_snapshot_or_exit(request.provider_snapshot_file)
        parsed_input = InputLoader().load_many(
            request.input_specs,
            max_cves=request.max_cves,
            target_kind=request.target_kind,
            target_ref=request.target_ref,
            asset_records=asset_records,
            vex_statements=vex_statements,
        )
    except (ValidationError, ValueError) as exc:
        raise AnalysisInputError(str(exc)) from exc

    cve_ids = parsed_input.unique_cves
    context_profile = load_context_profile_or_exit(request.policy_profile, request.policy_file)
    waiver_rules = load_waiver_rules_or_exit(request.waiver_file)
    all_findings, _, enrichment = build_findings(
        cve_ids,
        policy=request.policy,
        parsed_input=parsed_input,
        context_profile=context_profile,
        attack_enabled=attack_enabled,
        attack_source=resolved_attack_source,
        attack_mapping_file=resolved_mapping_file,
        attack_technique_metadata_file=resolved_metadata_file,
        offline_kev_file=request.offline_kev_file,
        offline_attack_file=request.offline_attack_file,
        nvd_api_key_env=request.nvd_api_key_env,
        no_cache=request.no_cache,
        cache_dir=request.cache_dir,
        cache_ttl_hours=request.cache_ttl_hours,
        provider_snapshot=provider_snapshot,
        locked_provider_data=request.locked_provider_data,
    )
    all_findings, waiver_warnings = apply_waivers(all_findings, waiver_rules)

    if not all_findings:
        raise AnalysisNoFindingsError("No findings could be generated from the provided CVEs.")

    prioritizer = PrioritizationService(policy=request.policy)
    all_findings = prioritizer.assign_operational_ranks(all_findings)
    normalized_priority_filters = normalize_priority_filters(request.priority_filters)
    filtered_findings = prioritizer.filter_findings(
        all_findings,
        priorities=normalized_priority_filters,
        kev_only=request.kev_only,
        min_cvss=request.min_cvss,
        min_epss=request.min_epss,
        show_suppressed=request.show_suppressed,
        hide_waived=request.hide_waived,
    )
    findings = prioritizer.sort_findings(
        filtered_findings,
        sort_by=cast(SortField, _enum_value(request.sort_by)),
    )
    warnings = parsed_input.warnings + enrichment.warnings + waiver_warnings
    attack_summary = build_attack_summary_from_findings(findings)

    context = AnalysisContext(
        input_path=(
            parsed_input.input_paths[0]
            if parsed_input.input_paths
            else str(request.input_specs[0].path)
        ),
        output_path=str(request.output) if request.output else None,
        output_format=_enum_value(request.format),
        generated_at=iso_utc_now(),
        input_format=parsed_input.input_format,
        input_paths=parsed_input.input_paths,
        input_sources=parsed_input.source_summaries,
        merged_input_count=parsed_input.merged_input_count,
        duplicate_cve_count=parsed_input.duplicate_cve_count,
        provider_snapshot_file=(
            str(request.provider_snapshot_file) if request.provider_snapshot_file else None
        ),
        locked_provider_data=request.locked_provider_data,
        provider_snapshot_sources=enrichment.provider_snapshot_sources,
        attack_enabled=attack_enabled,
        attack_source=enrichment.attack_source,
        attack_mapping_file=enrichment.attack_mapping_file,
        attack_technique_metadata_file=enrichment.attack_technique_metadata_file,
        attack_source_version=enrichment.attack_source_version,
        attack_version=enrichment.attack_version,
        attack_domain=enrichment.attack_domain,
        mapping_framework=enrichment.mapping_framework,
        mapping_framework_version=enrichment.mapping_framework_version,
        attack_mapping_file_sha256=enrichment.attack_mapping_file_sha256,
        attack_technique_metadata_file_sha256=(enrichment.attack_technique_metadata_file_sha256),
        attack_metadata_format=enrichment.attack_metadata_format,
        attack_metadata_source=enrichment.attack_metadata_source,
        attack_stix_spec_version=enrichment.attack_stix_spec_version,
        attack_mapping_created_at=enrichment.attack_mapping_created_at,
        attack_mapping_updated_at=enrichment.attack_mapping_updated_at,
        attack_mapping_organization=enrichment.attack_mapping_organization,
        attack_mapping_author=enrichment.attack_mapping_author,
        attack_mapping_contact=enrichment.attack_mapping_contact,
        warnings=warnings,
        total_input=parsed_input.total_rows,
        valid_input=len(cve_ids),
        occurrences_count=len(parsed_input.occurrences),
        findings_count=len(findings),
        filtered_out_count=max(len(all_findings) - len(findings), 0),
        nvd_hits=count_nvd_hits(enrichment),
        nvd_diagnostics=enrichment.nvd_diagnostics,
        epss_diagnostics=enrichment.epss_diagnostics,
        kev_diagnostics=enrichment.kev_diagnostics,
        provider_degraded=provider_degraded(enrichment),
        provider_diagnostics=build_provider_diagnostics(enrichment),
        provider_freshness=build_provider_freshness(enrichment),
        epss_hits=count_epss_hits(enrichment),
        kev_hits=count_kev_hits(enrichment),
        attack_hits=attack_summary.mapped_cves,
        suppressed_by_vex=sum(1 for item in all_findings if item.suppressed_by_vex),
        under_investigation_count=sum(1 for item in all_findings if item.under_investigation),
        asset_match_conflict_count=parsed_input.asset_match_conflict_count,
        vex_conflict_count=parsed_input.vex_conflict_count,
        waived_count=sum(1 for item in all_findings if item.waived),
        waiver_review_due_count=sum(
            1 for item in all_findings if item.waiver_status == "review_due"
        ),
        expired_waiver_count=sum(1 for item in all_findings if item.waiver_status == "expired"),
        attack_summary=attack_summary,
        active_filters=build_active_filters(
            priority_filters=request.priority_filters,
            kev_only=request.kev_only,
            min_cvss=request.min_cvss,
            min_epss=request.min_epss,
            show_suppressed=request.show_suppressed,
            hide_waived=request.hide_waived,
        ),
        policy_overrides=request.policy.override_descriptions(),
        priority_policy=request.policy,
        policy_profile=context_profile.name,
        policy_file=str(request.policy_file) if request.policy_file else None,
        waiver_file=str(request.waiver_file) if request.waiver_file else None,
        counts_by_priority=prioritizer.count_by_priority(findings),
        source_stats=parsed_input.source_stats,
        included_occurrence_count=parsed_input.included_occurrence_count,
        included_unique_cves=parsed_input.included_unique_cves,
        data_sources=build_data_sources(enrichment),
        cache_enabled=not request.no_cache,
        cache_dir=str(request.cache_dir) if not request.no_cache else None,
    )

    return findings, context


def prepare_explain(request: ExplainRequest) -> ExplainResult:
    context_profile = load_context_profile_or_exit(request.policy_profile, request.policy_file)
    if request.locked_provider_data and request.provider_snapshot_file is None:
        raise AnalysisInputError("--locked-provider-data requires --provider-snapshot-file.")
    provider_snapshot = load_provider_snapshot_or_exit(request.provider_snapshot_file)
    attack_enabled, resolved_attack_source, resolved_mapping_file, resolved_metadata_file = (
        resolve_attack_options(
            no_attack=request.no_attack,
            attack_source=request.attack_source,
            attack_mapping_file=request.attack_mapping_file,
            attack_technique_metadata_file=request.attack_technique_metadata_file,
            offline_attack_file=request.offline_attack_file,
        )
    )
    asset_records = load_asset_records_or_exit(request.asset_context)
    vex_statements = load_vex_statements_or_exit(request.vex_files)
    waiver_rules = load_waiver_rules_or_exit(request.waiver_file)
    parsed_input = build_inline_input(
        request.cve_id,
        target_kind=request.target_kind,
        target_ref=request.target_ref,
        asset_records=asset_records,
        vex_statements=vex_statements,
    )
    findings, counts, enrichment = build_findings(
        parsed_input.unique_cves,
        policy=request.policy,
        parsed_input=parsed_input,
        context_profile=context_profile,
        attack_enabled=attack_enabled,
        attack_source=resolved_attack_source,
        attack_mapping_file=resolved_mapping_file,
        attack_technique_metadata_file=resolved_metadata_file,
        offline_kev_file=request.offline_kev_file,
        offline_attack_file=request.offline_attack_file,
        nvd_api_key_env=request.nvd_api_key_env,
        no_cache=request.no_cache,
        cache_dir=request.cache_dir,
        cache_ttl_hours=request.cache_ttl_hours,
        provider_snapshot=provider_snapshot,
        locked_provider_data=request.locked_provider_data,
    )
    findings, waiver_warnings = apply_waivers(findings, waiver_rules)
    findings = PrioritizationService(policy=request.policy).assign_operational_ranks(findings)
    if not request.show_suppressed:
        findings = [finding for finding in findings if not finding.suppressed_by_vex]

    if not findings:
        raise AnalysisNoFindingsError("No finding could be generated for the requested CVE.")

    finding = findings[0]
    nvd = enrichment.nvd.get(request.cve_id, NvdData(cve_id=request.cve_id))
    epss = enrichment.epss.get(request.cve_id, EpssData(cve_id=request.cve_id))
    kev = enrichment.kev.get(request.cve_id, KevData(cve_id=request.cve_id, in_kev=False))
    attack = enrichment.attack.get(request.cve_id, AttackData(cve_id=request.cve_id))
    warnings = parsed_input.warnings + enrichment.warnings + waiver_warnings
    comparison = PrioritizationService(policy=request.policy).build_comparison([finding])[0]
    attack_summary = build_attack_summary_from_findings([finding])

    context = AnalysisContext(
        input_path=f"inline:{request.cve_id}",
        output_path=str(request.output) if request.output else None,
        output_format=_enum_value(request.format),
        generated_at=iso_utc_now(),
        provider_snapshot_file=(
            str(request.provider_snapshot_file) if request.provider_snapshot_file else None
        ),
        locked_provider_data=request.locked_provider_data,
        provider_snapshot_sources=enrichment.provider_snapshot_sources,
        attack_enabled=attack_enabled,
        attack_source=enrichment.attack_source,
        attack_mapping_file=enrichment.attack_mapping_file,
        attack_technique_metadata_file=enrichment.attack_technique_metadata_file,
        attack_source_version=enrichment.attack_source_version,
        attack_version=enrichment.attack_version,
        attack_domain=enrichment.attack_domain,
        mapping_framework=enrichment.mapping_framework,
        mapping_framework_version=enrichment.mapping_framework_version,
        attack_mapping_file_sha256=enrichment.attack_mapping_file_sha256,
        attack_technique_metadata_file_sha256=(enrichment.attack_technique_metadata_file_sha256),
        attack_metadata_format=enrichment.attack_metadata_format,
        attack_metadata_source=enrichment.attack_metadata_source,
        attack_stix_spec_version=enrichment.attack_stix_spec_version,
        attack_mapping_created_at=enrichment.attack_mapping_created_at,
        attack_mapping_updated_at=enrichment.attack_mapping_updated_at,
        attack_mapping_organization=enrichment.attack_mapping_organization,
        attack_mapping_author=enrichment.attack_mapping_author,
        attack_mapping_contact=enrichment.attack_mapping_contact,
        warnings=warnings,
        total_input=1,
        valid_input=1,
        occurrences_count=parsed_input.total_rows,
        findings_count=1,
        filtered_out_count=0,
        nvd_hits=count_nvd_hits(enrichment),
        nvd_diagnostics=enrichment.nvd_diagnostics,
        epss_diagnostics=enrichment.epss_diagnostics,
        kev_diagnostics=enrichment.kev_diagnostics,
        provider_degraded=provider_degraded(enrichment),
        provider_diagnostics=build_provider_diagnostics(enrichment),
        provider_freshness=build_provider_freshness(enrichment),
        epss_hits=count_epss_hits(enrichment),
        kev_hits=count_kev_hits(enrichment),
        attack_hits=attack_summary.mapped_cves,
        suppressed_by_vex=sum(1 for item in findings if item.suppressed_by_vex),
        under_investigation_count=sum(1 for item in findings if item.under_investigation),
        asset_match_conflict_count=parsed_input.asset_match_conflict_count,
        vex_conflict_count=parsed_input.vex_conflict_count,
        waived_count=sum(1 for item in findings if item.waived),
        waiver_review_due_count=sum(1 for item in findings if item.waiver_status == "review_due"),
        expired_waiver_count=sum(1 for item in findings if item.waiver_status == "expired"),
        attack_summary=attack_summary,
        policy_overrides=request.policy.override_descriptions(),
        priority_policy=request.policy,
        policy_profile=context_profile.name,
        policy_file=str(request.policy_file) if request.policy_file else None,
        waiver_file=str(request.waiver_file) if request.waiver_file else None,
        counts_by_priority=counts,
        source_stats=parsed_input.source_stats,
        included_occurrence_count=parsed_input.included_occurrence_count,
        included_unique_cves=parsed_input.included_unique_cves,
        input_format=parsed_input.input_format,
        data_sources=build_data_sources(enrichment),
        cache_enabled=not request.no_cache,
        cache_dir=str(request.cache_dir) if not request.no_cache else None,
    )

    return ExplainResult(
        finding=finding,
        nvd=nvd,
        epss=epss,
        kev=kev,
        attack=attack,
        comparison=comparison,
        context=context,
        warnings=warnings,
    )


def prepare_saved_explain(
    *,
    cve_id: str,
    input_path: Path,
    output: Path | None,
    format: StrEnum | str,
) -> ExplainResult:
    """Build an explain result from a saved analysis or snapshot JSON artifact."""
    try:
        payload = json.loads(input_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise AnalysisInputError(f"{input_path} could not be read: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise AnalysisInputError(f"{input_path} is not valid JSON: {exc.msg}.") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("findings"), list):
        raise AnalysisInputError("--analysis-json/--snapshot-json must contain a findings array.")

    finding_payload = next(
        (
            item
            for item in payload["findings"]
            if isinstance(item, dict) and item.get("cve_id") == cve_id
        ),
        None,
    )
    if finding_payload is None:
        raise AnalysisInputError(f"{input_path} does not contain a finding for {cve_id}.")

    try:
        finding = PrioritizedFinding.model_validate(finding_payload, extra="ignore")
        raw_metadata = payload.get("metadata")
        metadata: dict[str, Any] = (
            cast(dict[str, Any], raw_metadata) if isinstance(raw_metadata, dict) else {}
        )
        context = AnalysisContext.model_validate(
            {
                **metadata,
                "input_path": str(input_path),
                "output_path": str(output) if output else None,
                "output_format": _enum_value(format),
                "generated_at": metadata.get("generated_at") or iso_utc_now(),
                "findings_count": 1,
                "schema_version": "1.0.0",
            }
        )
        attack_summary = AttackSummary.model_validate(
            payload.get("attack_summary") or {},
            extra="ignore",
        )
        context = context.model_copy(update={"attack_summary": attack_summary})
    except ValidationError as exc:
        raise AnalysisInputError(f"{input_path} contains an invalid saved finding: {exc}") from exc

    evidence = finding.provider_evidence
    nvd = evidence.nvd if evidence is not None else NvdData(cve_id=cve_id)
    epss = evidence.epss if evidence is not None else EpssData(cve_id=cve_id)
    kev = evidence.kev if evidence is not None else KevData(cve_id=cve_id, in_kev=False)
    attack = AttackData(
        cve_id=cve_id,
        mapped=finding.attack_mapped,
        source=context.attack_source,
        source_version=context.attack_source_version,
        attack_version=context.attack_version,
        domain=context.attack_domain,
        mappings=finding.attack_mappings,
        techniques=finding.attack_technique_details,
        attack_relevance=finding.attack_relevance,
        attack_rationale=finding.attack_rationale,
        attack_techniques=finding.attack_techniques,
        attack_tactics=finding.attack_tactics,
        attack_note=finding.attack_note,
    )
    comparison = PrioritizationService(policy=context.priority_policy).build_comparison([finding])[
        0
    ]
    return ExplainResult(
        finding=finding,
        nvd=nvd,
        epss=epss,
        kev=kev,
        attack=attack,
        comparison=comparison,
        context=context,
        warnings=list(context.warnings),
    )

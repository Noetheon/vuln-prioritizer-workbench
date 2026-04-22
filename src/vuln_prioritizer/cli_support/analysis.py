"""Shared analysis-oriented CLI workflows."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

import typer
from pydantic import ValidationError

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
    ProviderSnapshotReport,
    VexStatement,
    WaiverRule,
)
from vuln_prioritizer.provider_snapshot import load_provider_snapshot
from vuln_prioritizer.services.attack_enrichment import AttackEnrichmentService
from vuln_prioritizer.services.contextualization import (
    aggregate_provenance,
    load_context_profile,
)
from vuln_prioritizer.services.enrichment import EnrichmentService
from vuln_prioritizer.services.prioritization import PrioritizationService
from vuln_prioritizer.services.waivers import (
    apply_waivers,
    load_waiver_rules,
)
from vuln_prioritizer.utils import iso_utc_now

from .common import (
    PRIORITY_LABELS,
    AttackSource,
    PriorityFilter,
    SortBy,
    console,
    exit_input_validation,
)


@dataclass(frozen=True)
class AnalysisRequest:
    input_specs: list[InputSpec]
    output: Path | None
    format: StrEnum
    provider_snapshot_file: Path | None
    locked_provider_data: bool
    no_attack: bool
    attack_source: AttackSource
    attack_mapping_file: Path | None
    attack_technique_metadata_file: Path | None
    offline_attack_file: Path | None
    priority_filters: list[PriorityFilter] | None
    kev_only: bool
    min_cvss: float | None
    min_epss: float | None
    sort_by: SortBy
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
    format: StrEnum
    provider_snapshot_file: Path | None
    locked_provider_data: bool
    no_attack: bool
    attack_source: AttackSource
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
        exit_input_validation(str(exc))
    raise AssertionError("unreachable")


def load_asset_records_or_exit(
    asset_context: Path | None,
) -> AssetContextCatalog:
    try:
        return load_asset_context_file(asset_context)
    except ValueError as exc:
        exit_input_validation(str(exc))
    raise AssertionError("unreachable")


def load_vex_statements_or_exit(vex_files: list[Path]) -> list[VexStatement]:
    try:
        return load_vex_files(vex_files)
    except ValueError as exc:
        exit_input_validation(str(exc))
    raise AssertionError("unreachable")


def load_waiver_rules_or_exit(waiver_file: Path | None) -> list[WaiverRule]:
    try:
        return load_waiver_rules(waiver_file)
    except ValueError as exc:
        exit_input_validation(str(exc))
    raise AssertionError("unreachable")


def load_context_profile_or_exit(
    policy_profile: str,
    policy_file: Path | None,
) -> ContextPolicyProfile:
    try:
        return load_context_profile(policy_profile, policy_file)
    except ValueError as exc:
        exit_input_validation(str(exc))
    raise AssertionError("unreachable")


def load_provider_snapshot_or_exit(path: Path | None) -> ProviderSnapshotReport | None:
    if path is None:
        return None
    try:
        return load_provider_snapshot(path)
    except ValueError as exc:
        exit_input_validation(str(exc))
    raise AssertionError("unreachable")


def resolve_attack_options(
    *,
    no_attack: bool,
    attack_source: AttackSource,
    attack_mapping_file: Path | None,
    attack_technique_metadata_file: Path | None,
    offline_attack_file: Path | None,
) -> tuple[bool, str, Path | None, Path | None]:
    if no_attack:
        return False, AttackSource.none.value, None, None

    if attack_source == AttackSource.none:
        if offline_attack_file is not None:
            return True, AttackSource.local_csv.value, offline_attack_file, None
        if attack_mapping_file is not None:
            return (
                True,
                AttackSource.ctid_json.value,
                attack_mapping_file,
                attack_technique_metadata_file,
            )
        return False, AttackSource.none.value, None, None

    if attack_source == AttackSource.local_csv:
        return True, attack_source.value, attack_mapping_file or offline_attack_file, None

    return (
        True,
        attack_source.value,
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
    if enrichment.attack_source == "ctid-mappings-explorer":
        sources.append("CTID Mappings Explorer (local JSON artifact)")
    elif enrichment.attack_source == "local-csv":
        sources.append("Local ATT&CK CSV mapping")
    parsed_input = enrichment.parsed_input
    if parsed_input.source_stats:
        sources.append("Input formats: " + ", ".join(sorted(parsed_input.source_stats)))
    return sources


def has_nvd_content(item: NvdData) -> bool:
    return any(
        [
            item.description is not None,
            item.cvss_base_score is not None,
            item.cvss_severity is not None,
            item.cvss_version is not None,
            item.published is not None,
            item.last_modified is not None,
            bool(item.cwes),
            bool(item.references),
        ]
    )


def normalize_priority_filters(priority_filters: list[PriorityFilter] | None) -> set[str]:
    if not priority_filters:
        return set()
    return {PRIORITY_LABELS[item] for item in priority_filters}


def build_active_filters(
    *,
    priority_filters: list[PriorityFilter] | None,
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
            label = PRIORITY_LABELS[item]
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
    if not attack_enabled or attack_source == AttackSource.none.value:
        return
    if attack_mapping_file is not None or offline_attack_file is not None:
        return
    exit_input_validation(
        "ATT&CK mode requires --attack-mapping-file or legacy --offline-attack-file."
    )


def handle_fail_on(findings: list[PrioritizedFinding], fail_on: PriorityFilter) -> None:
    threshold = PRIORITY_LABELS[fail_on]
    ordered = {"Critical": 1, "High": 2, "Medium": 3, "Low": 4}
    active_findings = [finding for finding in findings if not finding.waived]
    if any(ordered[finding.priority_label] <= ordered[threshold] for finding in active_findings):
        raise typer.Exit(code=1)


def handle_waiver_lifecycle_fail_on(
    context: AnalysisContext,
    *,
    fail_on_expired_waivers: bool,
    fail_on_review_due_waivers: bool,
) -> None:
    if fail_on_expired_waivers and context.expired_waiver_count:
        console.print(
            "[red]Policy check failed:[/red] expired waivers were detected in the current findings."
        )
        raise typer.Exit(code=1)
    if fail_on_review_due_waivers and (
        context.waiver_review_due_count or context.expired_waiver_count
    ):
        console.print(
            "[red]Policy check failed:[/red] review-due or expired waivers were "
            "detected in the current findings."
        )
        raise typer.Exit(code=1)


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
        exit_input_validation(str(exc))
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
            exit_input_validation("--locked-provider-data requires --provider-snapshot-file.")
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
        exit_input_validation(str(exc))

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
        console.print("[red]No findings could be generated from the provided CVEs.[/red]")
        raise typer.Exit(code=1)

    prioritizer = PrioritizationService(policy=request.policy)
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
    findings = prioritizer.sort_findings(filtered_findings, sort_by=request.sort_by.value)
    warnings = parsed_input.warnings + enrichment.warnings + waiver_warnings
    attack_summary = build_attack_summary_from_findings(findings)

    context = AnalysisContext(
        input_path=(
            parsed_input.input_paths[0]
            if parsed_input.input_paths
            else str(request.input_specs[0].path)
        ),
        output_path=str(request.output) if request.output else None,
        output_format=request.format.value,
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
        warnings=warnings,
        total_input=parsed_input.total_rows,
        valid_input=len(cve_ids),
        occurrences_count=len(parsed_input.occurrences),
        findings_count=len(findings),
        filtered_out_count=max(len(all_findings) - len(findings), 0),
        nvd_hits=count_nvd_hits(enrichment),
        nvd_diagnostics=enrichment.nvd_diagnostics,
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
        data_sources=build_data_sources(enrichment),
        cache_enabled=not request.no_cache,
        cache_dir=str(request.cache_dir) if not request.no_cache else None,
    )

    return findings, context


def prepare_explain(request: ExplainRequest) -> ExplainResult:
    context_profile = load_context_profile_or_exit(request.policy_profile, request.policy_file)
    if request.locked_provider_data and request.provider_snapshot_file is None:
        exit_input_validation("--locked-provider-data requires --provider-snapshot-file.")
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
    if not request.show_suppressed:
        findings = [finding for finding in findings if not finding.suppressed_by_vex]

    if not findings:
        console.print("[red]No finding could be generated for the requested CVE.[/red]")
        raise typer.Exit(code=1)

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
        output_format=request.format.value,
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
        warnings=warnings,
        total_input=1,
        valid_input=1,
        occurrences_count=parsed_input.total_rows,
        findings_count=1,
        filtered_out_count=0,
        nvd_hits=count_nvd_hits(enrichment),
        nvd_diagnostics=enrichment.nvd_diagnostics,
        epss_hits=count_epss_hits(enrichment),
        kev_hits=count_kev_hits(enrichment),
        attack_hits=attack_summary.mapped_cves,
        suppressed_by_vex=sum(1 for item in findings if item.suppressed_by_vex),
        under_investigation_count=sum(1 for item in findings if item.under_investigation),
        asset_match_conflict_count=parsed_input.asset_match_conflict_count,
        vex_conflict_count=parsed_input.vex_conflict_count,
        waived_count=sum(1 for item in findings if item.waived),
        attack_summary=attack_summary,
        policy_overrides=request.policy.override_descriptions(),
        priority_policy=request.policy,
        policy_profile=context_profile.name,
        policy_file=str(request.policy_file) if request.policy_file else None,
        waiver_file=str(request.waiver_file) if request.waiver_file else None,
        counts_by_priority=counts,
        source_stats=parsed_input.source_stats,
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

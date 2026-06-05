"""Analysis and explain pipeline facade helpers."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import cast

from pydantic import ValidationError

from app.domain.engine.inputs import (
    InputLoader,
)
from app.domain.engine.models import (
    AnalysisContext,
    PrioritizedFinding,
)
from app.domain.engine.services.analysis_attack import (
    build_attack_summary_from_findings,
    resolve_attack_options,
)
from app.domain.engine.services.analysis_filters import (
    build_active_filters,
    normalize_priority_filters,
)
from app.domain.engine.services.analysis_findings import build_findings
from app.domain.engine.services.analysis_inputs import (
    load_analysis_context_profile,
    load_analysis_provider_snapshot,
    load_analysis_waiver_rules,
    load_asset_records,
    load_vex_statements,
)
from app.domain.engine.services.analysis_models import (
    AnalysisInputError,
    AnalysisNoFindingsError,
    AnalysisRequest,
    ExplainRequest,
    ExplainResult,
    _enum_value,
)
from app.domain.engine.services.analysis_provider import (
    build_data_sources,
    build_provider_diagnostics,
    build_provider_freshness,
    count_epss_hits,
    count_kev_hits,
    count_nvd_hits,
    provider_degraded,
    stale_provider_sources,
)
from app.domain.engine.services.analysis_snapshot import (
    _provider_snapshot_hash,
    _provider_snapshot_metadata_path,
)
from app.domain.engine.services.defensive_context import (
    defensive_context_hit_count,
)
from app.domain.engine.services.prioritization import PrioritizationService, SortField
from app.domain.engine.services.waivers import (
    apply_waivers,
)
from app.domain.engine.utils import iso_utc_now


def prepare_analysis(request: AnalysisRequest) -> tuple[list[PrioritizedFinding], AnalysisContext]:
    """Prepare analysis function."""
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
        if request.locked_provider_data and request.provider_snapshot_file is None:
            raise AnalysisInputError("Locked provider data requires a provider snapshot file.")
        provider_snapshot = load_analysis_provider_snapshot(request.provider_snapshot_file)
        if request.parsed_input is not None:
            parsed_input = request.parsed_input
        else:
            asset_records = load_asset_records(request.asset_context)
            vex_statements = load_vex_statements(request.vex_files)
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
    context_profile = load_analysis_context_profile(request.policy_profile, request.policy_file)
    waiver_rules = load_analysis_waiver_rules(request.waiver_file)
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
        defensive_context_file=request.defensive_context_file,
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
    generated_at = iso_utc_now()
    provider_freshness = build_provider_freshness(
        enrichment,
        provider_snapshot=provider_snapshot,
        lookup_completed_at=generated_at,
    )
    provider_stale_sources = stale_provider_sources(
        provider_freshness,
        max_age_hours=request.max_provider_age_hours,
        snapshot_sources=enrichment.provider_snapshot_sources if provider_snapshot else None,
    )
    if provider_stale_sources:
        warnings.append(
            "Provider data exceeded --max-provider-age-hours for: "
            + ", ".join(sorted(provider_stale_sources))
        )

    context = AnalysisContext(
        input_path=(
            parsed_input.input_paths[0]
            if parsed_input.input_paths
            else str(request.input_specs[0].path)
        ),
        output_path=str(request.output) if request.output else None,
        output_format=_enum_value(request.format),
        generated_at=generated_at,
        input_format=parsed_input.input_format,
        input_paths=parsed_input.input_paths,
        input_sources=parsed_input.source_summaries,
        merged_input_count=parsed_input.merged_input_count,
        duplicate_cve_count=parsed_input.duplicate_cve_count,
        provider_snapshot_id=(
            provider_snapshot.metadata.snapshot_id if provider_snapshot is not None else None
        ),
        provider_snapshot_hash=_provider_snapshot_hash(request.provider_snapshot_file),
        provider_snapshot_file=(
            _provider_snapshot_metadata_path(request.provider_snapshot_file, request.output)
        ),
        locked_provider_data=request.locked_provider_data,
        provider_snapshot_sources=enrichment.provider_snapshot_sources,
        defensive_context_file=enrichment.defensive_context_file,
        defensive_context_sources=enrichment.defensive_context_sources,
        defensive_context_hits=defensive_context_hit_count(findings),
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
        provider_data_quality_flags=enrichment.provider_data_quality_flags,
        provider_freshness=provider_freshness,
        max_provider_age_hours=request.max_provider_age_hours,
        provider_stale=bool(provider_stale_sources),
        provider_stale_sources=provider_stale_sources,
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
    """Compatibility wrapper for the focused explain module."""
    from app.domain.engine.services.analysis_explain import prepare_explain as _prepare_explain

    return _prepare_explain(request)


def prepare_saved_explain(
    *,
    cve_id: str,
    input_path: Path,
    output: Path | None,
    format: StrEnum | str,
) -> ExplainResult:
    """Compatibility wrapper for saved-analysis explain results."""
    from app.domain.engine.services.analysis_explain import (
        prepare_saved_explain as _prepare_saved_explain,
    )

    return _prepare_saved_explain(
        cve_id=cve_id,
        input_path=input_path,
        output=output,
        format=format,
    )

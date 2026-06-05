"""Explain-result builders for live and saved analysis findings."""

from __future__ import annotations

import json
from enum import StrEnum
from pathlib import Path
from typing import Any, cast

from pydantic import ValidationError

from app.domain.engine.inputs import build_inline_input
from app.domain.engine.models import (
    AnalysisContext,
    AttackData,
    AttackSummary,
    EpssData,
    KevData,
    NvdData,
    PrioritizedFinding,
)
from app.domain.engine.services.analysis_attack import (
    build_attack_summary_from_findings,
    resolve_attack_options,
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
)
from app.domain.engine.services.analysis_snapshot import (
    _provider_snapshot_hash,
    _provider_snapshot_metadata_path,
)
from app.domain.engine.services.defensive_context import defensive_context_hit_count
from app.domain.engine.services.prioritization import PrioritizationService
from app.domain.engine.services.waivers import apply_waivers
from app.domain.engine.utils import iso_utc_now


def prepare_explain(request: ExplainRequest) -> ExplainResult:
    """Prepare an explain result for one requested CVE."""
    context_profile = load_analysis_context_profile(request.policy_profile, request.policy_file)
    if request.locked_provider_data and request.provider_snapshot_file is None:
        raise AnalysisInputError("Locked provider data requires a provider snapshot file.")
    provider_snapshot = load_analysis_provider_snapshot(request.provider_snapshot_file)
    attack_enabled, resolved_attack_source, resolved_mapping_file, resolved_metadata_file = (
        resolve_attack_options(
            no_attack=request.no_attack,
            attack_source=request.attack_source,
            attack_mapping_file=request.attack_mapping_file,
            attack_technique_metadata_file=request.attack_technique_metadata_file,
            offline_attack_file=request.offline_attack_file,
        )
    )
    asset_records = load_asset_records(request.asset_context)
    vex_statements = load_vex_statements(request.vex_files)
    waiver_rules = load_analysis_waiver_rules(request.waiver_file)
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
        defensive_context_file=request.defensive_context_file,
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
    generated_at = iso_utc_now()
    provider_freshness = build_provider_freshness(
        enrichment,
        provider_snapshot=provider_snapshot,
        lookup_completed_at=generated_at,
    )

    context = AnalysisContext(
        input_path=f"inline:{request.cve_id}",
        output_path=str(request.output) if request.output else None,
        output_format=_enum_value(request.format),
        generated_at=generated_at,
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
        provider_data_quality_flags=enrichment.provider_data_quality_flags,
        provider_freshness=provider_freshness,
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

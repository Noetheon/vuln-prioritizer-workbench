"""Finding construction helpers for the analysis pipeline."""

from __future__ import annotations

from pathlib import Path

from pydantic import ValidationError

from vuln_prioritizer.attack_sources import ATTACK_SOURCE_NONE
from vuln_prioritizer.models import (
    ContextPolicyProfile,
    EnrichmentResult,
    ParsedInput,
    PrioritizedFinding,
    PriorityPolicy,
    ProviderSnapshotReport,
)
from vuln_prioritizer.services.analysis_models import AnalysisInputError
from vuln_prioritizer.services.analysis_quality import attach_provider_data_quality_flags
from vuln_prioritizer.services.contextualization import aggregate_provenance
from vuln_prioritizer.services.defensive_context import (
    attach_defensive_contexts,
    load_defensive_context_file,
    merge_defensive_contexts,
)
from vuln_prioritizer.services.enrichment import EnrichmentService
from vuln_prioritizer.services.prioritization import PrioritizationService


def validate_requested_attack_mode(
    *,
    attack_enabled: bool,
    attack_source: str,
    attack_mapping_file: Path | None,
    offline_attack_file: Path | None,
) -> None:
    """Reject enabled ATT&CK mode when no mapping source was provided."""
    if not attack_enabled or attack_source == ATTACK_SOURCE_NONE:
        return
    if attack_mapping_file is not None or offline_attack_file is not None:
        return
    raise AnalysisInputError(
        "ATT&CK mode requires a mapping file for the selected Workbench ATT&CK source."
    )


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
    defensive_context_file: Path | None,
    nvd_api_key_env: str,
    no_cache: bool,
    cache_dir: Path,
    cache_ttl_hours: int,
    provider_snapshot: ProviderSnapshotReport | None = None,
    locked_provider_data: bool = False,
) -> tuple[list[PrioritizedFinding], dict[str, int], EnrichmentResult]:
    """Build enriched, prioritized findings from parsed CVE input."""
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
    try:
        defensive_context_result = load_defensive_context_file(defensive_context_file)
    except ValueError as exc:
        raise AnalysisInputError(str(exc)) from exc
    enrichment.defensive_contexts = merge_defensive_contexts(
        enrichment.defensive_contexts,
        defensive_context_result.contexts,
    )
    enrichment.defensive_context_sources = sorted(
        set(enrichment.defensive_context_sources) | set(defensive_context_result.sources)
    )
    enrichment.defensive_context_file = (
        str(defensive_context_file) if defensive_context_file else None
    )
    enrichment.warnings.extend(defensive_context_result.warnings)
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
    findings = attach_defensive_contexts(findings, enrichment.defensive_contexts)
    findings = attach_provider_data_quality_flags(findings, enrichment.provider_data_quality_flags)
    return findings, counts, enrichment

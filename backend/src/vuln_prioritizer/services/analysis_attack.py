"""ATT&CK option and summary helpers for analysis flows."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path

from vuln_prioritizer.attack_sources import (
    ATTACK_SOURCE_CTID_JSON,
    ATTACK_SOURCE_LOCAL_CSV,
    ATTACK_SOURCE_NONE,
)
from vuln_prioritizer.models import (
    AttackData,
    AttackSummary,
    PrioritizedFinding,
)
from vuln_prioritizer.services.analysis_models import _enum_value
from vuln_prioritizer.services.attack_enrichment import AttackEnrichmentService


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

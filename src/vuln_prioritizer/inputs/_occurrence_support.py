"""Private occurrence post-processing helpers for normalized inputs."""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from fnmatch import fnmatchcase
from typing import Any, Literal, overload

from vuln_prioritizer.models import (
    AssetContextRecord,
    InputOccurrence,
    InputSourceSummary,
    ParsedInput,
)


@dataclass(frozen=True)
class AssetContextMatchDiagnostics:
    matched_occurrences: int
    unmatched_occurrences: int
    exact_matches: int
    glob_matches: int
    ambiguous_occurrences: int
    warnings: tuple[str, ...] = ()


def apply_manual_target(
    occurrence: InputOccurrence,
    *,
    target_kind: str | None,
    target_ref: str | None,
) -> InputOccurrence:
    """Apply a manual target override when the occurrence has no target yet."""
    if target_kind is None and target_ref is None:
        return occurrence
    if occurrence.target_ref:
        return occurrence
    return occurrence.model_copy(
        update={
            "target_kind": (target_kind or occurrence.target_kind).lower(),
            "target_ref": target_ref or occurrence.target_ref,
        }
    )


@overload
def apply_asset_context(
    occurrences: list[InputOccurrence],
    asset_records: Mapping[tuple[str, str], AssetContextRecord] | Any,
    *,
    return_diagnostics: Literal[False] = False,
) -> list[InputOccurrence]: ...


@overload
def apply_asset_context(
    occurrences: list[InputOccurrence],
    asset_records: Mapping[tuple[str, str], AssetContextRecord] | Any,
    *,
    return_diagnostics: Literal[True],
) -> tuple[list[InputOccurrence], AssetContextMatchDiagnostics]: ...


def apply_asset_context(
    occurrences: list[InputOccurrence],
    asset_records: Mapping[tuple[str, str], AssetContextRecord] | Any,
    *,
    return_diagnostics: bool = False,
) -> list[InputOccurrence] | tuple[list[InputOccurrence], AssetContextMatchDiagnostics]:
    """Attach asset context records to occurrences."""
    rules = getattr(asset_records, "rules", None)
    if asset_records is None or (not rules and not asset_records):
        diagnostics = AssetContextMatchDiagnostics(
            matched_occurrences=0,
            unmatched_occurrences=len(occurrences),
            exact_matches=0,
            glob_matches=0,
            ambiguous_occurrences=0,
        )
        return (occurrences, diagnostics) if return_diagnostics else occurrences

    if rules:
        enriched: list[InputOccurrence] = []
        matched_occurrences = 0
        unmatched_occurrences = 0
        exact_matches = 0
        glob_matches = 0
        ambiguous_occurrences = 0

        for occurrence in occurrences:
            matched_rule, candidate_count = _resolve_asset_context_rule(occurrence, rules)
            if matched_rule is None:
                unmatched_occurrences += 1
                enriched.append(occurrence)
                continue
            matched_occurrences += 1
            if candidate_count > 1:
                ambiguous_occurrences += 1
            if matched_rule.match_mode == "glob":
                glob_matches += 1
            else:
                exact_matches += 1
            enriched.append(
                _apply_asset_context_record(
                    occurrence,
                    matched_rule.asset_record,
                    candidate_count=candidate_count,
                )
            )

        warning_messages: list[str] = []
        if ambiguous_occurrences:
            warning_messages.append(
                "Asset context resolved "
                f"{ambiguous_occurrences} occurrence(s) against multiple candidate rules "
                "using precedence, match mode, specificity, and CSV row order."
            )

        diagnostics = AssetContextMatchDiagnostics(
            matched_occurrences=matched_occurrences,
            unmatched_occurrences=unmatched_occurrences,
            exact_matches=exact_matches,
            glob_matches=glob_matches,
            ambiguous_occurrences=ambiguous_occurrences,
            warnings=tuple(warning_messages),
        )
        return (enriched, diagnostics) if return_diagnostics else enriched

    legacy_enriched: list[InputOccurrence] = []
    matched_occurrences = 0
    unmatched_occurrences = 0
    for occurrence in occurrences:
        if not occurrence.target_ref:
            unmatched_occurrences += 1
            legacy_enriched.append(occurrence)
            continue
        asset = asset_records.get((occurrence.target_kind.lower(), occurrence.target_ref))
        if asset is None:
            unmatched_occurrences += 1
            legacy_enriched.append(occurrence)
            continue
        matched_occurrences += 1
        legacy_enriched.append(_apply_asset_context_record(occurrence, asset, candidate_count=1))

    diagnostics = AssetContextMatchDiagnostics(
        matched_occurrences=matched_occurrences,
        unmatched_occurrences=unmatched_occurrences,
        exact_matches=matched_occurrences,
        glob_matches=0,
        ambiguous_occurrences=0,
    )
    return (legacy_enriched, diagnostics) if return_diagnostics else legacy_enriched


def _apply_asset_context_record(
    occurrence: InputOccurrence,
    asset: AssetContextRecord,
    *,
    candidate_count: int,
) -> InputOccurrence:
    return occurrence.model_copy(
        update={
            "asset_id": asset.asset_id,
            "asset_criticality": asset.criticality,
            "asset_exposure": asset.exposure,
            "asset_environment": asset.environment,
            "asset_owner": asset.owner,
            "asset_business_service": asset.business_service,
            "asset_match_rule_id": asset.rule_id,
            "asset_match_row": asset.row_number,
            "asset_match_mode": asset.match_mode,
            "asset_match_pattern": asset.target_ref,
            "asset_match_precedence": asset.precedence,
            "asset_match_candidate_count": candidate_count,
        }
    )


def _resolve_asset_context_rule(
    occurrence: InputOccurrence,
    rules: Any,
) -> tuple[Any | None, int]:
    matched_rules: list[Any] = []
    for rule in rules:
        if _asset_context_rule_matches(occurrence, rule):
            matched_rules.append(rule)
    if not matched_rules:
        return None, 0
    winner = max(matched_rules, key=_asset_context_rule_score)
    return winner, len(matched_rules)


def _asset_context_rule_score(rule: Any) -> tuple[int, int, int, int, int]:
    precedence = int(getattr(rule, "precedence", 0) or 0)
    specificity = 1 if getattr(rule, "match_mode", "exact") == "exact" else 0
    order = int(getattr(rule, "order", 0) or 0)
    pattern = str(getattr(rule, "target_ref", "") or "")
    return (
        precedence,
        specificity,
        _literal_char_count(pattern),
        -_wildcard_count(pattern),
        -order,
    )


def _asset_context_rule_matches(
    occurrence: InputOccurrence,
    rule: Any,
) -> bool:
    if occurrence.target_ref is None:
        return False
    target_kind = (occurrence.target_kind or "").lower()
    rule_kind = (getattr(rule, "target_kind", "") or "").lower()
    rule_ref = getattr(rule, "target_ref", "") or ""
    match_mode = (getattr(rule, "match_mode", "exact") or "exact").lower()
    if target_kind != rule_kind:
        return False
    if match_mode == "glob":
        return fnmatchcase(occurrence.target_ref, rule_ref)
    return occurrence.target_ref == rule_ref


def _literal_char_count(pattern: str) -> int:
    return sum(1 for char in pattern if char not in {"*", "?", "[", "]"})


def _wildcard_count(pattern: str) -> int:
    return sum(1 for char in pattern if char in {"*", "?", "[", "]"})


def finalize_occurrences(
    occurrences: list[InputOccurrence],
    *,
    input_format: str,
    warnings: list[str],
    total_rows: int,
    max_cves: int | None,
    input_paths: list[str] | None = None,
    source_summaries: list[InputSourceSummary] | None = None,
    merged_input_count: int = 1,
    asset_match_conflict_count: int = 0,
    vex_conflict_count: int = 0,
) -> ParsedInput:
    """Deduplicate, truncate, and package normalized occurrences."""
    duplicate_cve_count = sum(
        1
        for count in Counter(occurrence.cve_id for occurrence in occurrences).values()
        if count > 1
    )
    seen: set[str] = set()
    unique_cves: list[str] = []
    for occurrence in occurrences:
        if occurrence.cve_id in seen:
            continue
        seen.add(occurrence.cve_id)
        unique_cves.append(occurrence.cve_id)

    if max_cves is not None and len(unique_cves) > max_cves:
        allowed = set(unique_cves[:max_cves])
        warnings = warnings + [
            "Applied --max-cves "
            f"{max_cves}; truncated the analysis set from {len(unique_cves)} "
            f"to {max_cves} CVEs."
        ]
        unique_cves = unique_cves[:max_cves]
        occurrences = [occurrence for occurrence in occurrences if occurrence.cve_id in allowed]

    if not unique_cves:
        raise ValueError("No valid CVE identifiers were found in the provided input.")

    if merged_input_count > 1 and duplicate_cve_count:
        warnings = warnings + [
            "Merged input set collapsed duplicate CVEs for "
            f"{duplicate_cve_count} CVE identifier(s) across {merged_input_count} input files."
        ]

    source_stats = dict(Counter(occurrence.source_format for occurrence in occurrences))
    return ParsedInput(
        input_format=input_format,
        total_rows=total_rows,
        occurrences=occurrences,
        unique_cves=unique_cves,
        warnings=warnings,
        source_stats=source_stats,
        input_paths=input_paths or [],
        source_summaries=source_summaries or [],
        merged_input_count=merged_input_count,
        duplicate_cve_count=duplicate_cve_count,
        asset_match_conflict_count=asset_match_conflict_count,
        vex_conflict_count=vex_conflict_count,
    )

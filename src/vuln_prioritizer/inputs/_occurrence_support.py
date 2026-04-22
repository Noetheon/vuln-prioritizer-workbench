"""Private occurrence post-processing helpers for normalized inputs."""

from __future__ import annotations

from collections import Counter

from vuln_prioritizer.models import AssetContextRecord, InputOccurrence, ParsedInput


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


def apply_asset_context(
    occurrences: list[InputOccurrence],
    asset_records: dict[tuple[str, str], AssetContextRecord],
) -> list[InputOccurrence]:
    """Attach exact-match asset context records to occurrences."""
    if not asset_records:
        return occurrences

    enriched: list[InputOccurrence] = []
    for occurrence in occurrences:
        if not occurrence.target_ref:
            enriched.append(occurrence)
            continue
        asset = asset_records.get((occurrence.target_kind.lower(), occurrence.target_ref))
        if asset is None:
            enriched.append(occurrence)
            continue
        enriched.append(
            occurrence.model_copy(
                update={
                    "asset_id": asset.asset_id,
                    "asset_criticality": asset.criticality,
                    "asset_exposure": asset.exposure,
                    "asset_environment": asset.environment,
                    "asset_owner": asset.owner,
                    "asset_business_service": asset.business_service,
                }
            )
        )
    return enriched


def finalize_occurrences(
    occurrences: list[InputOccurrence],
    *,
    input_format: str,
    warnings: list[str],
    total_rows: int,
    max_cves: int | None,
) -> ParsedInput:
    """Deduplicate, truncate, and package normalized occurrences."""
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
        raise ValueError("No valid CVE identifiers were found in the input file.")

    source_stats = dict(Counter(occurrence.source_format for occurrence in occurrences))
    return ParsedInput(
        input_format=input_format,
        total_rows=total_rows,
        occurrences=occurrences,
        unique_cves=unique_cves,
        warnings=warnings,
        source_stats=source_stats,
    )

"""Provenance, asset context, and VEX helpers."""

from __future__ import annotations

from collections import Counter
from pathlib import Path

import yaml

from vuln_prioritizer.models import (
    ContextPolicyProfile,
    FindingProvenance,
    InputOccurrence,
)

CRITICALITY_ORDER = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

EXPOSURE_ORDER = {
    "internal": 1,
    "dmz": 2,
    "internet-facing": 3,
}

DEFAULT_CONTEXT_PROFILES = {
    "default": ContextPolicyProfile(name="default", narrative_only=True),
    "enterprise": ContextPolicyProfile(
        name="enterprise",
        narrative_only=False,
        enterprise_escalation=True,
        internet_facing_boost=True,
        prod_asset_boost=True,
    ),
    "conservative": ContextPolicyProfile(
        name="conservative",
        narrative_only=True,
        enterprise_escalation=False,
        internet_facing_boost=False,
        prod_asset_boost=False,
    ),
}

SUPPRESSED_VEX_STATUSES = {"not_affected", "fixed"}


def aggregate_provenance(
    cve_ids: list[str],
    occurrences: list[InputOccurrence],
) -> dict[str, FindingProvenance]:
    """Aggregate occurrence-level context into per-CVE provenance."""
    by_cve: dict[str, list[InputOccurrence]] = {cve_id: [] for cve_id in cve_ids}
    for occurrence in occurrences:
        by_cve.setdefault(occurrence.cve_id, []).append(occurrence)

    aggregated: dict[str, FindingProvenance] = {}
    for cve_id, items in by_cve.items():
        source_formats = sorted({item.source_format for item in items})
        components = sorted(
            {
                " ".join(
                    part for part in [item.component_name, item.component_version] if part
                ).strip()
                for item in items
                if item.component_name or item.component_version
            }
        )
        affected_paths = sorted(
            {path for item in items for path in [item.file_path, item.dependency_path] if path}
        )
        fix_versions = sorted({version for item in items for version in item.fix_versions})
        targets = sorted(
            {f"{item.target_kind}:{item.target_ref}" for item in items if item.target_ref}
        )
        asset_ids = sorted({item.asset_id for item in items if item.asset_id})
        vex_statuses = dict(Counter(item.vex_status for item in items if item.vex_status))
        active_items = [
            item for item in items if (item.vex_status or "").lower() not in SUPPRESSED_VEX_STATUSES
        ]
        suppressed_items = len(items) - len(active_items)

        aggregated[cve_id] = FindingProvenance(
            occurrence_count=len(items),
            active_occurrence_count=len(active_items),
            suppressed_occurrence_count=suppressed_items,
            source_formats=source_formats,
            components=components,
            affected_paths=affected_paths,
            fix_versions=fix_versions,
            targets=targets,
            asset_ids=asset_ids,
            highest_asset_criticality=_highest_criticality(items),
            highest_asset_exposure=_highest_exposure(items),
            asset_count=len(asset_ids),
            vex_statuses=vex_statuses,
            occurrences=items,
        )

    return aggregated


def load_context_profile(name: str, policy_file: Path | None) -> ContextPolicyProfile:
    """Load a built-in or YAML-defined context profile."""
    if policy_file is None:
        try:
            return DEFAULT_CONTEXT_PROFILES[name]
        except KeyError as exc:
            raise ValueError(f"Unknown policy profile: {name}") from exc

    document = yaml.safe_load(policy_file.read_text(encoding="utf-8")) or {}
    profiles = document.get("profiles", {})
    config = profiles.get(name)
    if not isinstance(config, dict):
        raise ValueError(f"Policy profile {name!r} is not defined in {policy_file}.")
    return ContextPolicyProfile(
        name=name,
        narrative_only=bool(config.get("narrative_only", True)),
        enterprise_escalation=bool(config.get("enterprise_escalation", False)),
        internet_facing_boost=bool(config.get("internet_facing_boost", False)),
        prod_asset_boost=bool(config.get("prod_asset_boost", False)),
    )


def is_suppressed_by_vex(provenance: FindingProvenance) -> bool:
    """Return True if all known occurrences are suppressed by VEX."""
    return provenance.occurrence_count > 0 and provenance.active_occurrence_count == 0


def is_under_investigation(provenance: FindingProvenance) -> bool:
    """Return True if any occurrence is still under investigation."""
    return "under_investigation" in provenance.vex_statuses


def _highest_criticality(items: list[InputOccurrence]) -> str | None:
    best = max(
        (
            (
                CRITICALITY_ORDER.get((item.asset_criticality or "").lower(), 0),
                item.asset_criticality,
            )
            for item in items
            if item.asset_criticality
        ),
        default=(0, None),
    )
    return best[1]


def _highest_exposure(items: list[InputOccurrence]) -> str | None:
    best = max(
        (
            (EXPOSURE_ORDER.get((item.asset_exposure or "").lower(), 0), item.asset_exposure)
            for item in items
            if item.asset_exposure
        ),
        default=(0, None),
    )
    return best[1]

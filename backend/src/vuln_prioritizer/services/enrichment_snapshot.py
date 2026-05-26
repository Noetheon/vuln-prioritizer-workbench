"""Provider snapshot helpers for enrichment."""

from __future__ import annotations

from vuln_prioritizer.models import DefensiveContext, ProviderSnapshotReport


def snapshot_defensive_contexts(
    *,
    provider_snapshot: ProviderSnapshotReport | None,
    cve_ids: list[str],
) -> dict[str, list[DefensiveContext]]:
    """Return defensive context records embedded in a provider snapshot."""
    if provider_snapshot is None:
        return {}
    indexed = {item.cve_id: item for item in provider_snapshot.items}
    return {
        cve_id: list(item.defensive_contexts)
        for cve_id in cve_ids
        if (item := indexed.get(cve_id)) is not None and item.defensive_contexts
    }


def snapshot_source_selected(
    provider_snapshot: ProviderSnapshotReport,
    source_name: str,
) -> bool:
    """Return whether a provider source was selected in the snapshot."""
    return source_name in set(provider_snapshot.metadata.selected_sources)


def active_provider_sources(
    *,
    provider_snapshot: ProviderSnapshotReport | None,
    locked_provider_data: bool,
) -> set[str]:
    """Return provider sources that participate in data-quality evaluation."""
    if provider_snapshot is None or not locked_provider_data:
        return {"nvd", "epss", "kev"}
    return {
        source
        for source in provider_snapshot.metadata.selected_sources
        if source in {"nvd", "epss", "kev"}
    }

"""Provider diagnostics and freshness helpers for analysis flows."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime, timedelta

from vuln_prioritizer.attack_sources import (
    ATTACK_SOURCE_CTID_MAPPINGS_EXPLORER,
    ATTACK_SOURCE_LOCAL_CSV,
)
from vuln_prioritizer.config import DATA_SOURCES
from vuln_prioritizer.models import (
    EnrichmentResult,
    ProviderLookupDiagnostics,
    ProviderSnapshotReport,
)
from vuln_prioritizer.providers.nvd import has_nvd_content


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


def build_data_sources(enrichment: EnrichmentResult) -> list[str]:
    sources = list(DATA_SOURCES)
    if enrichment.provider_snapshot_sources:
        sources.append(
            "Provider snapshot replay: " + ", ".join(sorted(enrichment.provider_snapshot_sources))
        )
    if enrichment.defensive_context_sources:
        sources.append(
            "Defensive context: "
            + ", ".join(source.upper() for source in enrichment.defensive_context_sources)
        )
    if enrichment.attack_source == ATTACK_SOURCE_CTID_MAPPINGS_EXPLORER:
        sources.append("CTID Mappings Explorer (local JSON artifact)")
    elif enrichment.attack_source == ATTACK_SOURCE_LOCAL_CSV:
        sources.append("Local ATT&CK CSV mapping")
    parsed_input = enrichment.parsed_input
    if parsed_input.source_stats:
        sources.append("Input formats: " + ", ".join(sorted(parsed_input.source_stats)))
    return sources


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
    *,
    provider_snapshot: ProviderSnapshotReport | None = None,
    lookup_completed_at: str | None = None,
) -> dict[str, str | int | float | bool | None]:
    nvd_last_modified = sorted(
        item.last_modified for item in enrichment.nvd.values() if item.last_modified
    )
    epss_dates = sorted(item.date for item in enrichment.epss.values() if item.date)
    kev_date_added = sorted(item.date_added for item in enrichment.kev.values() if item.date_added)
    kev_due_dates = sorted(item.due_date for item in enrichment.kev.values() if item.due_date)
    cache_timestamps = {} if provider_snapshot is not None else enrichment.provider_cache_timestamps
    nvd_cache_latest = cache_timestamps.get("nvd")
    epss_cache_latest = cache_timestamps.get("epss")
    kev_cache_latest = cache_timestamps.get("kev")
    return {
        "nvd_last_modified_min": nvd_last_modified[0] if nvd_last_modified else None,
        "nvd_last_modified_max": nvd_last_modified[-1] if nvd_last_modified else None,
        "latest_epss_date": epss_dates[-1] if epss_dates else None,
        "kev_date_added_max": kev_date_added[-1] if kev_date_added else None,
        "kev_due_date_min": kev_due_dates[0] if kev_due_dates else None,
        "nvd_cache_latest_cached_at": nvd_cache_latest,
        "epss_cache_latest_cached_at": epss_cache_latest,
        "kev_cache_latest_cached_at": kev_cache_latest,
        "nvd_freshness_at": _provider_source_freshness_at(
            diagnostics=enrichment.nvd_diagnostics,
            cache_timestamp=nvd_cache_latest,
            lookup_completed_at=lookup_completed_at,
        ),
        "epss_freshness_at": _provider_source_freshness_at(
            diagnostics=enrichment.epss_diagnostics,
            cache_timestamp=epss_cache_latest,
            lookup_completed_at=lookup_completed_at,
        ),
        "kev_freshness_at": _provider_source_freshness_at(
            diagnostics=enrichment.kev_diagnostics,
            cache_timestamp=kev_cache_latest,
            lookup_completed_at=lookup_completed_at,
        ),
        "provider_snapshot_generated_at": (
            provider_snapshot.metadata.generated_at if provider_snapshot is not None else None
        ),
        "lookup_completed_at": lookup_completed_at,
    }


def stale_provider_sources(
    freshness: dict[str, str | int | float | bool | None],
    *,
    max_age_hours: int | None,
    snapshot_sources: Sequence[str] | None = None,
    now: datetime | None = None,
) -> list[str]:
    if max_age_hours is None:
        return []
    active_now = now or datetime.now(UTC)
    threshold = active_now - timedelta(hours=max_age_hours)
    if snapshot_sources is not None:
        source_fields = {
            source: "provider_snapshot_generated_at"
            for source in snapshot_sources
            if source in {"nvd", "epss", "kev"}
        }
    else:
        source_fields = {
            "nvd": "nvd_freshness_at",
            "epss": "epss_freshness_at",
            "kev": "kev_freshness_at",
        }
    stale_sources: list[str] = []
    for source, field in source_fields.items():
        value = freshness.get(field)
        if value is None and snapshot_sources is None:
            value = freshness.get("lookup_completed_at")
        parsed = _parse_provider_timestamp(value)
        if parsed is None or parsed < threshold:
            stale_sources.append(source)
    return stale_sources


def _provider_source_freshness_at(
    *,
    diagnostics: ProviderLookupDiagnostics,
    cache_timestamp: str | None,
    lookup_completed_at: str | None,
) -> str | None:
    if diagnostics.cache_hits or diagnostics.stale_cache_hits:
        return cache_timestamp
    if diagnostics.network_fetches or diagnostics.content_hits or diagnostics.empty_records:
        return lookup_completed_at
    return cache_timestamp or lookup_completed_at


def _parse_provider_timestamp(value: object) -> datetime | None:
    if value is None:
        return None
    raw = str(value).strip()
    if not raw:
        return None
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        try:
            parsed = datetime.fromisoformat(raw + "T00:00:00+00:00")
        except ValueError:
            return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)

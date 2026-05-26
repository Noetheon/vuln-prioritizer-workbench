"""Provider result and diagnostics helpers for enrichment."""

from __future__ import annotations

from typing import TypeVar

from vuln_prioritizer.models import EpssData, KevData, NvdData, ProviderLookupDiagnostics
from vuln_prioritizer.providers.nvd import NvdFetchDiagnostics, has_nvd_content

_T = TypeVar("_T", NvdData, EpssData, KevData)


def merge_provider_results(
    cve_ids: list[str],
    snapshot_results: dict[str, _T],
    live_results: dict[str, _T],
    model_cls: type[_T],
) -> dict[str, _T]:
    """Merge snapshot, live, and empty fallback provider records."""
    merged: dict[str, _T] = {}
    for cve_id in cve_ids:
        if cve_id in snapshot_results:
            merged[cve_id] = snapshot_results[cve_id]
        elif cve_id in live_results:
            merged[cve_id] = live_results[cve_id]
        else:
            merged[cve_id] = model_cls(cve_id=cve_id)
    return merged


def build_fallback_diagnostics(
    cve_ids: list[str],
    results: dict[str, _T],
    model_cls: type[_T],
) -> ProviderLookupDiagnostics:
    """Build provider lookup diagnostics when a provider has no native metrics."""
    if model_cls is EpssData:
        content_hits = sum(
            1
            for item in results.values()
            if isinstance(item, EpssData)
            and (item.epss is not None or item.percentile is not None or item.date is not None)
        )
    elif model_cls is KevData:
        content_hits = sum(
            1 for item in results.values() if isinstance(item, KevData) and item.in_kev
        )
    else:
        content_hits = sum(
            1 for item in results.values() if isinstance(item, NvdData) and has_nvd_content(item)
        )
    return ProviderLookupDiagnostics(
        requested=len(cve_ids),
        content_hits=content_hits,
        empty_records=max(len(cve_ids) - content_hits, 0),
    )


def build_nvd_fetch_diagnostics(
    cve_ids: list[str],
    results: dict[str, NvdData],
) -> NvdFetchDiagnostics:
    """Build NVD fetch diagnostics from fallback lookup metrics."""
    fallback = build_fallback_diagnostics(cve_ids, results, NvdData)
    return NvdFetchDiagnostics(
        requested=fallback.requested,
        cache_hits=fallback.cache_hits,
        network_fetches=fallback.network_fetches,
        failures=fallback.failures,
        content_hits=fallback.content_hits,
        empty_records=fallback.empty_records,
        stale_cache_hits=fallback.stale_cache_hits,
        degraded=fallback.degraded,
    )


def safe_provider_error(exc: BaseException, *, provider: object) -> str:
    """Return a provider error message with provider secrets redacted."""
    message = str(exc)
    secret = getattr(provider, "api_key", None)
    if isinstance(secret, str) and secret:
        message = message.replace(secret, "<redacted>")
    return message

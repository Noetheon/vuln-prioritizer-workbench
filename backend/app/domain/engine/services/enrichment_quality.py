"""Provider data-quality flag helpers for enrichment."""

from __future__ import annotations

from app.domain.engine.models import (
    EpssData,
    NvdData,
    ProviderDataQualityFlag,
    ProviderLookupDiagnostics,
    ProviderSnapshotReport,
)
from app.domain.engine.providers.nvd import has_nvd_content
from app.domain.engine.providers.sdk import provider_data_quality_flags


def provider_enrichment_quality_flags(
    *,
    nvd_results: dict[str, NvdData] | None = None,
    epss_results: dict[str, EpssData] | None = None,
    provider_snapshot: ProviderSnapshotReport | None = None,
    locked_provider_data: bool = False,
    active_provider_sources: set[str] | None = None,
    **sources: tuple[ProviderLookupDiagnostics, list[str]],
) -> dict[str, list[ProviderDataQualityFlag]]:
    """Return provider data-quality flags for an enrichment pass."""
    flags_by_source: dict[str, list[ProviderDataQualityFlag]] = {}
    for source, (diagnostics, warnings) in sources.items():
        if active_provider_sources is not None and source not in active_provider_sources:
            continue
        flags = provider_data_quality_flags(
            source=source,
            diagnostics=diagnostics,
            warnings=warnings,
        )
        if flags:
            flags_by_source[source] = flags
        _append_provider_error_flag(
            flags_by_source,
            source=source,
            diagnostics=diagnostics,
            warnings=warnings,
        )
    active_sources = active_provider_sources or {"nvd", "epss", "kev"}
    missing_cvss_flags = (
        _nvd_missing_cvss_flags(nvd_results or {}) if "nvd" in active_sources else []
    )
    if missing_cvss_flags:
        flags_by_source.setdefault("nvd", []).extend(missing_cvss_flags)
    if "nvd" in active_sources:
        _append_nvd_missing_flags(flags_by_source, nvd_results or {})
    if "epss" in active_sources:
        _append_epss_missing_flags(flags_by_source, epss_results or {})
        _append_epss_outdated_flag(flags_by_source, sources.get("epss"))
    if "kev" in active_sources:
        _append_kev_unavailable_flag(flags_by_source, sources.get("kev"))
    if locked_provider_data and provider_snapshot is not None:
        flags_by_source.setdefault("provider_snapshot", []).append(
            ProviderDataQualityFlag(
                source="provider_snapshot",
                code="snapshot_locked",
                message="Provider snapshot replay is locked; live provider lookups are disabled.",
                severity="info",
            )
        )
    return flags_by_source


def _append_provider_error_flag(
    flags_by_source: dict[str, list[ProviderDataQualityFlag]],
    *,
    source: str,
    diagnostics: ProviderLookupDiagnostics,
    warnings: list[str],
) -> None:
    if not diagnostics.failures and not any("failed" in warning.lower() for warning in warnings):
        return
    flags_by_source.setdefault(source, []).append(
        ProviderDataQualityFlag(
            source=source,
            code="provider_error",
            message=f"{source} provider returned recoverable errors during enrichment.",
            severity="error",
        )
    )


def _append_nvd_missing_flags(
    flags_by_source: dict[str, list[ProviderDataQualityFlag]],
    results: dict[str, NvdData],
) -> None:
    for cve_id, item in results.items():
        if has_nvd_content(item):
            continue
        flags_by_source.setdefault("nvd", []).append(
            ProviderDataQualityFlag(
                source="nvd",
                code="nvd_missing",
                message=f"NVD returned no provider content for {cve_id}.",
                cve_id=cve_id,
            )
        )


def _append_epss_missing_flags(
    flags_by_source: dict[str, list[ProviderDataQualityFlag]],
    results: dict[str, EpssData],
) -> None:
    for cve_id, item in results.items():
        if item.epss is not None or item.percentile is not None or item.date is not None:
            continue
        flags_by_source.setdefault("epss", []).append(
            ProviderDataQualityFlag(
                source="epss",
                code="epss_missing",
                message=f"FIRST EPSS returned no score for {cve_id}.",
                cve_id=cve_id,
            )
        )


def _append_epss_outdated_flag(
    flags_by_source: dict[str, list[ProviderDataQualityFlag]],
    source: tuple[ProviderLookupDiagnostics, list[str]] | None,
) -> None:
    if source is None:
        return
    diagnostics, _warnings = source
    if not diagnostics.stale_cache_hits:
        return
    flags_by_source.setdefault("epss", []).append(
        ProviderDataQualityFlag(
            source="epss",
            code="epss_outdated",
            message=(
                "FIRST EPSS used expired cached data for "
                f"{diagnostics.stale_cache_hits} requested CVE(s)."
            ),
        )
    )


def _append_kev_unavailable_flag(
    flags_by_source: dict[str, list[ProviderDataQualityFlag]],
    source: tuple[ProviderLookupDiagnostics, list[str]] | None,
) -> None:
    if source is None:
        return
    diagnostics, warnings = source
    if not diagnostics.failures and not any("KEV catalog load failed" in item for item in warnings):
        return
    flags_by_source.setdefault("kev", []).append(
        ProviderDataQualityFlag(
            source="kev",
            code="kev_unavailable",
            message="CISA KEV catalog was unavailable; KEV membership may be incomplete.",
            severity="error",
        )
    )


def _nvd_missing_cvss_flags(results: dict[str, NvdData]) -> list[ProviderDataQualityFlag]:
    flags: list[ProviderDataQualityFlag] = []
    for cve_id, item in results.items():
        if has_nvd_content(item) and item.cvss_base_score is None and item.cvss_version is None:
            flags.append(
                ProviderDataQualityFlag(
                    source="nvd",
                    code="nvd_cvss_missing",
                    message=(
                        "NVD returned provider metadata without a CVSS base score "
                        f"or version for {cve_id}."
                    ),
                    cve_id=cve_id,
                )
            )
    return flags

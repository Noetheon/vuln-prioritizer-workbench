"""Orchestrate provider calls."""

from __future__ import annotations

from pathlib import Path

import requests

from app.domain.engine.cache import FileCache
from app.domain.engine.config import (
    DEFAULT_CACHE_DIR,
    DEFAULT_CACHE_TTL_HOURS,
    DEFAULT_NVD_API_KEY_ENV,
)
from app.domain.engine.models import (
    EnrichmentResult,
    EpssData,
    KevData,
    NvdData,
    ProviderLookupDiagnostics,
    ProviderSnapshotReport,
)
from app.domain.engine.provider_snapshot import resolve_snapshot_provider_data
from app.domain.engine.providers.attack import AttackProvider
from app.domain.engine.providers.epss import EpssProvider
from app.domain.engine.providers.kev import KevProvider
from app.domain.engine.providers.nvd import NvdFetchDiagnostics, NvdProvider, has_nvd_content
from app.domain.engine.services.enrichment_quality import (
    provider_enrichment_quality_flags as _provider_data_quality_flags,
)
from app.domain.engine.services.enrichment_results import (
    build_fallback_diagnostics as _build_fallback_diagnostics,
)
from app.domain.engine.services.enrichment_results import (
    build_nvd_fetch_diagnostics as _build_nvd_fetch_diagnostics,
)
from app.domain.engine.services.enrichment_results import (
    merge_provider_results as _merge_provider_results,
)
from app.domain.engine.services.enrichment_results import (
    safe_provider_error as _safe_provider_error,
)
from app.domain.engine.services.enrichment_snapshot import (
    active_provider_sources as _active_provider_sources,
)
from app.domain.engine.services.enrichment_snapshot import (
    snapshot_defensive_contexts as _snapshot_defensive_contexts,
)
from app.domain.engine.services.enrichment_snapshot import (
    snapshot_source_selected as _snapshot_source_selected,
)


class EnrichmentService:
    """Coordinate all provider lookups for a list of CVEs."""

    def __init__(
        self,
        *,
        nvd_api_key_env: str = DEFAULT_NVD_API_KEY_ENV,
        session: requests.Session | None = None,
        use_cache: bool = True,
        cache_dir: Path = DEFAULT_CACHE_DIR,
        cache_ttl_hours: int = DEFAULT_CACHE_TTL_HOURS,
    ) -> None:
        """Initialize a new instance of EnrichmentService."""
        shared_session = session or requests.Session()
        cache = FileCache(cache_dir, cache_ttl_hours) if use_cache else None
        nvd_session = session if session is not None else None
        self.nvd = NvdProvider.from_env(
            api_key_env=nvd_api_key_env, session=nvd_session, cache=cache
        )
        self.epss = EpssProvider(session=shared_session, cache=cache)
        self.kev = KevProvider(session=shared_session, cache=cache)
        self.attack = AttackProvider()
        self.cache = cache
        self.cache_dir = cache_dir if use_cache else None
        self.last_nvd_diagnostics = NvdFetchDiagnostics()
        self.last_epss_diagnostics = ProviderLookupDiagnostics()
        self.last_kev_diagnostics = ProviderLookupDiagnostics()

    def enrich(
        self,
        cve_ids: list[str],
        *,
        attack_enabled: bool,
        attack_source: str = "none",
        offline_kev_file: Path | None = None,
        attack_mapping_file: Path | None = None,
        attack_technique_metadata_file: Path | None = None,
        offline_attack_file: Path | None = None,
        provider_snapshot: ProviderSnapshotReport | None = None,
        locked_provider_data: bool = False,
    ) -> EnrichmentResult:
        """Enrich method for EnrichmentService."""
        if locked_provider_data and provider_snapshot is None:
            raise ValueError("Locked provider data requires a provider snapshot file.")

        nvd_results, nvd_warnings = self._resolve_nvd_results(
            cve_ids,
            provider_snapshot=provider_snapshot,
            locked_provider_data=locked_provider_data,
        )
        epss_results, epss_warnings = self._resolve_epss_results(
            cve_ids,
            provider_snapshot=provider_snapshot,
            locked_provider_data=locked_provider_data,
        )
        kev_results, kev_warnings = self._resolve_kev_results(
            cve_ids,
            provider_snapshot=provider_snapshot,
            locked_provider_data=locked_provider_data,
            offline_kev_file=offline_kev_file,
        )
        attack_results, attack_metadata, attack_warnings = self.attack.fetch_many(
            cve_ids,
            enabled=attack_enabled,
            source=attack_source,
            mapping_file=attack_mapping_file,
            technique_metadata_file=attack_technique_metadata_file,
            offline_file=offline_attack_file,
        )
        defensive_contexts = _snapshot_defensive_contexts(
            provider_snapshot=provider_snapshot,
            cve_ids=cve_ids,
        )
        nvd_diagnostics = ProviderLookupDiagnostics(
            requested=self.last_nvd_diagnostics.requested,
            cache_hits=self.last_nvd_diagnostics.cache_hits,
            network_fetches=self.last_nvd_diagnostics.network_fetches,
            failures=self.last_nvd_diagnostics.failures,
            content_hits=self.last_nvd_diagnostics.content_hits,
            empty_records=self.last_nvd_diagnostics.empty_records,
            stale_cache_hits=self.last_nvd_diagnostics.stale_cache_hits,
            degraded=self.last_nvd_diagnostics.degraded,
        )
        epss_diagnostics = self.last_epss_diagnostics
        kev_diagnostics = self.last_kev_diagnostics

        return EnrichmentResult(
            nvd=nvd_results,
            epss=epss_results,
            kev=kev_results,
            attack=attack_results,
            defensive_contexts=defensive_contexts,
            defensive_context_sources=sorted(
                {context.source for items in defensive_contexts.values() for context in items}
            ),
            attack_source=attack_metadata["source"] or "none",
            attack_mapping_file=attack_metadata["mapping_file"],
            attack_technique_metadata_file=attack_metadata["technique_metadata_file"],
            attack_source_version=attack_metadata["source_version"],
            attack_version=attack_metadata["attack_version"],
            attack_domain=attack_metadata["domain"],
            mapping_framework=attack_metadata["mapping_framework"],
            mapping_framework_version=attack_metadata["mapping_framework_version"],
            attack_mapping_file_sha256=attack_metadata.get("mapping_file_sha256"),
            attack_technique_metadata_file_sha256=attack_metadata.get(
                "technique_metadata_file_sha256"
            ),
            attack_metadata_format=attack_metadata.get("metadata_format"),
            attack_metadata_source=attack_metadata.get("metadata_source"),
            attack_stix_spec_version=attack_metadata.get("stix_spec_version"),
            attack_mapping_created_at=attack_metadata.get("mapping_created_at"),
            attack_mapping_updated_at=attack_metadata.get("mapping_updated_at"),
            attack_mapping_organization=attack_metadata.get("mapping_organization"),
            attack_mapping_author=attack_metadata.get("mapping_author"),
            attack_mapping_contact=attack_metadata.get("mapping_contact"),
            warnings=nvd_warnings + epss_warnings + kev_warnings + attack_warnings,
            nvd_diagnostics=nvd_diagnostics,
            epss_diagnostics=epss_diagnostics,
            kev_diagnostics=kev_diagnostics,
            provider_data_quality_flags=_provider_data_quality_flags(
                nvd_results=nvd_results,
                epss_results=epss_results,
                provider_snapshot=provider_snapshot,
                locked_provider_data=locked_provider_data,
                active_provider_sources=_active_provider_sources(
                    provider_snapshot=provider_snapshot,
                    locked_provider_data=locked_provider_data,
                ),
                nvd=(nvd_diagnostics, nvd_warnings),
                epss=(epss_diagnostics, epss_warnings),
                kev=(kev_diagnostics, kev_warnings),
            ),
            provider_snapshot_sources=(
                list(provider_snapshot.metadata.selected_sources) if provider_snapshot else []
            ),
            provider_cache_timestamps=self._provider_cache_timestamps(),
        )

    def _provider_cache_timestamps(self) -> dict[str, str | None]:
        """Provider cache timestamps method for EnrichmentService."""
        if self.cache is None:
            return {}
        return {
            "nvd": self.cache.latest_cached_at("nvd"),
            "epss": self.cache.latest_cached_at("epss"),
            "kev": self.cache.latest_cached_at("kev"),
        }

    def _resolve_nvd_results(
        self,
        cve_ids: list[str],
        *,
        provider_snapshot: ProviderSnapshotReport | None,
        locked_provider_data: bool,
    ) -> tuple[dict[str, NvdData], list[str]]:
        """Resolve nvd results method for EnrichmentService."""
        snapshot_results: dict[str, NvdData] = {}
        missing_ids = list(cve_ids)
        if provider_snapshot is not None:
            if not _snapshot_source_selected(provider_snapshot, "nvd"):
                if locked_provider_data:
                    self.last_nvd_diagnostics = NvdFetchDiagnostics(requested=0)
                    return _merge_provider_results(cve_ids, {}, {}, NvdData), []
                missing_ids = list(cve_ids)
            else:
                resolved, missing_ids = resolve_snapshot_provider_data(
                    provider_snapshot,
                    source_name="nvd",
                    cve_ids=cve_ids,
                )
                snapshot_results = {
                    cve_id: data for cve_id, data in resolved.items() if isinstance(data, NvdData)
                }
        if locked_provider_data and missing_ids:
            raise ValueError(
                "Provider snapshot is missing NVD coverage for: " + ", ".join(sorted(missing_ids))
            )
        live_results: dict[str, NvdData] = {}
        warnings: list[str] = []
        if missing_ids:
            try:
                live_results, warnings = self.nvd.fetch_many(missing_ids)
            except Exception as exc:  # noqa: BLE001 - NVD must not abort analysis/import
                live_results = {cve_id: NvdData(cve_id=cve_id) for cve_id in missing_ids}
                warnings = [f"NVD provider failed: {_safe_provider_error(exc, provider=self.nvd)}"]
                self.last_nvd_diagnostics = NvdFetchDiagnostics(
                    requested=len(missing_ids),
                    failures=len(missing_ids) or 1,
                    empty_records=len(missing_ids),
                    degraded=True,
                )
            else:
                provider_diagnostics = getattr(self.nvd, "last_diagnostics", None)
                self.last_nvd_diagnostics = (
                    provider_diagnostics
                    if isinstance(provider_diagnostics, NvdFetchDiagnostics)
                    else _build_nvd_fetch_diagnostics(cve_ids, live_results)
                )
        else:
            self.last_nvd_diagnostics = NvdFetchDiagnostics(
                requested=len(cve_ids),
                cache_hits=0,
                network_fetches=0,
                failures=0,
                content_hits=sum(1 for item in snapshot_results.values() if has_nvd_content(item)),
                empty_records=sum(
                    1 for item in snapshot_results.values() if not has_nvd_content(item)
                ),
            )
        return _merge_provider_results(cve_ids, snapshot_results, live_results, NvdData), warnings

    def _resolve_epss_results(
        self,
        cve_ids: list[str],
        *,
        provider_snapshot: ProviderSnapshotReport | None,
        locked_provider_data: bool,
    ) -> tuple[dict[str, EpssData], list[str]]:
        """Resolve epss results method for EnrichmentService."""
        snapshot_results: dict[str, EpssData] = {}
        missing_ids = list(cve_ids)
        if provider_snapshot is not None:
            if not _snapshot_source_selected(provider_snapshot, "epss"):
                if locked_provider_data:
                    self.last_epss_diagnostics = ProviderLookupDiagnostics(requested=0)
                    return _merge_provider_results(cve_ids, {}, {}, EpssData), []
                missing_ids = list(cve_ids)
            else:
                resolved, missing_ids = resolve_snapshot_provider_data(
                    provider_snapshot,
                    source_name="epss",
                    cve_ids=cve_ids,
                )
                snapshot_results = {
                    cve_id: data for cve_id, data in resolved.items() if isinstance(data, EpssData)
                }
        if locked_provider_data and missing_ids:
            raise ValueError(
                "Provider snapshot is missing EPSS coverage for: " + ", ".join(sorted(missing_ids))
            )
        live_results: dict[str, EpssData]
        warnings: list[str]
        if missing_ids:
            try:
                live_results, warnings = self.epss.fetch_many(missing_ids)
            except Exception as exc:  # noqa: BLE001 - EPSS must not abort analysis/import
                live_results = {cve_id: EpssData(cve_id=cve_id) for cve_id in missing_ids}
                warnings = [f"EPSS provider failed: {exc}"]
                self.last_epss_diagnostics = ProviderLookupDiagnostics(
                    requested=len(missing_ids),
                    failures=len(missing_ids) or 1,
                    empty_records=len(missing_ids),
                    degraded=True,
                )
            else:
                self.last_epss_diagnostics = getattr(
                    self.epss,
                    "last_diagnostics",
                    _build_fallback_diagnostics(cve_ids, live_results, EpssData),
                )
        else:
            live_results, warnings = {}, []
            # Snapshot-only replay still produces diagnostics so freshness and
            # quality flags can be evaluated without a live EPSS request.
            content_hits = sum(
                1
                for item in snapshot_results.values()
                if item.epss is not None or item.percentile is not None or item.date is not None
            )
            self.last_epss_diagnostics = ProviderLookupDiagnostics(
                requested=len(cve_ids),
                content_hits=content_hits,
                empty_records=max(len(cve_ids) - content_hits, 0),
            )
        return _merge_provider_results(cve_ids, snapshot_results, live_results, EpssData), warnings

    def _resolve_kev_results(
        self,
        cve_ids: list[str],
        *,
        provider_snapshot: ProviderSnapshotReport | None,
        locked_provider_data: bool,
        offline_kev_file: Path | None,
    ) -> tuple[dict[str, KevData], list[str]]:
        """Resolve kev results method for EnrichmentService."""
        snapshot_results: dict[str, KevData] = {}
        missing_ids = list(cve_ids)
        if provider_snapshot is not None:
            if not _snapshot_source_selected(provider_snapshot, "kev"):
                if locked_provider_data:
                    self.last_kev_diagnostics = ProviderLookupDiagnostics(requested=0)
                    return _merge_provider_results(cve_ids, {}, {}, KevData), []
                missing_ids = list(cve_ids)
            else:
                resolved, missing_ids = resolve_snapshot_provider_data(
                    provider_snapshot,
                    source_name="kev",
                    cve_ids=cve_ids,
                )
                snapshot_results = {
                    cve_id: data for cve_id, data in resolved.items() if isinstance(data, KevData)
                }
        if locked_provider_data and missing_ids:
            raise ValueError(
                "Provider snapshot is missing KEV coverage for: " + ", ".join(sorted(missing_ids))
            )
        if missing_ids:
            try:
                live_results, warnings = self.kev.fetch_many(
                    missing_ids,
                    offline_file=offline_kev_file,
                )
            except Exception as exc:  # noqa: BLE001 - KEV must not abort analysis/import
                live_results = {
                    cve_id: KevData(cve_id=cve_id, in_kev=False) for cve_id in missing_ids
                }
                warnings = [f"KEV provider failed: {exc}"]
                self.last_kev_diagnostics = ProviderLookupDiagnostics(
                    requested=len(missing_ids),
                    failures=len(missing_ids) or 1,
                    empty_records=len(missing_ids),
                    degraded=True,
                )
            else:
                self.last_kev_diagnostics = getattr(
                    self.kev,
                    "last_diagnostics",
                    _build_fallback_diagnostics(cve_ids, live_results, KevData),
                )
        else:
            live_results, warnings = {}, []
            self.last_kev_diagnostics = ProviderLookupDiagnostics(
                requested=len(cve_ids),
                content_hits=sum(1 for item in snapshot_results.values() if item.in_kev),
            )
        return _merge_provider_results(cve_ids, snapshot_results, live_results, KevData), warnings

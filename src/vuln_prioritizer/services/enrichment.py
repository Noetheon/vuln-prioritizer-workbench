"""Orchestrate provider calls."""

from __future__ import annotations

from pathlib import Path
from typing import TypeVar

import requests

from vuln_prioritizer.cache import FileCache
from vuln_prioritizer.config import (
    DEFAULT_CACHE_DIR,
    DEFAULT_CACHE_TTL_HOURS,
    DEFAULT_NVD_API_KEY_ENV,
)
from vuln_prioritizer.models import (
    EnrichmentResult,
    EpssData,
    KevData,
    NvdData,
    ProviderLookupDiagnostics,
    ProviderSnapshotReport,
)
from vuln_prioritizer.provider_snapshot import resolve_snapshot_provider_data
from vuln_prioritizer.providers.attack import AttackProvider
from vuln_prioritizer.providers.epss import EpssProvider
from vuln_prioritizer.providers.kev import KevProvider
from vuln_prioritizer.providers.nvd import NvdFetchDiagnostics, NvdProvider, has_nvd_content

_T = TypeVar("_T", NvdData, EpssData, KevData)


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
        shared_session = session or requests.Session()
        cache = FileCache(cache_dir, cache_ttl_hours) if use_cache else None
        self.nvd = NvdProvider.from_env(
            api_key_env=nvd_api_key_env, session=shared_session, cache=cache
        )
        self.epss = EpssProvider(session=shared_session, cache=cache)
        self.kev = KevProvider(session=shared_session, cache=cache)
        self.attack = AttackProvider()
        self.cache = cache
        self.cache_dir = cache_dir if use_cache else None
        self.last_nvd_diagnostics = NvdFetchDiagnostics()

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
        if locked_provider_data and provider_snapshot is None:
            raise ValueError("--locked-provider-data requires --provider-snapshot-file.")

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

        return EnrichmentResult(
            nvd=nvd_results,
            epss=epss_results,
            kev=kev_results,
            attack=attack_results,
            attack_source=attack_metadata["source"] or "none",
            attack_mapping_file=attack_metadata["mapping_file"],
            attack_technique_metadata_file=attack_metadata["technique_metadata_file"],
            attack_source_version=attack_metadata["source_version"],
            attack_version=attack_metadata["attack_version"],
            attack_domain=attack_metadata["domain"],
            mapping_framework=attack_metadata["mapping_framework"],
            mapping_framework_version=attack_metadata["mapping_framework_version"],
            warnings=nvd_warnings + epss_warnings + kev_warnings + attack_warnings,
            nvd_diagnostics=ProviderLookupDiagnostics(
                requested=self.last_nvd_diagnostics.requested,
                cache_hits=self.last_nvd_diagnostics.cache_hits,
                network_fetches=self.last_nvd_diagnostics.network_fetches,
                failures=self.last_nvd_diagnostics.failures,
                content_hits=self.last_nvd_diagnostics.content_hits,
            ),
            provider_snapshot_sources=(
                list(provider_snapshot.metadata.selected_sources) if provider_snapshot else []
            ),
        )

    def _resolve_nvd_results(
        self,
        cve_ids: list[str],
        *,
        provider_snapshot: ProviderSnapshotReport | None,
        locked_provider_data: bool,
    ) -> tuple[dict[str, NvdData], list[str]]:
        snapshot_results: dict[str, NvdData] = {}
        missing_ids = list(cve_ids)
        if provider_snapshot is not None:
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
            live_results, warnings = self.nvd.fetch_many(missing_ids)
            self.last_nvd_diagnostics = self.nvd.last_diagnostics
        else:
            self.last_nvd_diagnostics = NvdFetchDiagnostics(
                requested=len(cve_ids),
                cache_hits=0,
                network_fetches=0,
                failures=0,
                content_hits=sum(1 for item in snapshot_results.values() if has_nvd_content(item)),
            )
        return _merge_provider_results(cve_ids, snapshot_results, live_results, NvdData), warnings

    def _resolve_epss_results(
        self,
        cve_ids: list[str],
        *,
        provider_snapshot: ProviderSnapshotReport | None,
        locked_provider_data: bool,
    ) -> tuple[dict[str, EpssData], list[str]]:
        snapshot_results: dict[str, EpssData] = {}
        missing_ids = list(cve_ids)
        if provider_snapshot is not None:
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
        live_results, warnings = self.epss.fetch_many(missing_ids) if missing_ids else ({}, [])
        return _merge_provider_results(cve_ids, snapshot_results, live_results, EpssData), warnings

    def _resolve_kev_results(
        self,
        cve_ids: list[str],
        *,
        provider_snapshot: ProviderSnapshotReport | None,
        locked_provider_data: bool,
        offline_kev_file: Path | None,
    ) -> tuple[dict[str, KevData], list[str]]:
        snapshot_results: dict[str, KevData] = {}
        missing_ids = list(cve_ids)
        if provider_snapshot is not None:
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
        live_results, warnings = (
            self.kev.fetch_many(missing_ids, offline_file=offline_kev_file)
            if missing_ids
            else ({}, [])
        )
        return _merge_provider_results(cve_ids, snapshot_results, live_results, KevData), warnings


def _merge_provider_results(
    cve_ids: list[str],
    snapshot_results: dict[str, _T],
    live_results: dict[str, _T],
    model_cls: type[_T],
) -> dict[str, _T]:
    merged: dict[str, _T] = {}
    for cve_id in cve_ids:
        if cve_id in snapshot_results:
            merged[cve_id] = snapshot_results[cve_id]
        elif cve_id in live_results:
            merged[cve_id] = live_results[cve_id]
        else:
            merged[cve_id] = model_cls(cve_id=cve_id)
    return merged

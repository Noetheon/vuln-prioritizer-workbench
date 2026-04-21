"""Orchestrate provider calls."""

from __future__ import annotations

from pathlib import Path

import requests

from vuln_prioritizer.cache import FileCache
from vuln_prioritizer.config import (
    DEFAULT_CACHE_DIR,
    DEFAULT_CACHE_TTL_HOURS,
    DEFAULT_NVD_API_KEY_ENV,
)
from vuln_prioritizer.models import EnrichmentResult
from vuln_prioritizer.providers.attack import AttackProvider
from vuln_prioritizer.providers.epss import EpssProvider
from vuln_prioritizer.providers.kev import KevProvider
from vuln_prioritizer.providers.nvd import NvdProvider


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
    ) -> EnrichmentResult:
        nvd_results, nvd_warnings = self.nvd.fetch_many(cve_ids)
        epss_results, epss_warnings = self.epss.fetch_many(cve_ids)
        kev_results, kev_warnings = self.kev.fetch_many(cve_ids, offline_file=offline_kev_file)
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
        )

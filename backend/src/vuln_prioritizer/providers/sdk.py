"""Static provider extension contracts.

The provider SDK is intentionally declarative and local-only. It documents the
shape required by provider implementations without loading arbitrary entry
points, importing user supplied paths, or fetching executable code.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol, cast

import requests

from vuln_prioritizer.cache import FileCache
from vuln_prioritizer.config import DEFAULT_NVD_API_KEY_ENV
from vuln_prioritizer.models_provider import (
    ProviderCacheContract,
    ProviderDataQualityFlag,
    ProviderEnrichmentResult,
    ProviderLookupDiagnostics,
    ProviderSnapshot,
    ProviderStatus,
)
from vuln_prioritizer.providers.epss import EpssProvider
from vuln_prioritizer.providers.kev import KevProvider
from vuln_prioritizer.providers.nvd import NvdProvider
from vuln_prioritizer.utils import iso_utc_now

STATIC_PROVIDER_EXTENSION_POLICY = "static-local-only"
ProviderFetchResult = tuple[Mapping[str, Any], list[str]]


class CveProvider(Protocol):
    """Protocol implemented by CVE enrichment providers."""

    last_diagnostics: Any

    def fetch_many(self, cve_ids: list[str], **kwargs: Any) -> ProviderFetchResult:
        """Return provider data keyed by CVE identifier."""


class ProviderEnrichmentClient(Protocol):
    """Uniform enrichment service contract exposed to analysis flows."""

    @property
    def source(self) -> str:
        """Stable provider source name."""
        ...

    def enrich(self, cve_ids: Sequence[str], **kwargs: Any) -> ProviderEnrichmentResult:
        """Return provider records, status, snapshot DTO, and data-quality flags."""
        ...


@dataclass(frozen=True)
class ProviderDefinition:
    """Declarative contract for a locally registered enrichment provider."""

    name: str
    provider: CveProvider
    source_kind: str
    cache_namespace: str | None = None
    cache_key_template: str | None = "{cve_id}"
    cache_ttl_seconds: int | None = None
    stale_while_error: bool = True
    offline_capable: bool = False
    remote_code_loading: bool = False


@dataclass(frozen=True)
class ProviderClientAdapter:
    """Adapter that exposes the VPW provider service contract over fetch_many providers."""

    definition: ProviderDefinition
    cache: FileCache | None = None

    @property
    def source(self) -> str:
        return self.definition.name

    def enrich(self, cve_ids: Sequence[str], **kwargs: Any) -> ProviderEnrichmentResult:
        """Enrich CVEs without letting provider failures abort the caller."""

        requested_cves = list(cve_ids)
        completed_at = iso_utc_now()
        warnings: list[str]
        records: Mapping[str, Any]
        try:
            records, warnings = self.definition.provider.fetch_many(requested_cves, **kwargs)
            diagnostics = provider_diagnostics_from_any(
                getattr(self.definition.provider, "last_diagnostics", None),
                requested_count=len(requested_cves),
                record_count=len(records),
            )
        except Exception as exc:  # noqa: BLE001 - provider contract degrades by design
            records = {}
            warnings = [f"{self.source} provider failed: {exc}"]
            diagnostics = ProviderLookupDiagnostics(
                requested=len(requested_cves),
                failures=len(requested_cves) or 1,
                empty_records=len(requested_cves),
                degraded=True,
            )

        cache_contract = provider_cache_contract(self.definition, cache=self.cache)
        flags = provider_data_quality_flags(
            source=self.source,
            diagnostics=diagnostics,
            warnings=warnings,
        )
        status = provider_status_from_diagnostics(
            source=self.source,
            diagnostics=diagnostics,
            cache_contract=cache_contract,
            cache=self.cache,
            completed_at=completed_at,
            data_quality_flags=flags,
        )
        snapshot = ProviderSnapshot(
            source=self.source,
            generated_at=completed_at,
            requested_cves=len(requested_cves),
            content_hits=status.content_hits,
            record_keys=sorted(str(key) for key in records),
            status=status,
        )
        return ProviderEnrichmentResult(
            source=self.source,
            records=dict(records),
            warnings=list(warnings),
            status=status,
            snapshot=snapshot,
        )


def validate_provider_definition(definition: ProviderDefinition) -> None:
    """Validate provider metadata without performing provider lookups."""

    if not definition.name or definition.name.strip() != definition.name:
        raise ValueError("Provider names must be non-empty and trimmed.")
    if definition.cache_namespace is not None and (
        not definition.cache_namespace
        or definition.cache_namespace.strip() != definition.cache_namespace
    ):
        raise ValueError("Provider cache namespaces must be non-empty and trimmed.")
    if definition.cache_key_template is not None and not definition.cache_key_template.strip():
        raise ValueError("Provider cache key templates must not be blank.")
    if definition.cache_ttl_seconds is not None and definition.cache_ttl_seconds < 0:
        raise ValueError("Provider cache TTL must not be negative.")
    if definition.remote_code_loading:
        raise ValueError("Provider definitions must not load remote code.")
    if not hasattr(definition.provider, "fetch_many"):
        raise ValueError(f"Provider {definition.name!r} does not implement fetch_many.")


def build_provider_registry(
    definitions: tuple[ProviderDefinition, ...],
) -> Mapping[str, ProviderDefinition]:
    """Build a static provider registry from explicit local definitions."""

    registry: dict[str, ProviderDefinition] = {}
    for definition in definitions:
        validate_provider_definition(definition)
        if definition.name in registry:
            raise ValueError(f"Duplicate provider name: {definition.name}")
        registry[definition.name] = definition
    return registry


def build_provider_clients(
    definitions: tuple[ProviderDefinition, ...],
    *,
    cache: FileCache | None = None,
) -> Mapping[str, ProviderEnrichmentClient]:
    """Build uniform enrichment clients from static provider definitions."""

    return {
        name: ProviderClientAdapter(definition=definition, cache=cache)
        for name, definition in build_provider_registry(definitions).items()
    }


def builtin_provider_definitions(
    *,
    cache: FileCache | None = None,
    session: requests.Session | None = None,
    nvd_api_key_env: str = DEFAULT_NVD_API_KEY_ENV,
) -> tuple[ProviderDefinition, ...]:
    """Return explicit local definitions for the built-in provider implementations."""

    shared_session = session or requests.Session()
    return (
        ProviderDefinition(
            name="nvd",
            provider=cast(
                CveProvider,
                NvdProvider.from_env(
                    api_key_env=nvd_api_key_env,
                    session=shared_session,
                    cache=cache,
                ),
            ),
            source_kind="nvd",
            cache_namespace="nvd",
            cache_key_template="{cve_id}",
            offline_capable=True,
        ),
        ProviderDefinition(
            name="epss",
            provider=cast(CveProvider, EpssProvider(session=shared_session, cache=cache)),
            source_kind="epss",
            cache_namespace="epss",
            cache_key_template="{cve_id}",
            offline_capable=True,
        ),
        ProviderDefinition(
            name="kev",
            provider=cast(CveProvider, KevProvider(session=shared_session, cache=cache)),
            source_kind="kev",
            cache_namespace="kev",
            cache_key_template="catalog",
            offline_capable=True,
        ),
    )


def provider_cache_contract(
    definition: ProviderDefinition,
    *,
    cache: FileCache | None = None,
) -> ProviderCacheContract:
    """Return the declared cache contract for a provider definition."""

    ttl_seconds = definition.cache_ttl_seconds
    if ttl_seconds is None and cache is not None:
        ttl_seconds = int(cache.ttl.total_seconds())
    return ProviderCacheContract(
        source=definition.name,
        cache_enabled=cache is not None and definition.cache_namespace is not None,
        namespace=definition.cache_namespace,
        key_template=definition.cache_key_template,
        ttl_seconds=ttl_seconds,
        stale_while_error=definition.stale_while_error,
    )


def provider_status_from_diagnostics(
    *,
    source: str,
    diagnostics: ProviderLookupDiagnostics,
    cache_contract: ProviderCacheContract,
    completed_at: str,
    data_quality_flags: Sequence[ProviderDataQualityFlag] = (),
    cache: FileCache | None = None,
) -> ProviderStatus:
    """Build the source status DTO from normalized lookup diagnostics."""

    latest_cached_at = None
    if cache is not None and cache_contract.namespace:
        latest_cached_at = cache.latest_cached_at(cache_contract.namespace)
    cache_misses = max(diagnostics.requested - diagnostics.cache_hits, 0)
    return ProviderStatus(
        source=source,
        last_sync=latest_cached_at or completed_at,
        requested=diagnostics.requested,
        cache_hit=diagnostics.cache_hits > 0 or diagnostics.stale_cache_hits > 0,
        cache_miss=cache_misses > 0,
        cache_hits=diagnostics.cache_hits,
        cache_misses=cache_misses,
        stale_cache_hits=diagnostics.stale_cache_hits,
        network_fetches=diagnostics.network_fetches,
        failures=diagnostics.failures,
        content_hits=diagnostics.content_hits,
        empty_records=diagnostics.empty_records,
        degraded=diagnostics.degraded or diagnostics.failures > 0,
        cache=cache_contract,
        data_quality_flags=list(data_quality_flags),
    )


def provider_data_quality_flags(
    *,
    source: str,
    diagnostics: ProviderLookupDiagnostics,
    warnings: Sequence[str] = (),
) -> list[ProviderDataQualityFlag]:
    """Convert recoverable provider problems into data-quality flags."""

    flags: list[ProviderDataQualityFlag] = []
    if diagnostics.failures:
        flags.append(
            ProviderDataQualityFlag(
                source=source,
                code="provider_failure",
                message=f"{source} lookup degraded with {diagnostics.failures} failure(s).",
            )
        )
    if diagnostics.stale_cache_hits:
        flags.append(
            ProviderDataQualityFlag(
                source=source,
                code="stale_cache",
                message=(
                    f"{source} used expired cached data for "
                    f"{diagnostics.stale_cache_hits} requested CVE(s)."
                ),
            )
        )
    if diagnostics.empty_records:
        flags.append(
            ProviderDataQualityFlag(
                source=source,
                code="provider_missing_data",
                message=(
                    f"{source} returned no provider content for "
                    f"{diagnostics.empty_records} requested CVE(s)."
                ),
            )
        )
    for warning in warnings:
        flags.append(
            ProviderDataQualityFlag(
                source=source,
                code="provider_warning",
                message=str(warning),
            )
        )
    if diagnostics.degraded and not flags:
        flags.append(
            ProviderDataQualityFlag(
                source=source,
                code="provider_degraded",
                message=f"{source} provider marked the lookup as degraded.",
            )
        )
    return flags


def provider_diagnostics_from_any(
    value: Any,
    *,
    requested_count: int,
    record_count: int = 0,
) -> ProviderLookupDiagnostics:
    """Normalize provider-specific diagnostics into the shared DTO."""

    content_hits = _int_attr(value, "content_hits", record_count)
    empty_records = _int_attr(value, "empty_records", max(requested_count - content_hits, 0))
    failures = _int_attr(value, "failures", 0)
    stale_cache_hits = _int_attr(value, "stale_cache_hits", 0)
    degraded = _bool_attr(value, "degraded", failures > 0 or stale_cache_hits > 0)
    return ProviderLookupDiagnostics(
        requested=_int_attr(value, "requested", requested_count),
        cache_hits=_int_attr(value, "cache_hits", 0),
        network_fetches=_int_attr(value, "network_fetches", 0),
        failures=failures,
        content_hits=content_hits,
        empty_records=empty_records,
        stale_cache_hits=stale_cache_hits,
        degraded=degraded,
    )


def _int_attr(value: Any, name: str, default: int) -> int:
    try:
        raw = getattr(value, name)
    except AttributeError:
        raw = default
    if raw is None:
        return default
    return int(raw)


def _bool_attr(value: Any, name: str, default: bool) -> bool:
    try:
        raw = getattr(value, name)
    except AttributeError:
        raw = default
    if raw is None:
        return default
    return bool(raw)


__all__ = [
    "CveProvider",
    "ProviderClientAdapter",
    "ProviderDefinition",
    "ProviderEnrichmentClient",
    "ProviderFetchResult",
    "STATIC_PROVIDER_EXTENSION_POLICY",
    "build_provider_clients",
    "build_provider_registry",
    "builtin_provider_definitions",
    "provider_cache_contract",
    "provider_data_quality_flags",
    "provider_diagnostics_from_any",
    "provider_status_from_diagnostics",
    "validate_provider_definition",
]

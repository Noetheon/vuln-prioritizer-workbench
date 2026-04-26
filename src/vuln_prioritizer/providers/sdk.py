"""Static provider extension contracts.

The provider SDK is intentionally declarative and local-only. It documents the
shape required by provider implementations without loading arbitrary entry
points, importing user supplied paths, or fetching executable code.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol, cast

import requests

from vuln_prioritizer.cache import FileCache
from vuln_prioritizer.config import DEFAULT_NVD_API_KEY_ENV
from vuln_prioritizer.providers.epss import EpssProvider
from vuln_prioritizer.providers.kev import KevProvider
from vuln_prioritizer.providers.nvd import NvdProvider

STATIC_PROVIDER_EXTENSION_POLICY = "static-local-only"
ProviderFetchResult = tuple[Mapping[str, Any], list[str]]


class CveProvider(Protocol):
    """Protocol implemented by CVE enrichment providers."""

    last_diagnostics: Any

    def fetch_many(self, cve_ids: list[str], **kwargs: Any) -> ProviderFetchResult:
        """Return provider data keyed by CVE identifier."""


@dataclass(frozen=True)
class ProviderDefinition:
    """Declarative contract for a locally registered enrichment provider."""

    name: str
    provider: CveProvider
    source_kind: str
    cache_namespace: str | None = None
    offline_capable: bool = False
    remote_code_loading: bool = False


def validate_provider_definition(definition: ProviderDefinition) -> None:
    """Validate provider metadata without performing provider lookups."""

    if not definition.name or definition.name.strip() != definition.name:
        raise ValueError("Provider names must be non-empty and trimmed.")
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
            offline_capable=True,
        ),
        ProviderDefinition(
            name="epss",
            provider=cast(CveProvider, EpssProvider(session=shared_session, cache=cache)),
            source_kind="epss",
            cache_namespace="epss",
            offline_capable=True,
        ),
        ProviderDefinition(
            name="kev",
            provider=cast(CveProvider, KevProvider(session=shared_session, cache=cache)),
            source_kind="kev",
            cache_namespace="kev",
            offline_capable=True,
        ),
    )


__all__ = [
    "CveProvider",
    "ProviderDefinition",
    "ProviderFetchResult",
    "STATIC_PROVIDER_EXTENSION_POLICY",
    "build_provider_registry",
    "builtin_provider_definitions",
    "validate_provider_definition",
]

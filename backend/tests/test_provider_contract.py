from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import pytest

from vuln_prioritizer.cache import FileCache
from vuln_prioritizer.models import ProviderLookupDiagnostics
from vuln_prioritizer.providers.sdk import (
    ProviderClientAdapter,
    ProviderDefinition,
    build_provider_clients,
    provider_cache_contract,
    validate_provider_definition,
)


class FakeProvider:
    def __init__(
        self,
        *,
        diagnostics: ProviderLookupDiagnostics | None = None,
        warnings: list[str] | None = None,
    ) -> None:
        self.last_diagnostics = diagnostics or ProviderLookupDiagnostics()
        self.warnings = warnings or []
        self.calls: list[tuple[list[str], dict[str, Any]]] = []

    def fetch_many(
        self,
        cve_ids: Sequence[str],
        **kwargs: Any,
    ) -> tuple[Mapping[str, Any], list[str]]:
        self.calls.append((list(cve_ids), kwargs))
        return ({cve_id: {"source": kwargs.get("source", "fake")} for cve_id in cve_ids}, [])


class WarningProvider(FakeProvider):
    def fetch_many(
        self,
        cve_ids: Sequence[str],
        **kwargs: Any,
    ) -> tuple[Mapping[str, Any], list[str]]:
        self.calls.append((list(cve_ids), kwargs))
        return ({cve_id: {"source": "stale"} for cve_id in cve_ids}, self.warnings)


class ExplodingProvider:
    last_diagnostics = ProviderLookupDiagnostics()

    def fetch_many(
        self,
        cve_ids: Sequence[str],
        **kwargs: Any,
    ) -> tuple[Mapping[str, Any], list[str]]:
        raise RuntimeError("provider offline")


def test_provider_client_adapter_exposes_enrich_status_and_snapshot_contract(
    tmp_path: Path,
) -> None:
    cache = FileCache(tmp_path / "cache", ttl_hours=2)
    cache.set_json("fake", "CVE-2026-0001", {"cached": True})
    provider = FakeProvider(
        diagnostics=ProviderLookupDiagnostics(
            requested=2,
            cache_hits=1,
            network_fetches=1,
            content_hits=2,
        )
    )
    definition = ProviderDefinition(
        name="fake",
        provider=provider,
        source_kind="fixture",
        cache_namespace="fake",
        cache_key_template="{cve_id}",
    )

    result = ProviderClientAdapter(definition=definition, cache=cache).enrich(
        ["CVE-2026-0001", "CVE-2026-0002"],
        refresh=True,
        source="unit-test",
    )

    assert provider.calls == [
        (
            ["CVE-2026-0001", "CVE-2026-0002"],
            {"refresh": True, "source": "unit-test"},
        )
    ]
    assert result.source == "fake"
    assert result.status.source == "fake"
    assert result.status.last_sync == cache.latest_cached_at("fake")
    assert result.status.cache_hit is True
    assert result.status.cache_miss is True
    assert result.status.cache_hits == 1
    assert result.status.cache_misses == 1
    assert result.status.data_quality_flags == []
    assert result.status.cache.namespace == "fake"
    assert result.status.cache.key_template == "{cve_id}"
    assert result.status.cache.ttl_seconds == 7200
    assert result.snapshot.source == "fake"
    assert result.snapshot.requested_cves == 2
    assert result.snapshot.content_hits == 2
    assert result.snapshot.record_keys == ["CVE-2026-0001", "CVE-2026-0002"]


def test_provider_clients_share_enrich_contract_for_nvd_epss_and_kev() -> None:
    definitions = tuple(
        ProviderDefinition(
            name=name,
            provider=FakeProvider(
                diagnostics=ProviderLookupDiagnostics(
                    requested=1,
                    network_fetches=1,
                    content_hits=1,
                )
            ),
            source_kind=name,
            cache_namespace=name,
            cache_key_template="catalog" if name == "kev" else "{cve_id}",
        )
        for name in ("nvd", "epss", "kev")
    )

    clients = build_provider_clients(definitions)

    assert set(clients) == {"nvd", "epss", "kev"}
    for source, client in clients.items():
        result = client.enrich(["CVE-2026-0001"])
        assert result.source == source
        assert result.status.source == source
        assert result.status.network_fetches == 1
        assert result.status.content_hits == 1
        assert result.snapshot.record_keys == ["CVE-2026-0001"]


def test_provider_failure_becomes_data_quality_flags_without_abort() -> None:
    definition = ProviderDefinition(
        name="nvd",
        provider=ExplodingProvider(),
        source_kind="nvd",
        cache_namespace="nvd",
    )

    result = ProviderClientAdapter(definition=definition).enrich(["CVE-2026-0001"])

    assert result.records == {}
    assert result.warnings == ["nvd provider failed: provider offline"]
    assert result.status.degraded is True
    assert result.status.failures == 1
    assert result.status.empty_records == 1
    assert [flag.code for flag in result.status.data_quality_flags] == [
        "provider_failure",
        "provider_warning",
    ]
    assert result.status.data_quality_flags[0].message == "nvd lookup degraded with 1 failure(s)."


def test_stale_cache_diagnostics_become_data_quality_flags() -> None:
    provider = WarningProvider(
        diagnostics=ProviderLookupDiagnostics(
            requested=1,
            failures=1,
            content_hits=1,
            stale_cache_hits=1,
            degraded=True,
        ),
        warnings=["EPSS lookup failed; using expired cached data"],
    )
    definition = ProviderDefinition(
        name="epss",
        provider=provider,
        source_kind="epss",
        cache_namespace="epss",
    )

    result = ProviderClientAdapter(definition=definition).enrich(["CVE-2026-0001"])

    assert result.records == {"CVE-2026-0001": {"source": "stale"}}
    assert result.status.cache_hit is True
    assert result.status.stale_cache_hits == 1
    assert result.status.degraded is True
    assert [flag.code for flag in result.status.data_quality_flags] == [
        "provider_failure",
        "stale_cache",
        "provider_warning",
    ]


def test_provider_cache_contract_validation() -> None:
    provider = FakeProvider()
    definition = ProviderDefinition(
        name="kev",
        provider=provider,
        source_kind="kev",
        cache_namespace="kev",
        cache_key_template="catalog",
        cache_ttl_seconds=3600,
        stale_while_error=True,
    )

    validate_provider_definition(definition)
    contract = provider_cache_contract(definition)

    assert contract.source == "kev"
    assert contract.cache_enabled is False
    assert contract.namespace == "kev"
    assert contract.key_template == "catalog"
    assert contract.ttl_seconds == 3600
    assert contract.stale_while_error is True

    with pytest.raises(ValueError, match="cache TTL"):
        validate_provider_definition(
            ProviderDefinition(
                name="bad",
                provider=provider,
                source_kind="fixture",
                cache_ttl_seconds=-1,
            )
        )

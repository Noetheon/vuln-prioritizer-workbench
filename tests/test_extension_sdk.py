from __future__ import annotations

import inspect
from collections.abc import Mapping, Sequence
from typing import Any

import pytest

from vuln_prioritizer.inputs import loader
from vuln_prioritizer.inputs.sdk import (
    STATIC_EXTENSION_POLICY,
    InputParserDefinition,
    build_input_parser_registry,
    validate_input_parser_definition,
)
from vuln_prioritizer.providers import sdk as provider_sdk
from vuln_prioritizer.providers.sdk import (
    STATIC_PROVIDER_EXTENSION_POLICY,
    ProviderDefinition,
    build_provider_registry,
    builtin_provider_definitions,
    validate_provider_definition,
)


class FakeProvider:
    last_diagnostics: dict[str, Any] = {}

    def fetch_many(
        self,
        cve_ids: Sequence[str],
        **kwargs: Any,
    ) -> tuple[Mapping[str, Any], list[str]]:
        return {cve_id: {"source": kwargs.get("source", "fake")} for cve_id in cve_ids}, []


class MissingFetchProvider:
    last_diagnostics: dict[str, Any] = {}


def test_builtin_input_parser_definitions_are_static_local_contracts() -> None:
    assert STATIC_EXTENSION_POLICY == "static-local-only"
    registry = build_input_parser_registry(loader.INPUT_PARSER_DEFINITIONS)

    assert set(registry) == set(loader._INPUT_PARSERS)
    assert {"cve-list", "trivy-json", "cyclonedx-json", "nessus-xml"} <= set(registry)
    for definition in loader.INPUT_PARSER_DEFINITIONS:
        validate_input_parser_definition(definition)
        assert definition.remote_code_loading is False
        assert definition.fixture_names or definition.name == "generic-occurrence-csv"


def test_input_parser_sdk_rejects_remote_code_loading_and_duplicates() -> None:
    parser = loader.INPUT_PARSER_DEFINITIONS[0].parser
    with pytest.raises(ValueError, match="remote code"):
        validate_input_parser_definition(
            InputParserDefinition(
                name="remote-parser",
                parser=parser,
                remote_code_loading=True,
            )
        )
    with pytest.raises(ValueError, match="Duplicate"):
        build_input_parser_registry(
            (
                InputParserDefinition(name="duplicate", parser=parser),
                InputParserDefinition(name="duplicate", parser=parser),
            )
        )


def test_provider_sdk_is_static_and_rejects_remote_code_loading() -> None:
    assert STATIC_PROVIDER_EXTENSION_POLICY == "static-local-only"
    provider = FakeProvider()
    definition = ProviderDefinition(
        name="fake",
        provider=provider,
        source_kind="fixture",
        cache_namespace="fake",
        offline_capable=True,
    )
    validate_provider_definition(definition)
    registry = build_provider_registry((definition,))
    records, warnings = registry["fake"].provider.fetch_many(["CVE-2024-3094"])
    assert warnings == []
    assert records["CVE-2024-3094"]
    builtin_registry = build_provider_registry(builtin_provider_definitions())
    assert {"nvd", "epss", "kev"} <= set(builtin_registry)
    for builtin in builtin_registry.values():
        validate_provider_definition(builtin)
        assert builtin.remote_code_loading is False

    with pytest.raises(ValueError, match="remote code"):
        validate_provider_definition(
            ProviderDefinition(
                name="remote-provider",
                provider=provider,
                source_kind="remote",
                remote_code_loading=True,
            )
        )
    with pytest.raises(ValueError, match="non-empty and trimmed"):
        validate_provider_definition(
            ProviderDefinition(
                name=" invalid",
                provider=provider,
                source_kind="fixture",
            )
        )
    with pytest.raises(ValueError, match="fetch_many"):
        validate_provider_definition(
            ProviderDefinition(
                name="missing-fetch",
                provider=MissingFetchProvider(),  # type: ignore[arg-type]
                source_kind="fixture",
            )
        )
    with pytest.raises(ValueError, match="Duplicate"):
        build_provider_registry(
            (
                ProviderDefinition(name="duplicate", provider=provider, source_kind="fixture"),
                ProviderDefinition(name="duplicate", provider=provider, source_kind="fixture"),
            )
        )


def test_extension_sdks_do_not_discover_entry_points_or_remote_imports() -> None:
    input_sdk_source = inspect.getsource(loader)
    provider_sdk_source = inspect.getsource(provider_sdk)

    for source in (input_sdk_source, provider_sdk_source):
        assert "entry_points" not in source
        assert "importlib.metadata" not in source
        assert "subprocess" not in source
        assert "urlopen" not in source

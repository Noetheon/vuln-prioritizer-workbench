from __future__ import annotations

import importlib.util
import inspect
import json
from collections.abc import Mapping, Sequence
from pathlib import Path
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
    build_provider_clients,
    build_provider_registry,
    builtin_provider_definitions,
    validate_provider_definition,
)

ROOT = Path(__file__).resolve().parents[2]


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
        assert definition.fixture_names


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


def test_documented_extension_stub_compiles_and_matches_static_contracts(
    tmp_path: Path,
) -> None:
    stub = _load_extension_stub()

    validate_input_parser_definition(stub.ACME_SCAN_PARSER)
    parser_registry = build_input_parser_registry((stub.ACME_SCAN_PARSER,))
    assert set(parser_registry) == {"acme-scan-json"}

    fixture = tmp_path / "positive.acme.json"
    fixture.write_text(
        json.dumps(
            {
                "findings": [
                    {
                        "id": "ACME-1",
                        "cve": "cve-2024-3094",
                        "component": "xz",
                        "version": "5.6.0",
                        "severity": "critical",
                        "asset": "container:api",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    parsed = parser_registry["acme-scan-json"](fixture)

    assert parsed.input_format == "acme-scan-json"
    assert parsed.unique_cves == ["CVE-2024-3094"]
    assert parsed.occurrences[0].component_name == "xz"
    assert parsed.occurrences[0].target_ref == "container:api"

    validate_provider_definition(stub.ACME_CONTEXT_PROVIDER)
    provider_clients = build_provider_clients((stub.ACME_CONTEXT_PROVIDER,))
    result = provider_clients["acme-context"].enrich(["CVE-2024-3094"])

    assert result.source == "acme-context"
    assert result.records["CVE-2024-3094"]["review_status"] == "fixture-only"
    assert result.status.degraded is False
    assert result.status.content_hits == 1


def _load_extension_stub() -> Any:
    stub_path = ROOT / "docs" / "examples" / "extension_stub.py"
    spec = importlib.util.spec_from_file_location("vpw_extension_stub", stub_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

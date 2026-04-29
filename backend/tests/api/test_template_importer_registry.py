from __future__ import annotations

from pathlib import Path

import pytest

from app.importers import (
    DEFAULT_IMPORT_INPUT_TYPES,
    DuplicateInputTypeError,
    ImporterError,
    ImporterParseError,
    ImporterRegistry,
    ImporterValidationError,
    NormalizedOccurrence,
    UnsupportedInputTypeError,
    build_importer_registry,
)


class FakeImporter:
    input_type = "fake-json"

    def parse(
        self,
        payload: bytes | str,
        *,
        filename: str | None = None,
    ) -> list[NormalizedOccurrence]:
        if payload == "broken":
            raise ImporterParseError("fake payload is not parseable")
        return [
            NormalizedOccurrence(
                cve="cve-2026-12345",
                component="openssl",
                version="3.0.0",
                asset_ref=filename,
                source=self.input_type,
                fix_version="3.0.8",
                raw_evidence={"payload_type": type(payload).__name__},
            )
        ]


def test_importer_registry_lists_and_gets_importers_by_input_type() -> None:
    importer = FakeImporter()
    registry = build_importer_registry([importer])

    assert registry.list_input_types() == ("fake-json",)
    assert registry.list() == ("fake-json",)
    assert registry.supported_input_types() == ("fake-json",)
    assert registry.get("fake-json") is importer
    assert registry.get(" FAKE-JSON ") is importer


def test_default_importer_registry_maps_current_workbench_input_types() -> None:
    registry = build_importer_registry()

    assert registry.supported_input_types() == tuple(sorted(DEFAULT_IMPORT_INPUT_TYPES))


def test_importer_registry_rejects_duplicate_input_types() -> None:
    first = FakeImporter()
    second = FakeImporter()

    with pytest.raises(DuplicateInputTypeError) as exc_info:
        ImporterRegistry([first, second])

    assert exc_info.value.input_type == "fake-json"
    assert isinstance(exc_info.value, ImporterValidationError)


def test_importer_registry_rejects_blank_input_type() -> None:
    with pytest.raises(ImporterValidationError, match="must not be blank"):
        build_importer_registry([type("BlankImporter", (), {"input_type": "  "})()])


def test_importer_registry_raises_clear_error_for_unsupported_type() -> None:
    registry = build_importer_registry([FakeImporter()])

    with pytest.raises(UnsupportedInputTypeError) as exc_info:
        registry.get("unknown")

    assert exc_info.value.input_type == "unknown"
    assert exc_info.value.supported == ("fake-json",)
    assert "Supported input types: fake-json" in str(exc_info.value)
    assert isinstance(exc_info.value, ImporterError)


def test_registry_parse_path_returns_normalized_occurrences() -> None:
    registry = build_importer_registry([FakeImporter()])
    occurrences = registry.parse("fake-json", b"{}", filename="scan.json")

    assert occurrences == [
        NormalizedOccurrence(
            cve="CVE-2026-12345",
            component="openssl",
            version="3.0.0",
            asset_ref="scan.json",
            source="fake-json",
            fix_version="3.0.8",
            raw_evidence={"payload_type": "bytes"},
        )
    ]


def test_normalized_occurrence_rejects_invalid_cve() -> None:
    with pytest.raises(ImporterValidationError):
        NormalizedOccurrence(cve="not-a-cve", source="fake-json")


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("cve", None),
        ("source", None),
    ],
)
def test_normalized_occurrence_rejects_non_string_identifiers(
    field_name: str,
    value: object,
) -> None:
    payload = {"cve": "CVE-2026-12345", "source": "fake-json", field_name: value}

    with pytest.raises(ImporterValidationError, match=field_name):
        NormalizedOccurrence(**payload)


def test_normalized_occurrence_rejects_non_string_raw_evidence_keys() -> None:
    with pytest.raises(ImporterValidationError, match="keys must be strings"):
        NormalizedOccurrence(
            cve="CVE-2026-12345",
            source="fake-json",
            raw_evidence={1: "non-string-key"},
        )


def test_fake_importer_surfaces_parse_errors() -> None:
    with pytest.raises(ImporterParseError, match="not parseable"):
        FakeImporter().parse("broken")


def test_default_registry_parses_cve_list_payload() -> None:
    registry = build_importer_registry()

    occurrences = registry.parse(
        "cve-list",
        "CVE-2026-12345\nCVE-2026-23456\n",
        filename="findings.txt",
    )

    assert [item.cve for item in occurrences] == ["CVE-2026-12345", "CVE-2026-23456"]
    assert [item.source for item in occurrences] == ["cve-list", "cve-list"]


def test_default_registry_maps_parse_failures_to_importer_error() -> None:
    registry = build_importer_registry()

    with pytest.raises(ImporterParseError, match="trivy-json"):
        registry.parse("trivy-json", "{not valid json", filename="trivy.json")


def test_importer_layer_stays_framework_provider_and_db_free() -> None:
    importer_dir = Path(__file__).resolve().parents[2] / "app" / "importers"
    source = "\n".join(path.read_text() for path in importer_dir.glob("*.py"))

    forbidden_imports = [
        "fastapi",
        "HTTPException",
        "sqlmodel",
        "app.repositories",
        "vuln_prioritizer.db",
        "vuln_prioritizer.providers",
    ]
    for forbidden in forbidden_imports:
        assert forbidden not in source

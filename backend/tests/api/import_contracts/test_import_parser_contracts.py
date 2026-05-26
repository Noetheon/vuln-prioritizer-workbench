from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from _input_fixture_contracts import load_input_fixture_contracts

from app.importers import ImporterParseError, build_importer_registry
from app.importers.contracts import NormalizedOccurrence
from app.importers.offline_loader import DEFAULT_IMPORT_INPUT_TYPES
from app.services.workbench_capabilities import IMPORT_FORMAT_CAPABILITIES
from vuln_prioritizer.inputs.loader import InputLoader
from vuln_prioritizer.options import InputFormat

PROJECT_ROOT = Path(__file__).resolve().parents[4]
MATRIX_DIR = PROJECT_ROOT / "data" / "input_fixtures" / "parser_matrix"
INPUT_CONTRACTS = load_input_fixture_contracts()["inputs"]
CONTRACT_FIELDS = (
    "cve_id",
    "source_format",
    "component_name",
    "component_version",
    "purl",
    "package_type",
    "file_path",
    "dependency_path",
    "fix_versions",
    "raw_severity",
)

CONTRACT_CASES = tuple(
    (input_type, PROJECT_ROOT / Path(contract["fixture"]), contract)
    for input_type, contract in INPUT_CONTRACTS.items()
)
NEGATIVE_FIXTURES = (
    ("cve-list", MATRIX_DIR / "cve-list" / "negative.txt"),
    ("generic-occurrence-csv", MATRIX_DIR / "generic-occurrence-csv" / "negative.csv"),
    ("trivy-json", MATRIX_DIR / "trivy-json" / "negative.json"),
    ("grype-json", MATRIX_DIR / "grype-json" / "negative.json"),
)
NEGATIVE_PAYLOADS = {
    "cyclonedx-json": (b'{"bomFormat":"CycloneDX","vulnerabilities":"bad"}', "bad.json"),
    "spdx-json": (b'{"spdxVersion":"SPDX-2.3","packages":"bad"}', "bad.json"),
    "dependency-check-json": (b'{"scanInfo":{},"dependencies":"bad"}', "bad.json"),
    "github-alerts-json": (b'{"not":"alerts"}', "bad.json"),
    "nessus-xml": (b"<root/>", "bad.nessus"),
    "openvas-xml": (b"<root/>", "bad.xml"),
}


def _fixture_payload(path: Path) -> bytes:
    return path.read_bytes()


def _raw_evidence_value(
    occurrence: NormalizedOccurrence,
    *keys: str,
) -> object:
    for key in keys:
        if key in occurrence.raw_evidence:
            return occurrence.raw_evidence[key]
    return None


def _project_importer_occurrence(occurrence: NormalizedOccurrence) -> dict[str, object]:
    fix_versions = _raw_evidence_value(occurrence, "fix_versions")
    if not isinstance(fix_versions, list):
        fix_versions = [occurrence.fix_version] if occurrence.fix_version else []
    return {
        "cve_id": occurrence.cve,
        "source_format": occurrence.source,
        "component_name": occurrence.component,
        "component_version": occurrence.version,
        "purl": _raw_evidence_value(occurrence, "purl"),
        "package_type": _raw_evidence_value(occurrence, "package_type"),
        "file_path": _raw_evidence_value(occurrence, "file_path"),
        "dependency_path": _raw_evidence_value(occurrence, "dependency_path"),
        "fix_versions": fix_versions,
        "raw_severity": _raw_evidence_value(occurrence, "raw_severity", "severity"),
    }


def _project_loader_occurrence(occurrence: object) -> dict[str, object]:
    return {
        field_name: (
            list(getattr(occurrence, field_name) or [])
            if field_name == "fix_versions"
            else getattr(occurrence, field_name)
        )
        for field_name in CONTRACT_FIELDS
    }


@pytest.mark.parametrize(
    ("input_type", "fixture", "contract"),
    CONTRACT_CASES,
    ids=[case[0] for case in CONTRACT_CASES],
)
def test_workbench_importers_match_shared_normalization_contracts(
    input_type: str,
    fixture: Path,
    contract: dict[str, Any],
) -> None:
    registry = build_importer_registry()

    occurrences = registry.parse(
        input_type,
        _fixture_payload(fixture),
        filename=fixture.name,
    )

    assert fixture.is_file()
    assert len(occurrences) == contract["expected_occurrence_count"]
    assert list(dict.fromkeys(item.cve for item in occurrences)) == contract["expected_unique_cves"]
    assert [_project_importer_occurrence(item) for item in occurrences] == contract[
        "expected_occurrences"
    ]


@pytest.mark.parametrize(
    ("input_type", "negative_fixture"),
    NEGATIVE_FIXTURES,
    ids=[case[0] for case in NEGATIVE_FIXTURES],
)
def test_vpw021_negative_parser_fixtures_fail_offline(
    input_type: str,
    negative_fixture: Path,
) -> None:
    registry = build_importer_registry()

    assert negative_fixture.is_file()
    with pytest.raises(ImporterParseError):
        registry.parse(
            input_type,
            _fixture_payload(negative_fixture),
            filename=negative_fixture.name,
        )


def test_workbench_importer_registry_matches_core_inputloader_formats() -> None:
    supported_cli_upload_formats = {input_format.value for input_format in InputFormat} - {"auto"}

    assert set(DEFAULT_IMPORT_INPUT_TYPES) == supported_cli_upload_formats
    assert set(build_importer_registry().list_input_types()) == supported_cli_upload_formats


def test_workbench_capabilities_match_active_importer_registry() -> None:
    capability_input_types = {capability.input_type for capability in IMPORT_FORMAT_CAPABILITIES}

    assert capability_input_types == set(build_importer_registry().list_input_types())
    assert tuple(capability.input_type for capability in IMPORT_FORMAT_CAPABILITIES) == tuple(
        DEFAULT_IMPORT_INPUT_TYPES
    )


@pytest.mark.parametrize(
    ("input_type", "fixture", "_contract"),
    CONTRACT_CASES,
    ids=[case[0] for case in CONTRACT_CASES],
)
def test_workbench_importers_match_core_inputloader_normalization(
    input_type: str,
    fixture: Path,
    _contract: dict[str, Any],
) -> None:
    registry = build_importer_registry()

    importer_occurrences = registry.parse(
        input_type,
        fixture.read_bytes(),
        filename=fixture.name,
    )
    loader_occurrences = InputLoader().load(fixture, input_format=input_type).occurrences

    assert fixture.is_file()
    assert [_project_importer_occurrence(item) for item in importer_occurrences] == [
        _project_loader_occurrence(item) for item in loader_occurrences
    ]


@pytest.mark.parametrize(
    ("input_type", "negative_fixture"),
    (
        ("cve-list", MATRIX_DIR / "cve-list" / "negative.txt"),
        ("generic-occurrence-csv", MATRIX_DIR / "generic-occurrence-csv" / "negative.csv"),
    ),
)
def test_fail_closed_invalid_row_semantics_are_cli_compatibility_exceptions(
    input_type: str,
    negative_fixture: Path,
) -> None:
    registry = build_importer_registry()

    with pytest.raises(ImporterParseError):
        registry.parse(input_type, negative_fixture.read_bytes(), filename=negative_fixture.name)

    parsed = InputLoader().load(negative_fixture, input_format=input_type)
    assert [item.cve_id for item in parsed.occurrences] == ["CVE-2024-3094"]
    assert any("invalid CVE identifier" in warning for warning in parsed.warnings)


@pytest.mark.parametrize(
    ("input_type", "payload", "filename"),
    [(input_type, *payload) for input_type, payload in NEGATIVE_PAYLOADS.items()],
    ids=list(NEGATIVE_PAYLOADS),
)
def test_workbench_offline_loader_parity_formats_reject_negative_payloads(
    input_type: str,
    payload: bytes,
    filename: str,
) -> None:
    registry = build_importer_registry()

    with pytest.raises(ImporterParseError):
        registry.parse(input_type, payload, filename=filename)


def test_vpw021_fixture_matrix_has_no_sensitive_path_content() -> None:
    for fixture_path in MATRIX_DIR.rglob("*"):
        if not fixture_path.is_file():
            continue
        text = fixture_path.read_text(encoding="utf-8", errors="ignore")
        assert "/Users/" not in text
        assert "/private/" not in text
        assert "BEGIN " not in text

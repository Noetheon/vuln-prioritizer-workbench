from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

import pytest

from app.importers import ImporterParseError, build_importer_registry
from app.importers.contracts import NormalizedOccurrence
from app.importers.offline_loader import DEFAULT_IMPORT_INPUT_TYPES
from vuln_prioritizer.cli_options import InputFormat
from vuln_prioritizer.inputs.loader import InputLoader

PROJECT_ROOT = Path(__file__).resolve().parents[3]
MATRIX_DIR = PROJECT_ROOT / "data" / "input_fixtures" / "parser_matrix"
SNAPSHOT_FILE = MATRIX_DIR / "expected_normalized_occurrences.json"

MATRIX_CASES = (
    (
        "cve-list",
        MATRIX_DIR / "cve-list" / "positive.txt",
        MATRIX_DIR / "cve-list" / "negative.txt",
    ),
    (
        "generic-occurrence-csv",
        MATRIX_DIR / "generic-occurrence-csv" / "positive.csv",
        MATRIX_DIR / "generic-occurrence-csv" / "negative.csv",
    ),
    (
        "trivy-json",
        MATRIX_DIR / "trivy-json" / "positive.json",
        MATRIX_DIR / "trivy-json" / "negative.json",
    ),
    (
        "grype-json",
        MATRIX_DIR / "grype-json" / "positive.json",
        MATRIX_DIR / "grype-json" / "negative.json",
    ),
)
PARITY_CASES = (
    ("cve-list", MATRIX_DIR / "cve-list" / "positive.txt"),
    ("generic-occurrence-csv", MATRIX_DIR / "generic-occurrence-csv" / "positive.csv"),
    ("trivy-json", MATRIX_DIR / "trivy-json" / "positive.json"),
    ("grype-json", MATRIX_DIR / "grype-json" / "positive.json"),
    ("cyclonedx-json", PROJECT_ROOT / "data" / "input_fixtures" / "cyclonedx_bom.json"),
    ("spdx-json", PROJECT_ROOT / "data" / "input_fixtures" / "spdx_bom.json"),
    (
        "dependency-check-json",
        PROJECT_ROOT / "data" / "input_fixtures" / "dependency_check_report.json",
    ),
    ("github-alerts-json", PROJECT_ROOT / "data" / "input_fixtures" / "github_alerts_export.json"),
    ("nessus-xml", PROJECT_ROOT / "data" / "input_fixtures" / "nessus_report.nessus"),
    ("openvas-xml", PROJECT_ROOT / "data" / "input_fixtures" / "openvas_report.xml"),
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


def _snapshot_occurrences(occurrences: list[NormalizedOccurrence]) -> list[dict[str, Any]]:
    return [asdict(occurrence) for occurrence in occurrences]


def _expected_snapshots() -> dict[str, list[dict[str, Any]]]:
    return json.loads(SNAPSHOT_FILE.read_text(encoding="utf-8"))


def _project_importer_occurrence(occurrence: NormalizedOccurrence) -> dict[str, object]:
    return {
        "cve_id": occurrence.cve,
        "source_format": occurrence.source,
        "component_name": occurrence.component,
        "component_version": occurrence.version,
        "fix_versions": [occurrence.fix_version] if occurrence.fix_version else [],
        "target_ref": occurrence.asset_ref,
    }


def _project_loader_occurrence(occurrence: object) -> dict[str, object]:
    return {
        "cve_id": getattr(occurrence, "cve_id"),
        "source_format": getattr(occurrence, "source_format"),
        "component_name": getattr(occurrence, "component_name"),
        "component_version": getattr(occurrence, "component_version"),
        "fix_versions": list(getattr(occurrence, "fix_versions") or []),
        "target_ref": getattr(occurrence, "asset_id") or getattr(occurrence, "target_ref"),
    }


@pytest.mark.parametrize(
    ("input_type", "positive_fixture", "_negative_fixture"),
    MATRIX_CASES,
    ids=[case[0] for case in MATRIX_CASES],
)
def test_vpw021_positive_parser_fixtures_match_normalized_snapshots(
    input_type: str,
    positive_fixture: Path,
    _negative_fixture: Path,
) -> None:
    registry = build_importer_registry()

    occurrences = registry.parse(
        input_type,
        _fixture_payload(positive_fixture),
        filename=positive_fixture.name,
    )

    assert positive_fixture.is_file()
    assert _snapshot_occurrences(occurrences) == _expected_snapshots()[input_type]


@pytest.mark.parametrize(
    ("input_type", "_positive_fixture", "negative_fixture"),
    MATRIX_CASES,
    ids=[case[0] for case in MATRIX_CASES],
)
def test_vpw021_negative_parser_fixtures_fail_offline(
    input_type: str,
    _positive_fixture: Path,
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


@pytest.mark.parametrize(
    ("input_type", "fixture"),
    PARITY_CASES,
    ids=[case[0] for case in PARITY_CASES],
)
def test_workbench_importers_match_core_inputloader_normalization(
    input_type: str,
    fixture: Path,
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

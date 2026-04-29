from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

import pytest

from app.importers import ImporterParseError, build_importer_registry
from app.importers.contracts import NormalizedOccurrence

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


def _fixture_payload(path: Path) -> bytes:
    return path.read_bytes()


def _snapshot_occurrences(occurrences: list[NormalizedOccurrence]) -> list[dict[str, Any]]:
    return [asdict(occurrence) for occurrence in occurrences]


def _expected_snapshots() -> dict[str, list[dict[str, Any]]]:
    return json.loads(SNAPSHOT_FILE.read_text(encoding="utf-8"))


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


def test_vpw021_fixture_matrix_has_no_sensitive_path_content() -> None:
    for fixture_path in MATRIX_DIR.rglob("*"):
        if not fixture_path.is_file():
            continue
        text = fixture_path.read_text(encoding="utf-8", errors="ignore")
        assert "/Users/" not in text
        assert "/private/" not in text
        assert "BEGIN " not in text

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.importers import build_importer_registry
from vuln_prioritizer.inputs.loader import InputLoader
from vuln_prioritizer.inputs.parsers.scanner import parse_grype_json

PROJECT_ROOT = Path(__file__).resolve().parents[2]
FIXTURE_DIR = PROJECT_ROOT / "data" / "input_fixtures"


def test_grype_json_fixture_normalizes_matches_to_occurrences() -> None:
    parsed = InputLoader().load(
        FIXTURE_DIR / "grype_report.json",
        input_format="grype-json",
    )

    assert parsed.total_rows == 3
    assert parsed.unique_cves == ["CVE-2024-3094", "CVE-2023-34362"]
    assert len(parsed.occurrences) == 2

    os_occurrence = parsed.occurrences[0]
    assert os_occurrence.cve_id == "CVE-2024-3094"
    assert os_occurrence.source_id == "CVE-2024-3094"
    assert os_occurrence.component_name == "xz"
    assert os_occurrence.component_version == "5.6.0-r0"
    assert os_occurrence.package_type == "apk"
    assert os_occurrence.purl == "pkg:apk/alpine/xz@5.6.0-r0?arch=x86_64"
    assert os_occurrence.file_path == "/lib/apk/db/installed"
    assert os_occurrence.fix_versions == ["5.6.1-r2"]
    assert os_occurrence.source_record_id == "match:1"
    assert os_occurrence.raw_severity == "Critical"
    assert os_occurrence.target_kind == "image"
    assert os_occurrence.target_ref == "ghcr.io/acme/demo-app:1.0.0"

    library_occurrence = parsed.occurrences[1]
    assert library_occurrence.cve_id == "CVE-2023-34362"
    assert library_occurrence.component_name == "moveit-transfer"
    assert library_occurrence.component_version == "2023.0.0"
    assert library_occurrence.package_type == "python"
    assert library_occurrence.purl == "pkg:pypi/moveit-transfer@2023.0.0"
    assert library_occurrence.file_path == "app/requirements.txt"
    assert library_occurrence.fix_versions == ["2023.0.2"]


def test_grype_json_uses_related_cve_and_keeps_non_cve_source_id(tmp_path: Path) -> None:
    input_file = tmp_path / "grype.json"
    input_file.write_text(
        json.dumps(
            {
                "source": {"type": "directory", "target": {"name": "repo/demo"}},
                "matches": [
                    {
                        "vulnerability": {
                            "id": "GHSA-9m7r-4c2v-9j5j",
                            "relatedVulnerabilities": [{"id": "CVE-2024-9999"}],
                            "severity": "High",
                            "fix": {"versions": ["2.0.0"]},
                        },
                        "artifact": {
                            "name": "demo-package",
                            "version": "1.0.0",
                            "type": "npm",
                            "purl": "pkg:npm/demo-package@1.0.0",
                            "locations": [{"realPath": "package-lock.json"}],
                        },
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    parsed = parse_grype_json(input_file)

    assert parsed.warnings == []
    assert len(parsed.occurrences) == 1
    occurrence = parsed.occurrences[0]
    assert occurrence.cve_id == "CVE-2024-9999"
    assert occurrence.source_id == "GHSA-9m7r-4c2v-9j5j"
    assert occurrence.fix_versions == ["2.0.0"]
    assert occurrence.file_path == "package-lock.json"
    assert occurrence.target_kind == "directory"
    assert occurrence.target_ref == "repo/demo"


def test_grype_json_warns_about_unexpected_match_shapes(tmp_path: Path) -> None:
    input_file = tmp_path / "grype.json"
    input_file.write_text(
        json.dumps(
            {
                "matches": [
                    "not-a-match-object",
                    {
                        "vulnerability": {"id": "CVE-2024-0001"},
                    },
                    {
                        "artifact": {"name": "missing-vulnerability"},
                    },
                    {
                        "vulnerability": {"id": "GHSA-2m57-hf25-phgg"},
                        "artifact": {"name": "non-cve-demo"},
                    },
                ]
            }
        ),
        encoding="utf-8",
    )

    parsed = parse_grype_json(input_file)

    assert parsed.total_rows == 4
    assert len(parsed.occurrences) == 1
    assert parsed.occurrences[0].cve_id == "CVE-2024-0001"
    warning_text = "\n".join(parsed.warnings)
    assert "Ignored Grype match 1: expected an object" in warning_text
    assert "Grype match 2 is missing an artifact object" in warning_text
    assert "Ignored Grype match 3 without a vulnerability object" in warning_text
    assert "Ignored non-CVE Grype vulnerability identifier" in warning_text


def test_grype_json_reports_missing_or_invalid_matches_array(tmp_path: Path) -> None:
    missing_matches = tmp_path / "missing-matches.json"
    missing_matches.write_text("{}", encoding="utf-8")
    parsed_missing = parse_grype_json(missing_matches)
    assert parsed_missing.warnings == ["Grype JSON does not contain a matches array."]
    assert parsed_missing.total_rows == 0

    invalid_matches = tmp_path / "invalid-matches.json"
    invalid_matches.write_text('{"matches": {}}', encoding="utf-8")
    parsed_invalid = parse_grype_json(invalid_matches)
    assert parsed_invalid.warnings == ["Ignored Grype `matches` value because it was not a list."]
    assert parsed_invalid.total_rows == 0


def test_grype_json_rejects_broken_json_with_clear_error(tmp_path: Path) -> None:
    input_file = tmp_path / "grype.json"
    input_file.write_text("{not valid json", encoding="utf-8")

    with pytest.raises(ValueError, match="Grype JSON is invalid JSON"):
        parse_grype_json(input_file)


def test_workbench_grype_importer_preserves_source_metadata_in_raw_evidence() -> None:
    registry = build_importer_registry()

    occurrences = registry.parse(
        "grype-json",
        (FIXTURE_DIR / "grype_report.json").read_text(encoding="utf-8"),
        filename="grype_report.json",
    )

    assert len(occurrences) == 2
    assert occurrences[0].raw_evidence["source_id"] == "CVE-2024-3094"
    assert occurrences[0].raw_evidence["source_record_id"] == "match:1"
    assert occurrences[0].raw_evidence["target_ref"] == "ghcr.io/acme/demo-app:1.0.0"

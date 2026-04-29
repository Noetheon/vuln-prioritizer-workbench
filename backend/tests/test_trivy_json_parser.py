from __future__ import annotations

import json
from pathlib import Path

import pytest

from vuln_prioritizer.inputs.loader import InputLoader
from vuln_prioritizer.inputs.parsers.scanner import parse_trivy_json
from vuln_prioritizer.models import InputOccurrence

PROJECT_ROOT = Path(__file__).resolve().parents[2]
FIXTURE_DIR = PROJECT_ROOT / "data" / "input_fixtures"


def test_input_occurrence_serializes_source_id_only_when_present() -> None:
    assert "source_id" not in InputOccurrence(cve_id="CVE-2024-0001").model_dump()
    assert (
        InputOccurrence(cve_id="CVE-2024-0001", source_id="GHSA-9m7r-4c2v-9j5j").model_dump()[
            "source_id"
        ]
        == "GHSA-9m7r-4c2v-9j5j"
    )


def test_trivy_json_fixture_normalizes_os_and_library_occurrences() -> None:
    parsed = InputLoader().load(
        FIXTURE_DIR / "trivy_report.json",
        input_format="trivy-json",
    )

    assert parsed.total_rows == 4
    assert parsed.unique_cves == ["CVE-2024-3094", "CVE-2023-34362", "CVE-2024-4577"]
    assert len(parsed.occurrences) == 3

    os_occurrence = parsed.occurrences[0]
    assert os_occurrence.cve_id == "CVE-2024-3094"
    assert os_occurrence.source_id == "CVE-2024-3094"
    assert os_occurrence.component_name == "xz"
    assert os_occurrence.component_version == "5.6.0-r0"
    assert os_occurrence.package_type == "apk"
    assert os_occurrence.file_path == "/lib/apk/db/installed"
    assert os_occurrence.fix_versions == ["5.6.1-r2"]
    assert os_occurrence.target_kind == "image"
    assert os_occurrence.target_ref == "ghcr.io/acme/demo-app:1.0.0 (alpine 3.19)"

    library_occurrence = parsed.occurrences[1]
    assert library_occurrence.cve_id == "CVE-2023-34362"
    assert library_occurrence.component_name == "moveit-transfer"
    assert library_occurrence.package_type == "pip"
    assert library_occurrence.file_path == "requirements.txt"
    assert library_occurrence.purl == "pkg:pypi/moveit-transfer@2023.0.0"


def test_trivy_json_uses_cve_alias_and_keeps_non_cve_source_id(tmp_path: Path) -> None:
    input_file = tmp_path / "trivy.json"
    input_file.write_text(
        json.dumps(
            {
                "Results": [
                    {
                        "Target": "service/requirements.txt",
                        "Type": "pip",
                        "Vulnerabilities": [
                            {
                                "VulnerabilityID": "GHSA-9m7r-4c2v-9j5j",
                                "CVEs": ["CVE-2024-9999"],
                                "PkgName": "demo-package",
                                "InstalledVersion": "1.0.0",
                                "FixedVersions": ["1.0.1", "1.0.2"],
                            }
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    parsed = parse_trivy_json(input_file)

    assert parsed.warnings == []
    assert len(parsed.occurrences) == 1
    occurrence = parsed.occurrences[0]
    assert occurrence.cve_id == "CVE-2024-9999"
    assert occurrence.source_id == "GHSA-9m7r-4c2v-9j5j"
    assert occurrence.fix_versions == ["1.0.1", "1.0.2"]
    assert occurrence.target_ref == "service/requirements.txt"


def test_trivy_json_skips_non_cve_without_alias_and_warns_source_id(tmp_path: Path) -> None:
    input_file = tmp_path / "trivy.json"
    input_file.write_text(
        json.dumps(
            {
                "Results": [
                    {
                        "Vulnerabilities": [
                            {
                                "VulnerabilityID": "GHSA-2m57-hf25-phgg",
                                "PkgName": "demo-package",
                            }
                        ]
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    parsed = parse_trivy_json(input_file)

    assert parsed.total_rows == 1
    assert parsed.occurrences == []
    assert parsed.warnings == [
        "Ignored non-CVE Trivy vulnerability identifier: 'GHSA-2m57-hf25-phgg'"
    ]


def test_trivy_json_tolerates_missing_optional_fields(tmp_path: Path) -> None:
    input_file = tmp_path / "trivy.json"
    input_file.write_text(
        json.dumps(
            {
                "Results": [
                    {
                        "Class": "os-pkgs",
                        "Vulnerabilities": [{"VulnerabilityID": "CVE-2024-0001"}],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    parsed = parse_trivy_json(input_file)

    assert len(parsed.occurrences) == 1
    occurrence = parsed.occurrences[0]
    assert occurrence.cve_id == "CVE-2024-0001"
    assert occurrence.source_id == "CVE-2024-0001"
    assert occurrence.component_name is None
    assert occurrence.package_type is None
    assert occurrence.fix_versions == []
    assert occurrence.target_kind == "image"
    assert occurrence.target_ref is None


def test_trivy_json_rejects_broken_json_with_clear_error(tmp_path: Path) -> None:
    input_file = tmp_path / "trivy.json"
    input_file.write_text("{not valid json", encoding="utf-8")

    with pytest.raises(ValueError, match="Trivy JSON is invalid JSON"):
        parse_trivy_json(input_file)

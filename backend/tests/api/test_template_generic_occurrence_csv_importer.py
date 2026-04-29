from __future__ import annotations

from pathlib import Path

import pytest

from app.importers import (
    GenericOccurrenceCsvImporter,
    ImporterParseError,
    build_importer_registry,
)

PROJECT_ROOT = Path(__file__).resolve().parents[3]
FIXTURE_DIR = PROJECT_ROOT / "data" / "input_fixtures"


def test_generic_occurrence_csv_importer_accepts_demo_fixture() -> None:
    importer = GenericOccurrenceCsvImporter()

    occurrences = importer.parse(
        (FIXTURE_DIR / "generic_occurrences.csv").read_text(encoding="utf-8"),
        filename="generic_occurrences.csv",
    )

    assert [(item.cve, item.asset_ref, item.component, item.version) for item in occurrences] == [
        ("CVE-2024-3094", "build-host-1", "xz", "5.6.0"),
        ("CVE-2024-4577", "web-tier", "php-cgi", "8.3.7"),
    ]
    assert occurrences[0].fix_version == "5.6.1-r2"
    assert occurrences[0].raw_evidence["scanner"] == "trivy"
    assert occurrences[0].raw_evidence["severity"] == "CRITICAL"
    assert occurrences[0].raw_evidence["purl"] == "pkg:apk/alpine/xz@5.6.0-r0"
    assert occurrences[0].raw_evidence["owner"] == "team-platform"
    assert occurrences[0].raw_evidence["business_service"] == "payments"
    assert occurrences[0].raw_evidence["unknown_columns"] == {
        "notes": "owner says, urgent",
        "ticket_url": "SEC-1001",
    }


def test_generic_occurrence_csv_importer_sniffs_semicolon_dialect() -> None:
    importer = GenericOccurrenceCsvImporter()

    occurrences = importer.parse(
        (FIXTURE_DIR / "generic_occurrences_semicolon.csv").read_text(encoding="utf-8"),
        filename="generic_occurrences_semicolon.csv",
    )

    assert [item.cve for item in occurrences] == ["CVE-2024-3094"]
    assert occurrences[0].raw_evidence["scanner"] == "trivy"


def test_generic_occurrence_csv_importer_accepts_quoted_multiline_values() -> None:
    importer = GenericOccurrenceCsvImporter()

    occurrences = importer.parse(
        'cve_id,asset_ref,notes\nCVE-2024-3094,build-host-1,"line one\nline two"\n',
        filename="generic.csv",
    )

    assert len(occurrences) == 1
    assert occurrences[0].asset_ref == "build-host-1"
    assert occurrences[0].raw_evidence["line_number"] == 2
    assert occurrences[0].raw_evidence["unknown_columns"] == {"notes": "line one\nline two"}


def test_generic_occurrence_csv_importer_accepts_compatibility_aliases() -> None:
    importer = GenericOccurrenceCsvImporter()

    occurrences = importer.parse(
        "\n".join(
            [
                "vulnerability_id,target_ref,component,installed_version,fixed_versions,"
                "raw_severity,asset_owner,service,target_kind,asset_id,criticality,exposure,"
                "environment,ecosystem,path,dependency_path",
                "CVE-2022-22965,checkout-api,spring-webmvc,5.3.17,5.3.18,HIGH,"
                "appsec,checkout,service,asset-1,critical,public,prod,maven,pom.xml,"
                "root > spring-webmvc",
            ]
        ),
        filename="generic.csv",
    )

    assert len(occurrences) == 1
    occurrence = occurrences[0]
    assert occurrence.cve == "CVE-2022-22965"
    assert occurrence.asset_ref == "checkout-api"
    assert occurrence.component == "spring-webmvc"
    assert occurrence.version == "5.3.17"
    assert occurrence.fix_version == "5.3.18"
    assert occurrence.raw_evidence["severity"] == "HIGH"
    assert occurrence.raw_evidence["owner"] == "appsec"
    assert occurrence.raw_evidence["business_service"] == "checkout"
    assert occurrence.raw_evidence["target_kind"] == "service"
    assert occurrence.raw_evidence["asset_id"] == "asset-1"
    assert occurrence.raw_evidence["asset_criticality"] == "critical"
    assert occurrence.raw_evidence["asset_exposure"] == "public"
    assert occurrence.raw_evidence["asset_environment"] == "prod"
    assert occurrence.raw_evidence["package_type"] == "maven"
    assert occurrence.raw_evidence["file_path"] == "pom.xml"
    assert occurrence.raw_evidence["dependency_path"] == "root > spring-webmvc"


def test_generic_occurrence_csv_importer_collects_row_specific_errors() -> None:
    importer = GenericOccurrenceCsvImporter()

    with pytest.raises(ImporterParseError) as exc_info:
        importer.parse(
            (FIXTURE_DIR / "generic_occurrences_invalid.csv").read_text(encoding="utf-8"),
            filename="/private/tmp/generic_occurrences_invalid.csv",
        )

    message = str(exc_info.value)
    assert "line 2" in message
    assert "line 3" in message
    assert "not-a-cve" in message
    assert "/private/tmp" not in message


def test_generic_occurrence_csv_importer_requires_cve_id_column() -> None:
    importer = GenericOccurrenceCsvImporter()

    with pytest.raises(ImporterParseError, match="cve_id, cve, or vulnerability_id column"):
        importer.parse(
            (FIXTURE_DIR / "generic_occurrences_missing_cve.csv").read_text(encoding="utf-8"),
            filename="/private/tmp/generic_occurrences_missing_cve.csv",
        )


def test_default_registry_uses_template_generic_occurrence_importer() -> None:
    registry = build_importer_registry()

    assert isinstance(registry.get("generic-occurrence-csv"), GenericOccurrenceCsvImporter)
    assert [
        item.cve
        for item in registry.parse(
            "generic-occurrence-csv",
            "cve_id,asset_ref\nCVE-2024-3094,build-host-1\n",
            filename="generic.csv",
        )
    ] == ["CVE-2024-3094"]

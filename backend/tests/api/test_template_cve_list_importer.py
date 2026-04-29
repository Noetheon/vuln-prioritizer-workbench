from __future__ import annotations

from pathlib import Path

import pytest

from app.importers import CveListImporter, ImporterParseError, build_importer_registry

PROJECT_ROOT = Path(__file__).resolve().parents[3]
FIXTURE_DIR = PROJECT_ROOT / "data" / "input_fixtures"


def test_cve_list_txt_parser_skips_blank_comments_and_deduplicates() -> None:
    importer = CveListImporter()

    occurrences = importer.parse(
        "\n# tracked test fixture\nCVE-2021-44228\ncve-2021-44228\n\nCVE-2023-44487\n",
        filename="findings.txt",
    )

    assert [item.cve for item in occurrences] == ["CVE-2021-44228", "CVE-2023-44487"]
    assert [item.source for item in occurrences] == ["cve-list", "cve-list"]
    assert occurrences[0].raw_evidence["line_number"] == 3
    assert occurrences[1].raw_evidence["line_number"] == 6


def test_cve_list_txt_parser_accepts_valid_fixture() -> None:
    importer = CveListImporter()

    occurrences = importer.parse(
        (FIXTURE_DIR / "cve_list_valid.txt").read_text(encoding="utf-8"),
        filename="cve_list_valid.txt",
    )

    assert [item.cve for item in occurrences] == [
        "CVE-2021-44228",
        "CVE-2022-22965",
        "CVE-2023-44487",
    ]


def test_cve_list_csv_parser_maps_optional_occurrence_fields() -> None:
    importer = CveListImporter()

    occurrences = importer.parse(
        "\n".join(
            [
                "# comment before header",
                "cve_id,asset_ref,component,version",
                "CVE-2024-3094,build-host-1,xz,5.6.0",
                "CVE-2024-4577,web-tier,php,8.3.7",
                "",
            ]
        ),
        filename="findings.csv",
    )

    assert [(item.cve, item.asset_ref, item.component, item.version) for item in occurrences] == [
        ("CVE-2024-3094", "build-host-1", "xz", "5.6.0"),
        ("CVE-2024-4577", "web-tier", "php", "8.3.7"),
    ]
    assert occurrences[0].raw_evidence["line_number"] == 3


def test_cve_list_csv_parser_accepts_context_fixture() -> None:
    importer = CveListImporter()

    occurrences = importer.parse(
        (FIXTURE_DIR / "cve_list_context.csv").read_text(encoding="utf-8"),
        filename="cve_list_context.csv",
    )

    assert [(item.cve, item.asset_ref, item.component, item.version) for item in occurrences] == [
        ("CVE-2024-3094", "build-host-1", "xz", "5.6.0"),
        ("CVE-2024-4577", "web-tier", "php", "8.3.7"),
    ]


def test_cve_list_csv_parser_deduplicates_same_occurrence_context() -> None:
    importer = CveListImporter()

    occurrences = importer.parse(
        "\n".join(
            [
                "cve_id,asset_ref,component,version",
                "CVE-2024-3094,build-host-1,xz,5.6.0",
                "cve-2024-3094,build-host-1,xz,5.6.0",
                "CVE-2024-3094,build-host-2,xz,5.6.0",
            ]
        ),
        filename="findings.csv",
    )

    assert [(item.cve, item.asset_ref) for item in occurrences] == [
        ("CVE-2024-3094", "build-host-1"),
        ("CVE-2024-3094", "build-host-2"),
    ]


def test_cve_list_csv_parser_accepts_duplicate_fixture() -> None:
    importer = CveListImporter()

    occurrences = importer.parse(
        (FIXTURE_DIR / "cve_list_duplicates.csv").read_text(encoding="utf-8"),
        filename="cve_list_duplicates.csv",
    )

    assert [(item.cve, item.asset_ref) for item in occurrences] == [
        ("CVE-2024-3094", "build-host-1"),
        ("CVE-2024-3094", "build-host-2"),
    ]


def test_cve_list_txt_parser_reports_invalid_cve_with_line_number() -> None:
    importer = CveListImporter()

    with pytest.raises(ImporterParseError) as exc_info:
        importer.parse("CVE-2024-3094\nnot-a-cve\n", filename="/private/tmp/findings.txt")

    message = str(exc_info.value)
    assert "line 2" in message
    assert "not-a-cve" in message
    assert "/private/tmp" not in message


def test_cve_list_txt_parser_reports_invalid_fixture_with_line_number() -> None:
    importer = CveListImporter()

    with pytest.raises(ImporterParseError) as exc_info:
        importer.parse(
            (FIXTURE_DIR / "cve_list_invalid.txt").read_text(encoding="utf-8"),
            filename="/private/tmp/cve_list_invalid.txt",
        )

    message = str(exc_info.value)
    assert "line 2" in message
    assert "not-a-cve" in message
    assert "/private/tmp" not in message


def test_cve_list_csv_parser_requires_cve_id_column() -> None:
    importer = CveListImporter()

    with pytest.raises(ImporterParseError, match="cve_id column"):
        importer.parse("identifier,asset_ref\nCVE-2024-3094,build-host-1\n", filename="bad.csv")


def test_cve_list_csv_parser_reports_invalid_cve_with_line_number() -> None:
    importer = CveListImporter()

    with pytest.raises(ImporterParseError) as exc_info:
        importer.parse(
            "cve_id,asset_ref\nCVE-2024-3094,build-host-1\nbad-cve,build-host-2\n",
            filename="/private/tmp/findings.csv",
        )

    message = str(exc_info.value)
    assert "line 3" in message
    assert "bad-cve" in message
    assert "/private/tmp" not in message


def test_default_registry_uses_template_cve_list_importer() -> None:
    registry = build_importer_registry()

    assert isinstance(registry.get("cve-list"), CveListImporter)
    assert [item.cve for item in registry.parse("cve-list", "CVE-2024-3094\n")] == ["CVE-2024-3094"]

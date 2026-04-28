from __future__ import annotations

from pathlib import Path

import pytest

from vuln_prioritizer.parser import parse_input_file


def test_parse_txt_normalizes_and_deduplicates(tmp_path: Path) -> None:
    input_file = tmp_path / "cves.txt"
    input_file.write_text(
        "cve-2021-44228\ninvalid-entry\nCVE-2021-44228\n\nCVE-2024-3094\n",
        encoding="utf-8",
    )

    items, warnings, total_rows = parse_input_file(input_file)

    assert [item.cve_id for item in items] == ["CVE-2021-44228", "CVE-2024-3094"]
    assert total_rows == 4
    assert any("invalid CVE identifier" in warning for warning in warnings)
    assert all("duplicate CVE identifier" not in warning for warning in warnings)


def test_parse_csv_accepts_cve_id_header(tmp_path: Path) -> None:
    input_file = tmp_path / "cves.csv"
    input_file.write_text(
        "cve_id,owner\nCVE-2023-44487,web\ncve-2022-22965,app\n",
        encoding="utf-8",
    )

    items, warnings, total_rows = parse_input_file(input_file)

    assert [item.cve_id for item in items] == ["CVE-2023-44487", "CVE-2022-22965"]
    assert warnings == []
    assert total_rows == 2


def test_parse_input_rejects_empty_files(tmp_path: Path) -> None:
    input_file = tmp_path / "empty.txt"
    input_file.write_text("", encoding="utf-8")

    with pytest.raises(ValueError, match="No valid CVE identifiers"):
        parse_input_file(input_file)

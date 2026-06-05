from __future__ import annotations

from pathlib import Path

import pytest

from app.domain.engine.inputs.parsers.common import (
    as_string_list,
    first_string_from_list,
    read_cve_csv,
    read_txt,
    split_versions,
)


def test_read_txt_preserves_line_numbers_and_skips_blank_rows(tmp_path: Path) -> None:
    input_file = tmp_path / "cves.txt"
    input_file.write_text("\nCVE-2026-0001\n  \n CVE-2026-0002 \n", encoding="utf-8")

    assert read_txt(input_file) == [(2, "CVE-2026-0001"), (4, "CVE-2026-0002")]


def test_read_cve_csv_accepts_canonical_cve_id_and_skips_empty_values(tmp_path: Path) -> None:
    input_file = tmp_path / "cves.csv"
    input_file.write_text(
        "CVE_ID,component\nCVE-2026-0001,openssl\n,ignored\n CVE-2026-0002 ,curl\n",
        encoding="utf-8",
    )

    assert read_cve_csv(input_file) == [(2, "CVE-2026-0001"), (4, "CVE-2026-0002")]


def test_read_cve_csv_rejects_missing_header_and_cve_column(tmp_path: Path) -> None:
    empty_file = tmp_path / "empty.csv"
    no_cve_file = tmp_path / "components.csv"
    empty_file.write_text("", encoding="utf-8")
    no_cve_file.write_text("component,version\nopenssl,3.0\n", encoding="utf-8")

    with pytest.raises(ValueError, match="missing a header row"):
        read_cve_csv(empty_file)
    with pytest.raises(ValueError, match="must contain a cve_id column"):
        read_cve_csv(no_cve_file)


def test_common_parser_string_helpers_reject_non_matching_shapes() -> None:
    assert split_versions(42) == []
    assert as_string_list("not-a-list") == []
    assert first_string_from_list("not-a-list") is None

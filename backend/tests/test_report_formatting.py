from __future__ import annotations

from datetime import UTC, datetime

from app.services.report_formatting import (
    csv_safe_cell,
    dict_value,
    format_number,
    iso_datetime,
    metadata_bool,
    metadata_list,
    report_scope,
    safe_cell,
    safe_html,
    safe_inline,
)


def test_report_formatting_normalizes_markdown_html_and_csv_cells() -> None:
    assert safe_inline(" CVE | *critical* ") == "CVE | \\*critical\\*"
    assert safe_cell("left|right") == "left\\|right"
    assert safe_html("<script>bad()</script>") == "&lt;script&gt;bad()&lt;/script&gt;"
    assert csv_safe_cell("=cmd") == "'=cmd"
    assert csv_safe_cell(" normal ") == " normal "


def test_report_formatting_formats_numbers_dates_and_metadata() -> None:
    assert format_number(None) == "N/A"
    assert format_number(4.0) == "4"
    assert format_number(4.1256) == "4.126"
    assert iso_datetime(datetime(2026, 5, 6, 12, 0, tzinfo=UTC)) == "2026-05-06T12:00:00Z"
    assert metadata_bool({"locked": True}, "locked") == "Yes"
    assert metadata_bool({}, "locked") == "N/A"
    assert metadata_list({"sources": ["nvd", "kev"]}, "sources") == "nvd, kev"
    assert metadata_list({"sources": []}, "sources") == "N/A"
    assert dict_value({"ok": True}) == {"ok": True}
    assert dict_value(None) == {}


def test_report_scope_names_the_import_and_its_finding_count() -> None:
    text, partial = report_scope(
        finding_count=32,
        input_type="trivy-json",
        filename="trivy.json",
        run_id="1234abcd-0000-4000-8000-000000000001",
    )

    assert text == "This report covers 32 findings from the import of trivy.json (run 1234abcd)."
    assert partial is False


def test_report_scope_flags_reevaluation_runs_as_partial() -> None:
    text, partial = report_scope(
        finding_count=1,
        input_type="reevaluation",
        filename=None,
        run_id="5678ef00-0000-4000-8000-000000000002",
    )

    assert text.startswith("This report covers 1 finding re-scored by a re-evaluation run")
    assert "does not cover the rest of the project" in text
    assert partial is True

from __future__ import annotations

from datetime import UTC, datetime

from app.services.report_formatting import (
    csv_safe_cell,
    dict_value,
    format_number,
    iso_datetime,
    metadata_bool,
    metadata_list,
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

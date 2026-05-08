from __future__ import annotations

from types import SimpleNamespace

from vuln_prioritizer.reporting_executive_utils import (
    _float_value,
    _format_report_timestamp,
    _int_value,
    _pct,
    _provider_value,
    _short_provider_date,
)


def test_executive_utils_parse_invalid_numbers_and_percentages() -> None:
    assert _int_value("not-an-int") == 0
    assert _float_value("not-a-float") == -1.0
    assert _float_value(float("nan")) == -1.0
    assert _pct(10, 0) == 0


def test_executive_utils_format_provider_and_timestamp_values() -> None:
    assert _provider_value(None, "nvd_last_sync") == "not available"
    assert _provider_value(SimpleNamespace(nvd_last_sync="2026-05-01"), "nvd_last_sync") == (
        "2026-05-01"
    )
    assert _short_provider_date("") == "not available"
    assert _short_provider_date("2026-05-01T12:34:56Z") == "2026-05-01 12:34"
    assert _short_provider_date("2026-05-01") == "2026-05-01"
    assert _format_report_timestamp("not-a-date") == "not-a-date"

from __future__ import annotations

from app.domain.engine.utils import (
    chunk_cve_ids,
    comma_join,
    iso_utc_now,
    normalize_cve_id,
    safe_float,
)


def test_iso_utc_now_uses_fixed_environment_override(monkeypatch) -> None:
    monkeypatch.setenv("WORKBENCH_FIXED_NOW", "2026-04-21T12:00:00+00:00")

    assert iso_utc_now() == "2026-04-21T12:00:00+00:00"


def test_common_utils_cover_normalization_conversion_and_chunking_edges() -> None:
    assert normalize_cve_id(" cve-2026-0001 ") == "CVE-2026-0001"
    assert normalize_cve_id("   ") is None
    assert normalize_cve_id("not-a-cve") is None
    assert safe_float(None) is None
    assert safe_float(object()) is None
    assert safe_float("not-a-number") is None
    assert safe_float("1.5") == 1.5
    assert chunk_cve_ids(["CVE-2026-0001", "CVE-2026-0002"], max_chars=14) == [
        ["CVE-2026-0001"],
        ["CVE-2026-0002"],
    ]
    assert comma_join(["one", "", "two"]) == "one, two"

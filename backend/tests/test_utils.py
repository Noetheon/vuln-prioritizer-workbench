from __future__ import annotations

from vuln_prioritizer.utils import iso_utc_now


def test_iso_utc_now_uses_fixed_environment_override(monkeypatch) -> None:
    monkeypatch.setenv("VULN_PRIORITIZER_FIXED_NOW", "2026-04-21T12:00:00+00:00")

    assert iso_utc_now() == "2026-04-21T12:00:00+00:00"

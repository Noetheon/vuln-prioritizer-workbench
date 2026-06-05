from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from paths import DATA_ROOT

from app.domain.engine.providers.epss import EpssProvider
from app.domain.engine.providers.kev import KevProvider
from app.domain.engine.providers.nvd import NvdProvider

FIXTURE_ROOT = DATA_ROOT / "provider_contract_fixtures" / "v1"


class FixtureResponse:
    status_code = 200

    def __init__(self, payload: dict[str, Any]) -> None:
        self._payload = payload

    def json(self) -> dict[str, Any]:
        return self._payload

    def raise_for_status(self) -> None:
        return None


class FixtureSession:
    def __init__(self, payload: dict[str, Any]) -> None:
        self.payload = payload
        self.calls: list[dict[str, Any]] = []

    def get(self, url: str, **kwargs: Any) -> FixtureResponse:
        self.calls.append({"url": url, **kwargs})
        return FixtureResponse(self.payload)


def _load_fixture(provider: str, path: Path, *, required_keys: set[str]) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    missing = sorted(required_keys - set(payload))
    if missing:
        raise AssertionError(
            f"{provider} provider fixture {path} is missing required key(s): " + ", ".join(missing)
        )
    return payload


def test_epss_fixture_response_maps_to_epss_data_contract() -> None:
    payload = _load_fixture(
        "epss",
        FIXTURE_ROOT / "epss_first_response.json",
        required_keys={"data"},
    )
    session = FixtureSession(payload)
    provider = EpssProvider(session=session)

    records, warnings = provider.fetch_many(["CVE-2026-2001"])

    assert warnings == []
    assert session.calls[0]["params"] == {"cve": "CVE-2026-2001"}
    assert records["CVE-2026-2001"].epss == 0.73456
    assert records["CVE-2026-2001"].percentile == 0.98765
    assert records["CVE-2026-2001"].date == "2026-04-21"
    assert provider.last_diagnostics.content_hits == 1
    assert provider.last_diagnostics.network_fetches == 1


def test_kev_fixture_catalog_maps_to_kev_data_contract() -> None:
    fixture_path = FIXTURE_ROOT / "kev_catalog.json"
    _load_fixture("kev", fixture_path, required_keys={"vulnerabilities"})

    records, warnings = KevProvider().fetch_many(["CVE-2026-2001"], offline_file=fixture_path)

    assert warnings == []
    assert records["CVE-2026-2001"].in_kev is True
    assert records["CVE-2026-2001"].vendor_project == "Example Vendor"
    assert records["CVE-2026-2001"].product == "Example Product"
    assert records["CVE-2026-2001"].due_date == "2026-05-12"


def test_nvd_fixture_response_maps_to_nvd_data_contract() -> None:
    payload = _load_fixture(
        "nvd",
        FIXTURE_ROOT / "nvd_cve_api_2_0_response.json",
        required_keys={"vulnerabilities"},
    )

    record = NvdProvider.parse_payload("CVE-2026-2001", payload)

    assert record.cve_id == "CVE-2026-2001"
    assert record.description == (
        "Example Product allows command injection through a crafted request."
    )
    assert record.cvss_base_score == 9.3
    assert record.cvss_severity == "CRITICAL"
    assert record.cvss_version == "4.0"
    assert record.cvss_vector.startswith("CVSS:4.0/")
    assert record.cwes == ["CWE-78"]
    assert record.reference_tags == {
        "https://example.invalid/advisory/CVE-2026-2001": ["Vendor Advisory", "Patch"]
    }


def test_nvd_fixture_response_fetch_many_maps_live_contract_without_network() -> None:
    payload = _load_fixture(
        "nvd",
        FIXTURE_ROOT / "nvd_cve_api_2_0_response.json",
        required_keys={"vulnerabilities"},
    )
    session = FixtureSession(payload)
    provider = NvdProvider.from_env(session=session)

    records, warnings = provider.fetch_many(["CVE-2026-2001"])

    assert warnings == []
    assert session.calls[0]["params"] == {"cveIds": "CVE-2026-2001"}
    assert records["CVE-2026-2001"].cve_id == "CVE-2026-2001"
    assert records["CVE-2026-2001"].description == (
        "Example Product allows command injection through a crafted request."
    )
    assert provider.last_diagnostics.content_hits == 1
    assert provider.last_diagnostics.network_fetches == 1


def test_provider_contract_fixture_schema_failures_include_provider_and_path() -> None:
    fixture_path = FIXTURE_ROOT / "invalid" / "epss_missing_data.json"

    with pytest.raises(AssertionError) as exc_info:
        _load_fixture("epss", fixture_path, required_keys={"data"})

    message = str(exc_info.value)
    assert "epss provider fixture" in message
    assert str(fixture_path) in message
    assert "data" in message

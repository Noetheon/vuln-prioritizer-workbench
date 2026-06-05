from __future__ import annotations

import os

import pytest

from app.domain.engine.providers.epss import EpssProvider
from app.domain.engine.providers.kev import KevProvider
from app.domain.engine.providers.nvd import NvdProvider

pytestmark = pytest.mark.live_network


def _require_live_provider_tests() -> None:
    if os.getenv("VPW_RUN_LIVE_PROVIDER_TESTS") != "1":
        pytest.skip("Set VPW_RUN_LIVE_PROVIDER_TESTS=1 to run optional live provider checks.")


def test_live_epss_provider_contract_smoke() -> None:
    _require_live_provider_tests()

    records, warnings = EpssProvider().fetch_many(["CVE-2021-44228"])

    assert warnings == []
    assert records["CVE-2021-44228"].cve_id == "CVE-2021-44228"
    assert records["CVE-2021-44228"].epss is not None


def test_live_kev_provider_contract_smoke() -> None:
    _require_live_provider_tests()

    records, warnings = KevProvider().fetch_many(["CVE-2021-44228"])

    assert warnings == []
    assert records["CVE-2021-44228"].in_kev is True


def test_live_nvd_provider_contract_smoke() -> None:
    _require_live_provider_tests()

    records, warnings = NvdProvider.from_env().fetch_many(["CVE-2021-44228"])

    assert warnings == []
    assert records["CVE-2021-44228"].cve_id == "CVE-2021-44228"
    assert records["CVE-2021-44228"].description

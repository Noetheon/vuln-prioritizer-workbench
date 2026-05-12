from __future__ import annotations

import hashlib
import json
import threading
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlparse

import pytest
import requests
from paths import DATA_ROOT

from vuln_prioritizer.cache import FileCache
from vuln_prioritizer.config import (
    EPSS_API_URL,
    KEV_FEED_URL,
    KEV_MIRROR_URL,
    NVD_API_URL,
    ProviderConfig,
)
from vuln_prioritizer.models import (
    AttackData,
    EpssData,
    KevData,
    NvdData,
    ProviderLookupDiagnostics,
    ProviderSnapshotMetadata,
    ProviderSnapshotReport,
)
from vuln_prioritizer.providers.attack import AttackProvider
from vuln_prioritizer.providers.attack_metadata import AttackMetadataProvider
from vuln_prioritizer.providers.attack_stix import AttackStixProvider
from vuln_prioritizer.providers.ctid_mappings import CtidMappingsProvider
from vuln_prioritizer.providers.curated_attack_mappings import (
    CuratedAttackMappingProvider,
    CuratedAttackMappingValidationError,
)
from vuln_prioritizer.providers.epss import EpssProvider
from vuln_prioritizer.providers.kev import KevProvider
from vuln_prioritizer.providers.nvd import NvdFetchDiagnostics, NvdProvider
from vuln_prioritizer.services.enrichment import EnrichmentService, _provider_data_quality_flags


class FakeResponse:
    def __init__(
        self,
        json_data: dict | None = None,
        status_code: int = 200,
        headers: dict[str, str] | None = None,
    ) -> None:
        self._json_data = json_data or {}
        self.status_code = status_code
        self.headers = headers or {}

    def json(self) -> dict:
        return self._json_data

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            error = requests.HTTPError(f"{self.status_code} error")
            error.response = self
            raise error


def test_provider_endpoint_constants_are_https_and_pinned_to_public_hosts() -> None:
    expected_endpoints = {
        NVD_API_URL: ("services.nvd.nist.gov", "/rest/json/cves/2.0"),
        EPSS_API_URL: ("api.first.org", "/data/v1/epss"),
        KEV_FEED_URL: (
            "www.cisa.gov",
            "/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        ),
        KEV_MIRROR_URL: (
            "raw.githubusercontent.com",
            "/cisagov/kev-data/develop/known_exploited_vulnerabilities.json",
        ),
    }

    for endpoint, (expected_host, expected_path) in expected_endpoints.items():
        parsed = urlparse(endpoint)
        assert parsed.scheme == "https"
        assert parsed.hostname == expected_host
        assert parsed.path == expected_path

    assert not any("url" in name.lower() for name in ProviderConfig.__dataclass_fields__)


@pytest.mark.parametrize(
    "unsafe_name",
    ["lowercase_key", "1NVD_API_KEY", "NVD-API-KEY", "NVD API KEY", ""],
)
def test_provider_config_rejects_unsafe_nvd_api_key_env_names(unsafe_name: str) -> None:
    with pytest.raises(ValueError, match="NVD API key environment variable name must match"):
        ProviderConfig(nvd_api_key_env=unsafe_name)

    with pytest.raises(ValueError, match="NVD API key environment variable name must match"):
        NvdProvider.from_env(api_key_env=unsafe_name)


def test_provider_requests_ignore_endpoint_environment_overrides(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in (
        "NVD_API_URL",
        "EPSS_API_URL",
        "KEV_FEED_URL",
        "KEV_MIRROR_URL",
        "VULN_PRIORITIZER_NVD_API_URL",
        "VULN_PRIORITIZER_EPSS_API_URL",
        "VULN_PRIORITIZER_KEV_FEED_URL",
        "VULN_PRIORITIZER_KEV_MIRROR_URL",
    ):
        monkeypatch.setenv(name, "http://127.0.0.1/unsafe")

    class RecordingSession:
        def __init__(self, payload: dict) -> None:
            self.payload = payload
            self.urls: list[str] = []

        def get(self, url: str, *args, **kwargs):  # noqa: ANN002, ANN003
            self.urls.append(url)
            return FakeResponse(self.payload)

    nvd_session = RecordingSession({"vulnerabilities": []})
    epss_session = RecordingSession({"data": []})
    kev_session = RecordingSession({"vulnerabilities": []})

    NvdProvider(session=nvd_session).fetch_many(["CVE-2026-0710"])
    EpssProvider(session=epss_session).fetch_many(["CVE-2026-0710"])
    KevProvider(session=kev_session).fetch_many(["CVE-2026-0710"])

    assert nvd_session.urls == [NVD_API_URL]
    assert epss_session.urls == [EPSS_API_URL]
    assert kev_session.urls == [KEV_FEED_URL]


def test_kev_provider_fallback_uses_pinned_https_mirror() -> None:
    class FallbackSession:
        def __init__(self) -> None:
            self.urls: list[str] = []

        def get(self, url: str, *args, **kwargs):  # noqa: ANN002, ANN003
            self.urls.append(url)
            if url == KEV_FEED_URL:
                raise requests.RequestException("primary feed unavailable")
            return FakeResponse({"vulnerabilities": []})

    session = FallbackSession()

    KevProvider(session=session).fetch_many(["CVE-2026-0711"])

    assert session.urls == [KEV_FEED_URL, KEV_MIRROR_URL]


@pytest.mark.parametrize(
    "unsafe_url",
    [
        "http://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "https://user:pass@www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "https://localhost/kev.json",
        "https://127.0.0.1/kev.json",
        "https://10.0.0.5/kev.json",
        f"{KEV_FEED_URL}?override=true",
    ],
)
def test_kev_provider_rejects_unsafe_endpoint_overrides(unsafe_url: str) -> None:
    with pytest.raises(ValueError, match="must use a pinned HTTPS public provider endpoint"):
        KevProvider(feed_url=unsafe_url)

    with pytest.raises(ValueError, match="must use a pinned HTTPS public provider endpoint"):
        KevProvider(mirror_url=unsafe_url)


def test_nvd_parse_payload_prefers_v40_and_collects_metadata() -> None:
    payload = {
        "vulnerabilities": [
            {
                "cve": {
                    "descriptions": [
                        {"lang": "de", "value": "Deutsch"},
                        {"lang": "en", "value": "English description"},
                    ],
                    "published": "2026-01-01T00:00:00.000",
                    "lastModified": "2026-01-02T00:00:00.000",
                    "vulnStatus": "Analyzed",
                    "weaknesses": [
                        {"description": [{"lang": "en", "value": "CWE-79"}]},
                    ],
                    "references": [
                        {
                            "url": "https://example.com/advisory",
                            "tags": ["Vendor Advisory", "Patch"],
                        }
                    ],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {"baseScore": 8.0, "baseSeverity": "HIGH"},
                            }
                        ],
                        "cvssMetricV40": [
                            {
                                "cvssData": {
                                    "baseScore": 9.8,
                                    "baseSeverity": "CRITICAL",
                                    "vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N",
                                },
                            }
                        ],
                    },
                }
            }
        ]
    }

    parsed = NvdProvider.parse_payload("CVE-2026-0001", payload)

    assert parsed.description == "English description"
    assert parsed.cvss_base_score == 9.8
    assert parsed.cvss_severity == "CRITICAL"
    assert parsed.cvss_version == "4.0"
    assert parsed.cvss_vector == "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N"
    assert parsed.vulnerability_status == "Analyzed"
    assert parsed.cwes == ["CWE-79"]
    assert parsed.references == ["https://example.com/advisory"]
    assert parsed.reference_tags == {"https://example.com/advisory": ["Vendor Advisory", "Patch"]}


def test_nvd_parse_payload_uses_later_primary_v31_metric() -> None:
    payload = {
        "vulnerabilities": [
            {
                "cve": {
                    "descriptions": [{"lang": "en", "value": "CVSS v3 fallback"}],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "type": "Secondary",
                                "cvssData": {"vectorString": "CVSS:3.1/AV:L/AC:H"},
                            },
                            {
                                "type": "Primary",
                                "cvssData": {
                                    "baseScore": 7.4,
                                    "baseSeverity": "HIGH",
                                    "vectorString": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N",
                                },
                            },
                        ],
                    },
                }
            }
        ]
    }

    parsed = NvdProvider.parse_payload("CVE-2026-0002", payload)

    assert parsed.cvss_base_score == 7.4
    assert parsed.cvss_severity == "HIGH"
    assert parsed.cvss_version == "3.1"
    assert parsed.cvss_vector == "CVSS:3.1/AV:N/AC:H/PR:N/UI:N"


def test_nvd_fetch_many_handles_missing_results() -> None:
    class Session:
        def get(self, *args, **kwargs):  # noqa: ANN002, ANN003
            return FakeResponse({"vulnerabilities": []}, status_code=200)

    provider = NvdProvider(session=Session())
    results, warnings = provider.fetch_many(["CVE-2026-0001"])

    assert warnings == []
    assert results["CVE-2026-0001"].cvss_base_score is None


def test_nvd_uses_cache_on_second_fetch(tmp_path: Path) -> None:
    class Session:
        def __init__(self) -> None:
            self.calls = 0

        def get(self, *args, **kwargs):  # noqa: ANN002, ANN003
            self.calls += 1
            return FakeResponse(
                {
                    "vulnerabilities": [
                        {
                            "cve": {
                                "descriptions": [{"lang": "en", "value": "Cached NVD record"}],
                                "metrics": {
                                    "cvssMetricV31": [
                                        {
                                            "cvssData": {
                                                "baseScore": 8.8,
                                                "baseSeverity": "HIGH",
                                            }
                                        }
                                    ]
                                },
                            }
                        }
                    ]
                }
            )

    session = Session()
    cache = FileCache(tmp_path / "cache", ttl_hours=24)
    provider = NvdProvider(session=session, cache=cache)

    first_results, first_warnings = provider.fetch_many(["CVE-2026-1111"])
    second_results, second_warnings = provider.fetch_many(["CVE-2026-1111"])

    assert first_warnings == []
    assert second_warnings == []
    assert first_results["CVE-2026-1111"].description == "Cached NVD record"
    assert second_results["CVE-2026-1111"].description == "Cached NVD record"
    assert session.calls == 1


def test_nvd_fetch_many_preserves_input_order_and_counts_diagnostics(tmp_path: Path) -> None:
    class Session:
        def get(self, *args, **kwargs):  # noqa: ANN002, ANN003
            cve_id = kwargs["params"]["cveId"]
            return FakeResponse(
                {
                    "vulnerabilities": [
                        {
                            "cve": {
                                "descriptions": [{"lang": "en", "value": f"Live {cve_id}"}],
                            }
                        }
                    ]
                }
            )

    cache = FileCache(tmp_path / "cache", ttl_hours=24)
    cache.set_json(
        "nvd",
        "CVE-2026-0002",
        NvdData(cve_id="CVE-2026-0002", description="Cached record").model_dump(),
    )
    provider = NvdProvider(session=Session(), cache=cache, max_concurrency=2)

    results, warnings = provider.fetch_many(["CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"])

    assert list(results) == ["CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"]
    assert warnings == []
    assert results["CVE-2026-0002"].description == "Cached record"
    assert provider.last_diagnostics == NvdFetchDiagnostics(
        requested=3,
        cache_hits=1,
        network_fetches=2,
        failures=0,
        content_hits=3,
    )


def test_nvd_fetch_many_bounds_network_concurrency() -> None:
    class Monitor:
        def __init__(self) -> None:
            self.lock = threading.Lock()
            self.release = threading.Event()
            self.seen = 0
            self.in_flight = 0
            self.max_in_flight = 0

    class Session:
        def __init__(self, monitor: Monitor) -> None:
            self.monitor = monitor

        def get(self, *args, **kwargs):  # noqa: ANN002, ANN003
            cve_id = kwargs["params"]["cveId"]
            with self.monitor.lock:
                self.monitor.seen += 1
                self.monitor.in_flight += 1
                self.monitor.max_in_flight = max(
                    self.monitor.max_in_flight,
                    self.monitor.in_flight,
                )
                if self.monitor.seen >= 2:
                    self.monitor.release.set()
            self.monitor.release.wait(timeout=1)
            with self.monitor.lock:
                self.monitor.in_flight -= 1
            return FakeResponse(
                {
                    "vulnerabilities": [
                        {
                            "cve": {
                                "descriptions": [{"lang": "en", "value": f"Live {cve_id}"}],
                            }
                        }
                    ]
                }
            )

        def close(self) -> None:
            pass

    monitor = Monitor()
    provider = NvdProvider(session_factory=lambda: Session(monitor), max_concurrency=2)

    results, warnings = provider.fetch_many(
        [
            "CVE-2026-0101",
            "CVE-2026-0102",
            "CVE-2026-0103",
            "CVE-2026-0104",
        ]
    )

    assert warnings == []
    assert list(results) == [
        "CVE-2026-0101",
        "CVE-2026-0102",
        "CVE-2026-0103",
        "CVE-2026-0104",
    ]
    assert monitor.max_in_flight == 2


def test_nvd_fetch_many_degrades_gracefully_and_keeps_warning_order() -> None:
    class Session:
        def get(self, *args, **kwargs):  # noqa: ANN002, ANN003
            cve_id = kwargs["params"]["cveId"]
            if cve_id == "CVE-2026-0202":
                raise requests.RequestException("boom")
            return FakeResponse(
                {
                    "vulnerabilities": [
                        {
                            "cve": {
                                "descriptions": [{"lang": "en", "value": f"Live {cve_id}"}],
                            }
                        }
                    ]
                }
            )

    provider = NvdProvider(session=Session(), max_concurrency=3)

    results, warnings = provider.fetch_many(["CVE-2026-0201", "CVE-2026-0202", "CVE-2026-0203"])

    assert list(results) == ["CVE-2026-0201", "CVE-2026-0202", "CVE-2026-0203"]
    assert warnings == ["NVD lookup failed for CVE-2026-0202: boom"]
    assert results["CVE-2026-0201"].description == "Live CVE-2026-0201"
    assert results["CVE-2026-0202"] == NvdData(cve_id="CVE-2026-0202")
    assert results["CVE-2026-0203"].description == "Live CVE-2026-0203"
    assert provider.last_diagnostics == NvdFetchDiagnostics(
        requested=3,
        cache_hits=0,
        network_fetches=3,
        failures=1,
        content_hits=2,
        empty_records=1,
        degraded=True,
    )


def test_nvd_fetch_many_retries_rate_limited_response(monkeypatch) -> None:  # noqa: ANN001
    sleep_calls: list[float] = []

    class Session:
        def __init__(self) -> None:
            self.calls = 0

        def get(self, *args, **kwargs):  # noqa: ANN002, ANN003
            self.calls += 1
            if self.calls == 1:
                return FakeResponse(status_code=429, headers={"Retry-After": "0"})
            return FakeResponse(
                {
                    "vulnerabilities": [
                        {
                            "cve": {
                                "descriptions": [{"lang": "en", "value": "Retried NVD record"}],
                                "metrics": {
                                    "cvssMetricV40": [
                                        {
                                            "cvssData": {
                                                "baseScore": 8.7,
                                                "baseSeverity": "HIGH",
                                            }
                                        }
                                    ]
                                },
                            }
                        }
                    ]
                }
            )

    monkeypatch.setattr(
        "vuln_prioritizer.providers.nvd.time.sleep",
        lambda seconds: sleep_calls.append(seconds),
    )
    session = Session()
    provider = NvdProvider(session=session, max_retries=2)

    results, warnings = provider.fetch_many(["CVE-2026-0204"])

    assert warnings == []
    assert session.calls == 2
    assert sleep_calls == [0.0]
    assert results["CVE-2026-0204"].description == "Retried NVD record"
    assert results["CVE-2026-0204"].cvss_version == "4.0"


def test_nvd_api_key_from_env_is_sent_and_redacted_from_warnings(monkeypatch) -> None:  # noqa: ANN001
    secret = "nvd-secret-value"

    class Session:
        def __init__(self) -> None:
            self.headers: list[dict[str, str]] = []

        def get(self, *args, **kwargs):  # noqa: ANN002, ANN003
            self.headers.append(kwargs["headers"])
            raise requests.RequestException(f"transport failure for apiKey={secret}")

    monkeypatch.setenv("VPW_NVD_TEST_API_KEY", secret)
    session = Session()
    provider = NvdProvider.from_env(api_key_env="VPW_NVD_TEST_API_KEY", session=session)

    results, warnings = provider.fetch_many(["CVE-2026-0205"])

    assert session.headers == [{"apiKey": secret}]
    assert results["CVE-2026-0205"] == NvdData(cve_id="CVE-2026-0205")
    assert len(warnings) == 1
    assert secret not in warnings[0]
    assert "apiKey=<redacted>" in warnings[0]
    assert provider.last_diagnostics.degraded is True


def test_nvd_fetch_many_warns_on_cache_load_failure_and_deduplicates_inputs() -> None:
    class BrokenCache:
        def get_json(self, *_args, **_kwargs):  # noqa: ANN002, ANN003
            raise ValueError("cache contains token secret-value")

        def set_json(self, *_args, **_kwargs):  # noqa: ANN002, ANN003
            return None

    class Session:
        def __init__(self) -> None:
            self.requests: list[str] = []

        def get(self, *args, **kwargs):  # noqa: ANN002, ANN003
            cve_id = kwargs["params"]["cveId"]
            self.requests.append(cve_id)
            return FakeResponse(
                {
                    "vulnerabilities": [
                        {
                            "cve": {
                                "descriptions": [{"lang": "en", "value": f"Live {cve_id}"}],
                            }
                        }
                    ]
                }
            )

    session = Session()
    provider = NvdProvider(
        session=session,
        api_key="secret-value",
        cache=BrokenCache(),  # type: ignore[arg-type]
    )

    results, warnings = provider.fetch_many(["CVE-2026-0301", "CVE-2026-0301"])

    assert list(results) == ["CVE-2026-0301"]
    assert session.requests == ["CVE-2026-0301"]
    assert results["CVE-2026-0301"].description == "Live CVE-2026-0301"
    assert warnings == ["NVD cache load failed for CVE-2026-0301: cache contains token <redacted>"]


def test_nvd_fetch_many_uses_expired_cache_when_network_fails(tmp_path: Path) -> None:
    class Session:
        def get(self, *args, **kwargs):  # noqa: ANN002, ANN003
            raise requests.RequestException("nvd offline")

    cache = FileCache(tmp_path / "cache", ttl_hours=1)
    cache_path = cache._path_for("nvd", "CVE-2026-0302")
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(
        json.dumps(
            {
                "key": "CVE-2026-0302",
                "cached_at": "2000-01-01T00:00:00+00:00",
                "payload": NvdData(
                    cve_id="CVE-2026-0302",
                    description="Expired NVD record",
                ).model_dump(),
            }
        ),
        encoding="utf-8",
    )

    provider = NvdProvider(session=Session(), cache=cache)
    results, warnings = provider.fetch_many(["CVE-2026-0302"])

    assert results["CVE-2026-0302"].description == "Expired NVD record"
    assert any("using expired cached data" in warning for warning in warnings)
    assert provider.last_diagnostics.stale_cache_hits == 1
    assert provider.last_diagnostics.failures == 1
    assert provider.last_diagnostics.degraded is True


def test_nvd_request_handles_404_and_retryable_exceptions(monkeypatch) -> None:  # noqa: ANN001
    class Session:
        def __init__(self) -> None:
            self.calls = 0

        def get(self, *args, **kwargs):  # noqa: ANN002, ANN003
            self.calls += 1
            if self.calls == 1:
                response = FakeResponse(status_code=503, headers={"Retry-After": "invalid"})
                error = requests.HTTPError("503 transient")
                error.response = response
                raise error
            return FakeResponse(status_code=404)

    sleep_calls: list[float] = []
    monkeypatch.setattr("vuln_prioritizer.providers.nvd.time.sleep", sleep_calls.append)
    monkeypatch.setattr("vuln_prioritizer.providers.nvd.random.uniform", lambda *_args: 0.0)

    session = Session()
    provider = NvdProvider(session=session, max_retries=2)
    results, warnings = provider.fetch_many(["CVE-2026-0303"])

    assert warnings == []
    assert session.calls == 2
    assert sleep_calls == [1.0]
    assert results["CVE-2026-0303"] == NvdData(cve_id="CVE-2026-0303")


def test_nvd_parse_payload_falls_back_to_non_english_description_and_metric_severity() -> None:
    payload = {
        "vulnerabilities": [
            {
                "cve": {
                    "descriptions": [{"lang": "de", "value": "Beschreibung"}],
                    "metrics": {
                        "cvssMetricV2": [
                            {
                                "type": "Secondary",
                                "baseSeverity": "MEDIUM",
                                "cvssData": {"vectorString": "AV:N/AC:L/Au:N/C:P/I:N/A:N"},
                            }
                        ]
                    },
                    "references": [
                        {"name": "missing-url"},
                        {"url": "https://example.test/nvd", "tags": [None, " Patch ", ""]},
                    ],
                }
            }
        ]
    }

    parsed = NvdProvider.parse_payload("CVE-2026-0304", payload)

    assert parsed.description == "Beschreibung"
    assert parsed.cvss_base_score is None
    assert parsed.cvss_severity == "MEDIUM"
    assert parsed.cvss_version == "2.0"
    assert parsed.references == ["https://example.test/nvd"]
    assert parsed.reference_tags == {"https://example.test/nvd": ["Patch"]}


def test_enrichment_service_tracks_last_nvd_diagnostics() -> None:
    class Session:
        def get(self, *args, **kwargs):  # noqa: ANN002, ANN003
            cve_id = kwargs["params"]["cveId"]
            return FakeResponse(
                {
                    "vulnerabilities": [
                        {
                            "cve": {
                                "descriptions": [{"lang": "en", "value": f"Live {cve_id}"}],
                            }
                        }
                    ]
                }
            )

    class StubEpssProvider:
        def fetch_many(self, cve_ids, *, refresh: bool = False):  # noqa: ANN001, ARG002
            return ({cve_id: EpssData(cve_id=cve_id) for cve_id in cve_ids}, [])

    class StubKevProvider:
        def fetch_many(  # noqa: ANN001, ARG002
            self, cve_ids, offline_file=None, *, refresh: bool = False
        ):
            return ({cve_id: KevData(cve_id=cve_id) for cve_id in cve_ids}, [])

    class StubAttackProvider:
        def fetch_many(  # noqa: ANN001
            self,
            cve_ids,
            *,
            enabled: bool,
            source: str,
            mapping_file,
            technique_metadata_file,
            offline_file,
        ):
            return (
                {cve_id: AttackData(cve_id=cve_id) for cve_id in cve_ids},
                {
                    "source": source if enabled else "none",
                    "mapping_file": None,
                    "technique_metadata_file": None,
                    "source_version": None,
                    "attack_version": None,
                    "domain": None,
                    "mapping_framework": None,
                    "mapping_framework_version": None,
                },
                [],
            )

    service = EnrichmentService(session=Session(), use_cache=False)
    service.epss = StubEpssProvider()
    service.kev = StubKevProvider()
    service.attack = StubAttackProvider()

    result = service.enrich(["CVE-2026-0301"], attack_enabled=False)

    assert result.nvd["CVE-2026-0301"].description == "Live CVE-2026-0301"
    assert service.last_nvd_diagnostics == NvdFetchDiagnostics(
        requested=1,
        cache_hits=0,
        network_fetches=1,
        failures=0,
        content_hits=1,
    )


def test_enrichment_service_nvd_failure_records_data_quality_flags() -> None:
    class ExplodingNvdProvider:
        api_key = "nvd-secret-value"

        def fetch_many(self, cve_ids):  # noqa: ANN001, ARG002
            raise RuntimeError("invalid NVD cache for nvd-secret-value")

    class StubEpssProvider:
        last_diagnostics = ProviderLookupDiagnostics(
            requested=1,
            network_fetches=1,
            content_hits=0,
            empty_records=1,
        )

        def fetch_many(self, cve_ids):  # noqa: ANN001
            return ({cve_id: EpssData(cve_id=cve_id) for cve_id in cve_ids}, [])

    class StubKevProvider:
        last_diagnostics = ProviderLookupDiagnostics(
            requested=1,
            network_fetches=1,
            content_hits=0,
            empty_records=1,
        )

        def fetch_many(self, cve_ids, offline_file=None):  # noqa: ANN001, ARG002
            return ({cve_id: KevData(cve_id=cve_id) for cve_id in cve_ids}, [])

    class StubAttackProvider:
        def fetch_many(  # noqa: ANN001
            self,
            cve_ids,
            *,
            enabled: bool,
            source: str,
            mapping_file,
            technique_metadata_file,
            offline_file,
        ):
            return (
                {cve_id: AttackData(cve_id=cve_id) for cve_id in cve_ids},
                {
                    "source": source if enabled else "none",
                    "mapping_file": None,
                    "technique_metadata_file": None,
                    "source_version": None,
                    "attack_version": None,
                    "domain": None,
                    "mapping_framework": None,
                    "mapping_framework_version": None,
                },
                [],
            )

    service = EnrichmentService(use_cache=False)
    service.nvd = ExplodingNvdProvider()
    service.epss = StubEpssProvider()
    service.kev = StubKevProvider()
    service.attack = StubAttackProvider()

    result = service.enrich(["CVE-2026-0401"], attack_enabled=False)

    assert result.nvd["CVE-2026-0401"] == NvdData(cve_id="CVE-2026-0401")
    assert result.warnings == ["NVD provider failed: invalid NVD cache for <redacted>"]
    assert result.nvd_diagnostics.failures == 1
    assert result.nvd_diagnostics.empty_records == 1
    assert {
        "provider_failure",
        "provider_missing_data",
        "provider_warning",
        "provider_error",
        "nvd_missing",
    } <= {flag.code for flag in result.provider_data_quality_flags["nvd"]}
    assert "nvd-secret-value" not in result.model_dump_json()


def test_enrichment_service_flags_nvd_missing_cvss() -> None:
    class StubNvdProvider:
        last_diagnostics = NvdFetchDiagnostics(
            requested=1,
            network_fetches=1,
            content_hits=1,
        )

        def fetch_many(self, cve_ids):  # noqa: ANN001
            return (
                {
                    cve_id: NvdData(
                        cve_id=cve_id,
                        description="NVD record without CVSS metrics",
                        published="2026-04-29T00:00:00.000",
                    )
                    for cve_id in cve_ids
                },
                [],
            )

    class StubEpssProvider:
        last_diagnostics = ProviderLookupDiagnostics(
            requested=1,
            network_fetches=1,
            content_hits=0,
            empty_records=1,
        )

        def fetch_many(self, cve_ids):  # noqa: ANN001
            return ({cve_id: EpssData(cve_id=cve_id) for cve_id in cve_ids}, [])

    class StubKevProvider:
        last_diagnostics = ProviderLookupDiagnostics(
            requested=1,
            network_fetches=1,
            content_hits=0,
            empty_records=1,
        )

        def fetch_many(self, cve_ids, offline_file=None):  # noqa: ANN001, ARG002
            return ({cve_id: KevData(cve_id=cve_id) for cve_id in cve_ids}, [])

    class StubAttackProvider:
        def fetch_many(  # noqa: ANN001
            self,
            cve_ids,
            *,
            enabled: bool,
            source: str,
            mapping_file,
            technique_metadata_file,
            offline_file,
        ):
            return (
                {cve_id: AttackData(cve_id=cve_id) for cve_id in cve_ids},
                {
                    "source": source if enabled else "none",
                    "mapping_file": None,
                    "technique_metadata_file": None,
                    "source_version": None,
                    "attack_version": None,
                    "domain": None,
                    "mapping_framework": None,
                    "mapping_framework_version": None,
                },
                [],
            )

    service = EnrichmentService(use_cache=False)
    service.nvd = StubNvdProvider()
    service.epss = StubEpssProvider()
    service.kev = StubKevProvider()
    service.attack = StubAttackProvider()

    result = service.enrich(["CVE-2026-0402"], attack_enabled=False)

    flags = result.provider_data_quality_flags["nvd"]
    assert [flag.code for flag in flags] == ["nvd_cvss_missing"]
    assert flags[0].cve_id == "CVE-2026-0402"
    assert "without a CVSS base score or version" in flags[0].message


def test_enrichment_service_epss_failure_records_data_quality_flags() -> None:
    class StubNvdProvider:
        last_diagnostics = NvdFetchDiagnostics(
            requested=1,
            network_fetches=1,
            content_hits=1,
        )

        def fetch_many(self, cve_ids):  # noqa: ANN001
            return (
                {
                    cve_id: NvdData(
                        cve_id=cve_id,
                        description="NVD record",
                        cvss_base_score=7.5,
                    )
                    for cve_id in cve_ids
                },
                [],
            )

    class ExplodingEpssProvider:
        def fetch_many(self, cve_ids):  # noqa: ANN001, ARG002
            raise RuntimeError("invalid EPSS cache")

    class StubKevProvider:
        last_diagnostics = ProviderLookupDiagnostics(
            requested=1,
            network_fetches=1,
            content_hits=0,
        )

        def fetch_many(self, cve_ids, offline_file=None):  # noqa: ANN001, ARG002
            return ({cve_id: KevData(cve_id=cve_id) for cve_id in cve_ids}, [])

    class StubAttackProvider:
        def fetch_many(  # noqa: ANN001
            self,
            cve_ids,
            *,
            enabled: bool,
            source: str,
            mapping_file,
            technique_metadata_file,
            offline_file,
        ):
            return (
                {cve_id: AttackData(cve_id=cve_id) for cve_id in cve_ids},
                {
                    "source": source if enabled else "none",
                    "mapping_file": None,
                    "technique_metadata_file": None,
                    "source_version": None,
                    "attack_version": None,
                    "domain": None,
                    "mapping_framework": None,
                    "mapping_framework_version": None,
                },
                [],
            )

    service = EnrichmentService(use_cache=False)
    service.nvd = StubNvdProvider()
    service.epss = ExplodingEpssProvider()
    service.kev = StubKevProvider()
    service.attack = StubAttackProvider()

    result = service.enrich(["CVE-2026-0501"], attack_enabled=False)

    assert result.epss["CVE-2026-0501"] == EpssData(cve_id="CVE-2026-0501")
    assert result.warnings == ["EPSS provider failed: invalid EPSS cache"]
    assert result.epss_diagnostics.failures == 1
    assert result.epss_diagnostics.empty_records == 1
    assert {
        "provider_failure",
        "provider_missing_data",
        "provider_warning",
        "provider_error",
        "epss_missing",
    } <= {flag.code for flag in result.provider_data_quality_flags["epss"]}
    assert result.provider_data_quality_flags["epss"][1].message == (
        "epss returned no provider content for 1 requested CVE(s)."
    )


def test_vpw027_provider_data_quality_flags_include_canonical_codes() -> None:
    flags_by_source = _provider_data_quality_flags(
        nvd_results={
            "CVE-2026-0601": NvdData(cve_id="CVE-2026-0601"),
            "CVE-2026-0602": NvdData(
                cve_id="CVE-2026-0602",
                description="NVD metadata without CVSS.",
            ),
        },
        epss_results={"CVE-2026-0601": EpssData(cve_id="CVE-2026-0601")},
        provider_snapshot=ProviderSnapshotReport(
            metadata=ProviderSnapshotMetadata(
                generated_at="2026-04-29T12:00:00+00:00",
                selected_sources=["nvd", "epss", "kev"],
            )
        ),
        locked_provider_data=True,
        nvd=(
            ProviderLookupDiagnostics(
                requested=2,
                failures=1,
                empty_records=1,
                degraded=True,
            ),
            ["NVD lookup failed"],
        ),
        epss=(
            ProviderLookupDiagnostics(
                requested=1,
                content_hits=1,
                stale_cache_hits=1,
                degraded=True,
            ),
            [],
        ),
        kev=(
            ProviderLookupDiagnostics(
                requested=1,
                failures=1,
                empty_records=1,
                degraded=True,
            ),
            ["KEV catalog load failed"],
        ),
    )

    codes = {flag.code for flags in flags_by_source.values() for flag in flags}

    assert {
        "nvd_missing",
        "nvd_cvss_missing",
        "epss_missing",
        "epss_outdated",
        "kev_unavailable",
        "snapshot_locked",
        "provider_error",
    } <= codes


@pytest.mark.parametrize(
    ("expected_code", "kwargs"),
    [
        (
            "nvd_missing",
            {"nvd_results": {"CVE-2026-0601": NvdData(cve_id="CVE-2026-0601")}},
        ),
        (
            "nvd_cvss_missing",
            {
                "nvd_results": {
                    "CVE-2026-0602": NvdData(
                        cve_id="CVE-2026-0602",
                        description="NVD metadata without CVSS.",
                    )
                }
            },
        ),
        (
            "epss_missing",
            {"epss_results": {"CVE-2026-0603": EpssData(cve_id="CVE-2026-0603")}},
        ),
        (
            "epss_outdated",
            {
                "epss": (
                    ProviderLookupDiagnostics(
                        requested=1,
                        content_hits=1,
                        stale_cache_hits=1,
                        degraded=True,
                    ),
                    [],
                )
            },
        ),
        (
            "kev_unavailable",
            {
                "kev": (
                    ProviderLookupDiagnostics(
                        requested=1,
                        failures=1,
                        empty_records=1,
                        degraded=True,
                    ),
                    [],
                )
            },
        ),
        (
            "snapshot_locked",
            {
                "provider_snapshot": ProviderSnapshotReport(
                    metadata=ProviderSnapshotMetadata(
                        generated_at="2026-04-29T12:00:00+00:00",
                        selected_sources=["nvd", "epss", "kev"],
                    )
                ),
                "locked_provider_data": True,
            },
        ),
        (
            "provider_error",
            {
                "nvd": (
                    ProviderLookupDiagnostics(
                        requested=1,
                        failures=1,
                        empty_records=1,
                        degraded=True,
                    ),
                    [],
                )
            },
        ),
    ],
)
def test_vpw027_provider_data_quality_flags_are_emitted_per_code(
    expected_code: str,
    kwargs: dict[str, object],
) -> None:
    flags_by_source = _provider_data_quality_flags(**kwargs)
    codes = {flag.code for flags in flags_by_source.values() for flag in flags}

    assert expected_code in codes


def test_epss_fetch_many_parses_batch_payload() -> None:
    class Session:
        def __init__(self) -> None:
            self.requests: list[str] = []

        def get(self, *args, **kwargs):  # noqa: ANN002, ANN003
            self.requests.append(kwargs["params"]["cve"])
            return FakeResponse(
                {
                    "data": [
                        {
                            "cve": "CVE-2021-44228",
                            "epss": "0.973",
                            "percentile": "0.999",
                            "date": "2026-04-18",
                        },
                        {
                            "cve": "CVE-2023-1234",
                            "epss": "0.125",
                            "percentile": "0.456",
                            "date": "2026-04-18",
                        },
                    ]
                }
            )

    session = Session()
    provider = EpssProvider(session=session)
    results, warnings = provider.fetch_many(["CVE-2021-44228", "CVE-2023-1234"])

    assert warnings == []
    assert session.requests == ["CVE-2021-44228,CVE-2023-1234"]
    assert results["CVE-2021-44228"].epss == 0.973
    assert results["CVE-2021-44228"].percentile == 0.999
    assert results["CVE-2021-44228"].date == "2026-04-18"
    assert results["CVE-2023-1234"].epss == 0.125
    assert results["CVE-2023-1234"].percentile == 0.456
    assert provider.last_diagnostics.requested == 2
    assert provider.last_diagnostics.network_fetches == 2
    assert provider.last_diagnostics.content_hits == 2
    assert provider.last_diagnostics.empty_records == 0


def test_epss_fetch_many_reports_cache_hit_miss_and_freshness(tmp_path: Path) -> None:
    class Session:
        def __init__(self) -> None:
            self.requests: list[str] = []

        def get(self, *args, **kwargs):  # noqa: ANN002, ANN003
            self.requests.append(kwargs["params"]["cve"])
            return FakeResponse(
                {
                    "data": [
                        {
                            "cve": "CVE-2026-0002",
                            "epss": "0.420",
                            "percentile": "0.910",
                            "date": "2026-04-29",
                        }
                    ]
                }
            )

    cache = FileCache(tmp_path / "cache", ttl_hours=24)
    cache.set_json(
        "epss",
        "CVE-2026-0001",
        EpssData(
            cve_id="CVE-2026-0001",
            epss=0.3,
            percentile=0.8,
            date="2026-04-28",
        ).model_dump(),
    )
    session = Session()
    provider = EpssProvider(session=session, cache=cache)

    results, warnings = provider.fetch_many(["CVE-2026-0001", "CVE-2026-0002"])

    assert warnings == []
    assert session.requests == ["CVE-2026-0002"]
    assert results["CVE-2026-0001"].date == "2026-04-28"
    assert results["CVE-2026-0002"].epss == 0.42
    assert results["CVE-2026-0002"].date == "2026-04-29"
    assert cache.latest_cached_at("epss") is not None
    assert provider.last_diagnostics.cache_hits == 1
    assert provider.last_diagnostics.network_fetches == 1
    assert provider.last_diagnostics.content_hits == 2
    assert provider.last_diagnostics.empty_records == 0
    assert provider.last_diagnostics.degraded is False


def test_epss_fetch_many_records_missing_results(tmp_path: Path) -> None:
    class Session:
        def get(self, *args, **kwargs):  # noqa: ANN002, ANN003
            return FakeResponse({"data": []})

    cache = FileCache(tmp_path / "cache", ttl_hours=24)
    provider = EpssProvider(session=Session(), cache=cache)

    results, warnings = provider.fetch_many(["CVE-2026-0003"])

    assert warnings == []
    assert results["CVE-2026-0003"] == EpssData(cve_id="CVE-2026-0003")
    assert cache.get_json("epss", "CVE-2026-0003") == EpssData(cve_id="CVE-2026-0003").model_dump()
    assert provider.last_diagnostics.network_fetches == 1
    assert provider.last_diagnostics.content_hits == 0
    assert provider.last_diagnostics.empty_records == 1
    assert provider.last_diagnostics.degraded is False


def test_epss_fetch_many_degrades_without_stale_cache() -> None:
    class Session:
        def get(self, *args, **kwargs):  # noqa: ANN002, ANN003
            raise requests.RequestException("epss offline")

    provider = EpssProvider(session=Session())

    results, warnings = provider.fetch_many(["CVE-2026-0004"])

    assert results["CVE-2026-0004"] == EpssData(cve_id="CVE-2026-0004")
    assert warnings == ["EPSS lookup failed for chunk CVE-2026-0004: epss offline"]
    assert provider.last_diagnostics.network_fetches == 1
    assert provider.last_diagnostics.failures == 1
    assert provider.last_diagnostics.content_hits == 0
    assert provider.last_diagnostics.empty_records == 1
    assert provider.last_diagnostics.degraded is True


def test_epss_uses_stale_cache_on_chunk_failure(tmp_path: Path) -> None:
    class Session:
        def get(self, *args, **kwargs):  # noqa: ANN002, ANN003
            raise requests.RequestException("epss offline")

    cache = FileCache(tmp_path / "cache", ttl_hours=1)
    cache_path = cache._path_for("epss", "CVE-2021-44228")
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(
        json.dumps(
            {
                "key": "CVE-2021-44228",
                "cached_at": "2000-01-01T00:00:00+00:00",
                "payload": EpssData(
                    cve_id="CVE-2021-44228",
                    epss=0.973,
                    percentile=0.999,
                    date="2026-04-18",
                ).model_dump(),
            }
        ),
        encoding="utf-8",
    )

    provider = EpssProvider(session=Session(), cache=cache)
    results, warnings = provider.fetch_many(["CVE-2021-44228"])

    assert results["CVE-2021-44228"].epss == 0.973
    assert any("using expired cached data" in warning for warning in warnings)
    assert provider.last_diagnostics.stale_cache_hits == 1
    assert provider.last_diagnostics.failures == 1
    assert provider.last_diagnostics.degraded is True


def test_kev_fetch_many_from_offline_json(tmp_path: Path) -> None:
    kev_file = tmp_path / "kev.json"
    kev_file.write_text(
        json.dumps(
            {
                "vulnerabilities": [
                    {
                        "cveID": "CVE-2021-44228",
                        "vendorProject": "Apache",
                        "product": "Log4j",
                        "vulnerabilityName": "Apache Log4j2 remote code execution vulnerability",
                        "shortDescription": "Apache Log4j2 remote code execution.",
                        "dateAdded": "2021-12-10",
                        "requiredAction": "Patch now",
                        "dueDate": "2021-12-24",
                        "knownRansomwareCampaignUse": "Known",
                        "notes": "Frequently exploited in the wild.",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    provider = KevProvider()
    results, warnings = provider.fetch_many(
        ["CVE-2021-44228", "CVE-2024-3094"],
        offline_file=kev_file,
    )

    assert warnings == []
    assert results["CVE-2021-44228"].in_kev is True
    assert (
        results["CVE-2021-44228"].vulnerability_name
        == "Apache Log4j2 remote code execution vulnerability"
    )
    assert results["CVE-2021-44228"].short_description == "Apache Log4j2 remote code execution."
    assert results["CVE-2021-44228"].known_ransomware_campaign_use == "Known"
    assert results["CVE-2021-44228"].notes == "Frequently exploited in the wild."
    assert results["CVE-2024-3094"].in_kev is False


def test_kev_fetch_many_from_offline_csv_normalizes_aliases_and_skips_invalid_rows(
    tmp_path: Path,
) -> None:
    kev_file = tmp_path / "kev.csv"
    valid_row = (
        "CVE-2026-0001,Example Vendor,Example Product,CSV vulnerability,"
        + "CSV KEV entry,2026-04-29,2026-05-20,Patch CSV asset"
    )
    invalid_row = (
        "not-a-cve,Ignored Vendor,Ignored Product,Invalid row,"
        + "Invalid row,2026-04-29,2026-05-20,Ignore"
    )
    kev_file.write_text(
        "\n".join(
            [
                "cveId,vendorProject,product,vulnerability_name,shortDescription,dateAdded,dueDate,requiredAction",
                valid_row,
                invalid_row,
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    provider = KevProvider()
    results, warnings = provider.fetch_many(
        ["CVE-2026-0001", "CVE-2026-0002"],
        offline_file=kev_file,
    )

    assert warnings == []
    assert results["CVE-2026-0001"].in_kev is True
    assert results["CVE-2026-0001"].vendor_project == "Example Vendor"
    assert results["CVE-2026-0001"].vulnerability_name == "CSV vulnerability"
    assert results["CVE-2026-0001"].short_description == "CSV KEV entry"
    assert results["CVE-2026-0001"].date_added == "2026-04-29"
    assert results["CVE-2026-0001"].due_date == "2026-05-20"
    assert results["CVE-2026-0001"].required_action == "Patch CSV asset"
    assert results["CVE-2026-0002"].in_kev is False


def test_kev_provider_loads_checked_in_offline_fixtures() -> None:
    provider = KevProvider()
    json_results, json_warnings = provider.fetch_many(
        ["CVE-2026-1001"],
        offline_file=DATA_ROOT / "input_fixtures" / "kev_catalog.json",
    )
    csv_results, csv_warnings = provider.fetch_many(
        ["CVE-2026-1001"],
        offline_file=DATA_ROOT / "input_fixtures" / "kev_catalog.csv",
    )

    assert json_warnings == []
    assert csv_warnings == []
    assert json_results["CVE-2026-1001"].in_kev is True
    assert csv_results["CVE-2026-1001"].in_kev is True
    assert (
        json_results["CVE-2026-1001"].vulnerability_name
        == "Example Product command injection vulnerability"
    )
    assert csv_results["CVE-2026-1001"].required_action == (
        "Apply the vendor update or remove affected systems."
    )


def test_kev_refresh_stores_offline_catalog_and_reuses_cache(tmp_path: Path) -> None:
    class NoNetworkSession:
        def get(self, *args, **kwargs):  # noqa: ANN002, ANN003
            raise AssertionError("cache hit should not call KEV network")

    kev_file = tmp_path / "kev.json"
    kev_file.write_text(
        json.dumps(
            {
                "vulnerabilities": [
                    {
                        "cveID": "CVE-2026-0003",
                        "vendorProject": "Cached Vendor",
                        "product": "Cached Product",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    cache = FileCache(tmp_path / "cache", ttl_hours=24)

    provider = KevProvider(cache=cache)
    refreshed_results, refreshed_warnings = provider.fetch_many(
        ["CVE-2026-0003"],
        offline_file=kev_file,
        refresh=True,
    )
    cached_provider = KevProvider(session=NoNetworkSession(), cache=cache)
    cached_results, cached_warnings = cached_provider.fetch_many(["CVE-2026-0003"])

    assert refreshed_warnings == []
    assert refreshed_results["CVE-2026-0003"].in_kev is True
    assert cached_warnings == []
    assert cached_results["CVE-2026-0003"].product == "Cached Product"
    assert cached_provider.last_diagnostics.cache_hits == 1
    assert cached_provider.last_diagnostics.network_fetches == 0


def test_kev_live_catalog_stores_cache_with_namespace_checksum(tmp_path: Path) -> None:
    class Session:
        def get(self, url: str, **kwargs):  # noqa: ARG002, ANN003
            return FakeResponse(
                {
                    "vulnerabilities": [
                        {
                            "cveID": "CVE-2026-1002",
                            "vendorProject": "Live Vendor",
                            "product": "Live Product",
                            "vulnerabilityName": "Live Product KEV vulnerability",
                            "dateAdded": "2026-04-29",
                            "dueDate": "2026-05-20",
                            "requiredAction": "Apply live update.",
                        }
                    ]
                }
            )

    cache = FileCache(tmp_path / "cache", ttl_hours=24)
    provider = KevProvider(session=Session(), cache=cache)

    results, warnings = provider.fetch_many(["CVE-2026-1002"])

    assert warnings == []
    assert results["CVE-2026-1002"].vulnerability_name == "Live Product KEV vulnerability"
    status = cache.inspect_namespace("kev")
    assert status["file_count"] == 1
    assert status["valid_count"] == 1
    assert isinstance(status["namespace_checksum"], str)
    assert len(status["namespace_checksum"]) == 64
    cached_catalog = cache.get_json("kev", "catalog")
    assert cached_catalog["CVE-2026-1002"]["vulnerability_name"] == (
        "Live Product KEV vulnerability"
    )


def test_kev_fetch_many_degrades_for_missing_offline_file(tmp_path: Path) -> None:
    provider = KevProvider()

    results, warnings = provider.fetch_many(
        ["CVE-2026-0004"],
        offline_file=tmp_path / "missing.json",
    )

    assert results["CVE-2026-0004"].in_kev is False
    assert any("Offline KEV file not found" in warning for warning in warnings)
    assert provider.last_diagnostics.failures == 1
    assert provider.last_diagnostics.empty_records == 1
    assert provider.last_diagnostics.degraded is True


def test_kev_fetch_many_degrades_for_unsupported_offline_file(tmp_path: Path) -> None:
    kev_file = tmp_path / "kev.txt"
    kev_file.write_text("CVE-2026-0004\n", encoding="utf-8")
    provider = KevProvider()

    results, warnings = provider.fetch_many(
        ["CVE-2026-0004"],
        offline_file=kev_file,
    )

    assert results["CVE-2026-0004"].in_kev is False
    assert any("Offline KEV file must be .json or .csv" in warning for warning in warnings)
    assert provider.last_diagnostics.failures == 1
    assert provider.last_diagnostics.empty_records == 1
    assert provider.last_diagnostics.degraded is True


def test_kev_fetch_many_uses_expired_cache_when_live_catalog_fails(tmp_path: Path) -> None:
    class FailingSession:
        def get(self, *args, **kwargs):  # noqa: ANN002, ANN003
            raise requests.RequestException("KEV feed unavailable")

    cache = FileCache(tmp_path / "cache", ttl_hours=1)
    cache_path = cache._path_for("kev", "catalog")
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(
        json.dumps(
            {
                "key": "catalog",
                "cached_at": "2000-01-01T00:00:00+00:00",
                "payload": {
                    "CVE-2026-0005": KevData(
                        cve_id="CVE-2026-0005",
                        in_kev=True,
                        vendor_project="Stale Vendor",
                    ).model_dump()
                },
            }
        ),
        encoding="utf-8",
    )

    provider = KevProvider(session=FailingSession(), cache=cache)
    results, warnings = provider.fetch_many(["CVE-2026-0005", "CVE-2026-0006"])

    assert results["CVE-2026-0005"].in_kev is True
    assert results["CVE-2026-0005"].vendor_project == "Stale Vendor"
    assert results["CVE-2026-0006"].in_kev is False
    assert any("using expired cached catalog" in warning for warning in warnings)
    assert provider.last_diagnostics.failures == 1
    assert provider.last_diagnostics.stale_cache_hits == 2
    assert provider.last_diagnostics.degraded is True


def test_kev_uses_mirror_when_primary_feed_fails() -> None:
    class Session:
        def get(self, url: str, **kwargs):  # noqa: ANN003
            if url == KEV_FEED_URL:
                raise requests.RequestException("primary feed unavailable")
            return FakeResponse(
                {
                    "vulnerabilities": [
                        {
                            "cveID": "CVE-2023-44487",
                            "vendorProject": "IETF",
                            "product": "HTTP/2",
                        }
                    ]
                }
            )

    provider = KevProvider(session=Session())
    results, warnings = provider.fetch_many(["CVE-2023-44487"])

    assert warnings == []
    assert results["CVE-2023-44487"].in_kev is True


def test_attack_provider_accepts_alias_columns_and_reports_invalid_rows(tmp_path: Path) -> None:
    attack_file = tmp_path / "attack.csv"
    attack_file.write_text(
        "\n".join(
            [
                "cve,techniques,tactics,note",
                "CVE-2021-44228,T1190|T1190,Initial Access,Demo note",
                "bad-value,T1499,Impact,Ignored row",
                "CVE-2021-44228,T1059,Execution,Override row",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    provider = AttackProvider()
    results, metadata, warnings = provider.fetch_many(
        ["CVE-2021-44228"],
        enabled=True,
        offline_file=attack_file,
    )

    assert metadata["source"] == "local-csv"
    assert results["CVE-2021-44228"].mapped is True
    assert results["CVE-2021-44228"].attack_techniques == ["T1059"]
    assert results["CVE-2021-44228"].attack_tactics == ["Execution"]
    assert results["CVE-2021-44228"].attack_note == "Override row"
    assert any("basic local CSV mapping format" in warning for warning in warnings)
    assert any("invalid CVE identifier" in warning for warning in warnings)
    assert any("overrides duplicate row" in warning for warning in warnings)


def test_attack_provider_source_inference_and_empty_mapping_edges(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    provider = AttackProvider()

    results, metadata, warnings = provider.fetch_many(
        ["CVE-2024-0001"],
        enabled=True,
        source="none",
    )
    assert results == {}
    assert metadata["source"] == "none"
    assert warnings == []

    results, metadata, warnings = provider.fetch_many(
        ["CVE-2024-0001"],
        enabled=True,
        source="local-csv",
    )
    assert results == {}
    assert metadata["source"] == "local-csv"
    assert warnings == ["ATT&CK mode requested, but no ATT&CK mapping file was provided."]

    monkeypatch.setattr(
        provider,
        "_load_ctid_json",
        lambda _cve_ids, *, mapping_file, technique_metadata_file: (
            {"CVE-2024-0001": AttackData(cve_id="CVE-2024-0001", mapped=True)},
            {"source": "ctid-json", "mapping_file": str(mapping_file)},
            [str(technique_metadata_file)],
        ),
    )
    inferred_json, inferred_json_metadata, inferred_json_warnings = provider.fetch_many(
        ["CVE-2024-0001"],
        enabled=True,
        source="none",
        mapping_file=tmp_path / "mapping.json",
    )
    assert inferred_json["CVE-2024-0001"].mapped is True
    assert inferred_json_metadata["source"] == "ctid-json"
    assert inferred_json_warnings == ["None"]

    monkeypatch.setattr(
        provider,
        "_load_local_curated",
        lambda _cve_ids, *, mapping_file: (
            {"CVE-2024-0001": AttackData(cve_id="CVE-2024-0001", mapped=True)},
            {"source": "local-curated", "mapping_file": str(mapping_file)},
            [],
        ),
    )
    inferred_yaml, inferred_yaml_metadata, _ = provider.fetch_many(
        ["CVE-2024-0001"],
        enabled=True,
        source="none",
        mapping_file=tmp_path / "mapping.yaml",
    )
    assert inferred_yaml["CVE-2024-0001"].mapped is True
    assert inferred_yaml_metadata["source"] == "local-curated"

    monkeypatch.setattr(
        provider,
        "_load_local_csv",
        lambda _cve_ids, _mapping_file: (
            {"CVE-2024-0001": AttackData(cve_id="CVE-2024-0001", mapped=True)},
            [],
        ),
    )
    provider.enrichment_service = SimpleNamespace(
        enrich_local_csv=lambda _cve_ids, *, attack_data: attack_data
    )
    inferred_csv, inferred_csv_metadata, inferred_csv_warnings = provider.fetch_many(
        ["CVE-2024-0001"],
        enabled=True,
        source="none",
        mapping_file=tmp_path / "mapping.csv",
        technique_metadata_file=tmp_path / "metadata.json",
    )
    assert inferred_csv["CVE-2024-0001"].mapped is True
    assert inferred_csv_metadata["source"] == "local-csv"
    assert any("basic local CSV mapping format" in warning for warning in inferred_csv_warnings)
    assert any("metadata is ignored" in warning for warning in inferred_csv_warnings)

    unsupported, unsupported_metadata, unsupported_warnings = provider.fetch_many(
        ["CVE-2024-0001"],
        enabled=True,
        source="unsupported",
        mapping_file=tmp_path / "mapping.txt",
    )
    assert unsupported == {}
    assert unsupported_metadata["source"] == "unsupported"
    assert unsupported_warnings == ["Unsupported ATT&CK source: unsupported"]


def test_ctid_provider_loads_official_subset_fixture() -> None:
    provider = CtidMappingsProvider()

    results, metadata, warnings = provider.load(
        DATA_ROOT / "attack" / "ctid_kev_enterprise_2025-07-28_attack-16.1_subset.json"
    )

    assert warnings == []
    assert metadata["mapping_framework"] == "kev"
    assert metadata["mapping_framework_version"] == "07/28/2025"
    assert metadata["attack_version"] == "16.1"
    assert metadata["domain"] == "enterprise"
    assert len(results["CVE-2023-34362"]) == 7
    assert results["CVE-2023-34362"][0].mapping_type == "exploitation_technique"
    assert results["CVE-2023-34362"][0].source == "ctid-mappings-explorer"
    assert results["CVE-2023-34362"][0].confidence == "high"
    assert results["CVE-2023-34362"][0].review_status == "reviewed"
    assert results["CVE-2023-34362"][0].defensive_note

    quality_report = provider.build_quality_report(results, metadata)
    assert quality_report["mapping_count"] == 27
    assert quality_report["unique_cves"] == 3
    assert quality_report["unique_techniques"] == 22
    assert quality_report["source_counts"] == {"ctid-mappings-explorer": 27}
    assert quality_report["confidence_counts"] == {"high": 27}
    assert quality_report["review_status_counts"] == {"reviewed": 27}
    assert quality_report["mapping_type_counts"] == {
        "exploitation_technique": 4,
        "primary_impact": 5,
        "secondary_impact": 18,
    }
    assert quality_report["conflict_count"] == 2
    assert quality_report["conflicts"][0]["cve_id"] == "CVE-2020-1472"

    local_bundle = CuratedAttackMappingProvider().load(DATA_ROOT / "cve_attack_mappings.yml")
    comparison_report = provider.build_quality_report(
        results,
        metadata,
        comparison_mappings_by_cve=local_bundle.mappings_by_cve,
        comparison_source=local_bundle.metadata["metadata_source"],
        comparison_file=local_bundle.metadata["mapping_file"],
        comparison_file_sha256=local_bundle.metadata["mapping_file_sha256"],
    )
    assert comparison_report["comparison_source"] == "local-curated"
    assert comparison_report["local_ctid_conflict_count"] == 1
    assert comparison_report["local_ctid_conflicts"][0] == {
        "cve_id": "CVE-2023-34362",
        "shared_techniques": ["T1190"],
        "ctid_only_techniques": ["T1005", "T1059", "T1082", "T1105", "T1136", "T1531"],
        "local_only_techniques": [],
        "ctid_mapping_types": [
            "exploitation_technique",
            "primary_impact",
            "secondary_impact",
        ],
        "local_mapping_types": ["exploitation"],
    }


def test_ctid_provider_rejects_missing_file_extension_and_required_sections(
    tmp_path: Path,
) -> None:
    provider = CtidMappingsProvider()

    with pytest.raises(FileNotFoundError, match="mapping file not found"):
        provider.load(tmp_path / "missing.json")

    csv_file = tmp_path / "mapping.csv"
    csv_file.write_text("cve,techniques\n", encoding="utf-8")
    with pytest.raises(ValueError, match="must be a JSON file"):
        provider.load(csv_file)

    missing_metadata = tmp_path / "missing-metadata.json"
    missing_metadata.write_text(json.dumps({"mapping_objects": []}), encoding="utf-8")
    with pytest.raises(ValueError, match="missing a metadata object"):
        provider.load(missing_metadata)

    missing_mapping_objects = tmp_path / "missing-mapping-objects.json"
    missing_mapping_objects.write_text(json.dumps({"metadata": {}}), encoding="utf-8")
    with pytest.raises(ValueError, match="missing a mapping_objects array"):
        provider.load(missing_mapping_objects)


def test_ctid_provider_warns_for_malformed_unknown_and_duplicate_mappings(
    tmp_path: Path,
) -> None:
    mapping_file = tmp_path / "ctid.json"
    mapping_file.write_text(
        json.dumps(
            {
                "metadata": {
                    "mapping_framework": "kev",
                    "mapping_framework_version": "07/28/2025",
                    "mapping_version": "1",
                    "attack_version": "16.1",
                    "technology_domain": " enterprise ",
                    "mapping_types": {"primary_impact": {}},
                },
                "mapping_objects": [
                    "not an object",
                    {"capability_id": "not-a-cve", "attack_object_id": "T1190"},
                    {"capability_id": "CVE-2024-0001"},
                    {
                        "capability_id": "CVE-2024-0001",
                        "attack_object_id": "T1190",
                        "attack_object_name": "Exploit Public-Facing Application",
                        "mapping_type": "unexpected",
                        "capability_group": " initial-access ",
                        "references": [None, " https://example.test/a ", "https://example.test/a"],
                    },
                    {
                        "capability_id": "CVE-2024-0001",
                        "attack_object_id": "T1190",
                        "mapping_type": "unexpected",
                        "capability_group": "initial-access",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )

    results, metadata, warnings = CtidMappingsProvider().load(mapping_file)

    assert metadata["domain"] == "enterprise"
    assert len(results["CVE-2024-0001"]) == 1
    mapping = results["CVE-2024-0001"][0]
    assert mapping.mapping_type == "unexpected"
    assert mapping.references == ["https://example.test/a"]
    assert any("not a JSON object" in warning for warning in warnings)
    assert any("invalid capability_id" in warning for warning in warnings)
    assert any("without attack_object_id" in warning for warning in warnings)
    assert any("Unknown CTID mapping_type" in warning for warning in warnings)
    assert any("Ignored duplicate CTID mapping" in warning for warning in warnings)


def test_attack_metadata_provider_loads_subset_fixture() -> None:
    provider = AttackMetadataProvider()

    results, metadata, warnings = provider.load(
        DATA_ROOT / "attack" / "attack_techniques_enterprise_16.1_subset.json"
    )

    assert warnings == []
    assert metadata["attack_version"] == "16.1"
    assert metadata["domain"] == "enterprise"
    assert results["T1059"].name == "Command and Scripting Interpreter"
    assert results["T1059"].tactics == ["execution"]
    assert metadata["metadata_format"] == "vuln-prioritizer-technique-json"
    assert len(metadata["metadata_file_sha256"] or "") == 64


def test_attack_metadata_provider_loads_stix_bundle_fixture() -> None:
    fixture = DATA_ROOT / "attack" / "attack_stix_enterprise_16.1_subset.json"
    provider = AttackMetadataProvider()

    results, metadata, warnings = provider.load(fixture)

    assert warnings == []
    assert metadata["metadata_source"] == "mitre-attack-stix"
    assert metadata["metadata_format"] == "stix-bundle"
    assert metadata["metadata_file_sha256"] == hashlib.sha256(fixture.read_bytes()).hexdigest()
    assert metadata["attack_version"] == "16.1"
    assert metadata["domain"] == "enterprise"
    assert metadata["stix_spec_version"] == "2.1"
    assert results["T1190"].name == "Exploit Public-Facing Application"
    assert results["T1190"].tactics == ["initial-access"]
    assert results["T9999"].revoked is True
    assert results["T9999"].deprecated is True


def test_attack_metadata_provider_rejects_missing_or_wrong_extension(tmp_path: Path) -> None:
    provider = AttackMetadataProvider()

    with pytest.raises(FileNotFoundError, match="metadata file not found"):
        provider.load(tmp_path / "missing.json")

    yaml_file = tmp_path / "metadata.yaml"
    yaml_file.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="must be a JSON file"):
        provider.load(yaml_file)


def test_attack_metadata_provider_rejects_missing_techniques_array(tmp_path: Path) -> None:
    metadata_file = tmp_path / "metadata.json"
    metadata_file.write_text(json.dumps({"techniques": {}}), encoding="utf-8")

    provider = AttackMetadataProvider()

    with pytest.raises(ValueError, match="missing a techniques array"):
        provider.load(metadata_file)


def test_attack_metadata_provider_warns_for_malformed_and_duplicate_entries(
    tmp_path: Path,
) -> None:
    metadata_file = tmp_path / "metadata.json"
    metadata_file.write_text(
        json.dumps(
            {
                "attack_version": " 16.1 ",
                "domain": " enterprise ",
                "techniques": [
                    "not an object",
                    {"attack_object_id": "T0001"},
                    {
                        "attack_object_id": " T1059 ",
                        "name": "Original",
                        "tactics": "execution",
                    },
                    {
                        "attack_object_id": "T1059",
                        "name": "Duplicate",
                        "tactics": [None, " execution ", "execution", ""],
                        "url": " https://attack.mitre.org/techniques/T1059/ ",
                        "revoked": True,
                        "deprecated": True,
                    },
                ],
            }
        ),
        encoding="utf-8",
    )

    provider = AttackMetadataProvider()
    results, metadata, warnings = provider.load(metadata_file)

    assert metadata["attack_version"] == "16.1"
    assert metadata["domain"] == "enterprise"
    assert results["T1059"].name == "Duplicate"
    assert results["T1059"].tactics == ["execution"]
    assert results["T1059"].url == "https://attack.mitre.org/techniques/T1059/"
    assert results["T1059"].revoked is True
    assert results["T1059"].deprecated is True
    assert any("not a JSON object" in warning for warning in warnings)
    assert any("without attack_object_id or name" in warning for warning in warnings)
    assert any("overrides duplicate T1059" in warning for warning in warnings)


def test_attack_stix_provider_loads_versioned_snapshot_catalog() -> None:
    fixture = DATA_ROOT / "attack" / "attack_stix_enterprise_16.1_subset.json"
    payload = json.loads(fixture.read_text(encoding="utf-8"))

    snapshot = AttackStixProvider().load_snapshot_payload(
        payload,
        source_path=fixture,
        raw_content=fixture.read_bytes(),
    )

    assert snapshot.warnings == []
    assert snapshot.metadata["attack_version"] == "16.1"
    assert snapshot.metadata["domain"] == "enterprise"
    assert snapshot.metadata["stix_spec_version"] == "2.1"
    assert snapshot.object_counts == {
        "attack-pattern": 3,
        "course-of-action": 2,
        "relationship": 1,
        "x-mitre-collection": 1,
        "x-mitre-tactic": 2,
    }
    assert snapshot.tactics["TA0001"].short_name == "initial-access"
    assert snapshot.techniques["T1190"].tactic_ids == ["TA0001"]
    assert snapshot.techniques["T1190"].tactic_short_names == ["initial-access"]
    assert snapshot.techniques["T9999"].revoked is True
    assert snapshot.techniques["T9999"].deprecated is True
    assert snapshot.mitigations["M1051"].name == "Update Software"
    assert snapshot.mitigations["T9998"].name == "Deprecated Legacy Mitigation"
    assert snapshot.mitigations["T9998"].deprecated is True
    assert snapshot.mitigation_relationships[0].mitigation_id == "M1051"
    assert snapshot.mitigation_relationships[0].technique_id == "T1190"


def test_attack_stix_provider_rejects_non_bundle_and_missing_objects(tmp_path: Path) -> None:
    provider = AttackStixProvider()

    with pytest.raises(ValueError, match="must be a STIX bundle"):
        provider.load_snapshot_payload(
            {"type": "attack-pattern"},
            source_path=tmp_path / "attack.json",
            raw_content=b"{}",
        )

    with pytest.raises(ValueError, match="missing an objects array"):
        provider.load_snapshot_payload(
            {"type": "bundle"},
            source_path=tmp_path / "attack.json",
            raw_content=b"{}",
        )


def test_attack_stix_provider_warns_for_malformed_duplicates_and_unknown_relationships(
    tmp_path: Path,
) -> None:
    payload = {
        "type": "bundle",
        "spec_version": "2.1",
        "objects": [
            "not an object",
            {"id": "identity--missing-type"},
            {
                "type": "x-mitre-collection",
                "id": "x-mitre-collection--1",
                "x_mitre_attack_version": "16.1",
            },
            {
                "type": "x-mitre-tactic",
                "id": "x-mitre-tactic--missing",
                "external_references": [{"source_name": "mitre-attack", "external_id": "TA0001"}],
            },
            {
                "type": "x-mitre-tactic",
                "id": "x-mitre-tactic--execution",
                "name": "Execution",
                "x_mitre_shortname": "execution",
                "x_mitre_domains": ["enterprise-attack", "enterprise-attack"],
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": "TA0002",
                        "url": "https://attack.mitre.org/tactics/TA0002/",
                    }
                ],
            },
            {
                "type": "x-mitre-tactic",
                "id": "x-mitre-tactic--execution-duplicate",
                "name": "Execution duplicate",
                "x_mitre_shortname": "execution",
                "external_references": [{"source_name": "mitre-attack", "external_id": "TA0002"}],
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--missing",
                "external_references": [{"source_name": "mitre-attack", "external_id": "T9999"}],
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--command",
                "name": "Command and Scripting Interpreter",
                "kill_chain_phases": [
                    "invalid",
                    {"kill_chain_name": "not-attack", "phase_name": "ignored"},
                    {"kill_chain_name": "mitre-attack", "phase_name": "execution"},
                    {"kill_chain_name": "mitre-attack", "phase_name": "execution"},
                ],
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": "T1059",
                        "url": "https://attack.mitre.org/techniques/T1059/",
                    }
                ],
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--command-duplicate",
                "name": "Command duplicate",
                "external_references": [{"source_name": "mitre-attack", "external_id": "T1059"}],
            },
            {
                "type": "course-of-action",
                "id": "course-of-action--missing",
                "external_references": [{"source_name": "mitre-attack", "external_id": "M0001"}],
            },
            {
                "type": "course-of-action",
                "id": "course-of-action--mitigation",
                "name": "Update Software",
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": "M1051",
                        "url": "https://attack.mitre.org/mitigations/M1051/",
                    }
                ],
            },
            {
                "type": "course-of-action",
                "id": "course-of-action--mitigation-duplicate",
                "name": "Update Software duplicate",
                "external_references": [{"source_name": "mitre-attack", "external_id": "M1051"}],
            },
            {
                "type": "relationship",
                "id": "relationship--ignored",
                "relationship_type": "uses",
            },
            {
                "type": "relationship",
                "id": "relationship--unknown",
                "relationship_type": "mitigates",
                "source_ref": "course-of-action--missing-source",
                "target_ref": "attack-pattern--missing-target",
            },
            {
                "type": "relationship",
                "id": "relationship--known",
                "relationship_type": "mitigates",
                "source_ref": "course-of-action--mitigation",
                "target_ref": "attack-pattern--command",
                "description": "Apply vendor patches.",
            },
        ],
    }
    raw_content = json.dumps(payload).encode("utf-8")

    snapshot = AttackStixProvider().load_snapshot_payload(
        payload,
        source_path=tmp_path / "attack.json",
        raw_content=raw_content,
    )

    assert snapshot.metadata["attack_version"] == "16.1"
    assert snapshot.metadata["domain"] == "enterprise"
    assert snapshot.metadata["stix_spec_version"] == "2.1"
    assert snapshot.tactics["TA0002"].name == "Execution duplicate"
    assert snapshot.techniques["T1059"].name == "Command duplicate"
    assert snapshot.techniques["T1059"].tactic_short_names == []
    assert snapshot.mitigations["M1051"].name == "Update Software duplicate"
    assert snapshot.mitigation_relationships[0].mitigation_id == "M1051"
    assert snapshot.mitigation_relationships[0].technique_id == "T1059"
    assert any("not a JSON object" in warning for warning in snapshot.warnings)
    assert any("has no type" in warning for warning in snapshot.warnings)
    assert any(
        "tactic without ATT&CK external ID or name" in warning for warning in snapshot.warnings
    )
    assert any("overrides duplicate tactic TA0002" in warning for warning in snapshot.warnings)
    assert any(
        "attack-pattern without ATT&CK external ID or name" in warning
        for warning in snapshot.warnings
    )
    assert any("overrides duplicate T1059" in warning for warning in snapshot.warnings)
    assert any(
        "mitigation without MITRE ATT&CK external ID or name" in warning
        for warning in snapshot.warnings
    )
    assert any("overrides duplicate mitigation M1051" in warning for warning in snapshot.warnings)
    assert any("without known source mitigation" in warning for warning in snapshot.warnings)


def test_attack_provider_ctid_json_enriches_structured_attack_data() -> None:
    provider = AttackProvider()

    results, metadata, warnings = provider.fetch_many(
        ["CVE-2023-34362", "CVE-2024-3094"],
        enabled=True,
        source="ctid-json",
        mapping_file=DATA_ROOT
        / "attack"
        / "ctid_kev_enterprise_2025-07-28_attack-16.1_subset.json",
        technique_metadata_file=DATA_ROOT
        / "attack"
        / "attack_techniques_enterprise_16.1_subset.json",
    )

    assert warnings == []
    assert metadata["source"] == "ctid-mappings-explorer"
    assert metadata["attack_version"] == "16.1"
    assert len(metadata["mapping_file_sha256"] or "") == 64
    assert len(metadata["technique_metadata_file_sha256"] or "") == 64
    assert metadata["metadata_format"] == "vuln-prioritizer-technique-json"
    assert metadata["mapping_created_at"] == "07/28/2025"
    assert metadata["mapping_updated_at"] == "08/28/2025"
    assert results["CVE-2023-34362"].mapped is True
    assert results["CVE-2023-34362"].attack_relevance == "High"
    assert results["CVE-2023-34362"].mappings[0].source == "ctid-mappings-explorer"
    assert results["CVE-2023-34362"].mappings[0].confidence == "high"
    assert results["CVE-2023-34362"].mappings[0].review_status == "reviewed"
    assert results["CVE-2023-34362"].mapping_types == [
        "exploitation_technique",
        "primary_impact",
        "secondary_impact",
    ]
    assert results["CVE-2023-34362"].techniques[0].name == "Exploit Public-Facing Application"
    assert results["CVE-2024-3094"].mapped is False
    assert results["CVE-2024-3094"].attack_relevance == "Unmapped"


def test_curated_attack_mapping_provider_loads_yaml_fixture() -> None:
    provider = CuratedAttackMappingProvider()

    bundle = provider.load(DATA_ROOT / "cve_attack_mappings.yml")

    assert bundle.quality_report["mapping_count"] == 6
    assert bundle.quality_report["unique_cves"] == 6
    assert bundle.quality_report["confidence_counts"] == {"high": 3, "low": 1, "medium": 2}
    assert bundle.quality_report["low_confidence_count"] == 1
    assert bundle.mappings_by_cve["CVE-2021-44228"][0].attack_object_id == "T1190"
    assert bundle.mappings_by_cve["CVE-2021-44228"][0].confidence == "high"
    assert bundle.mappings_by_cve["CVE-2021-44228"][0].review_status == "reviewed"
    assert bundle.mappings_by_cve["CVE-2021-44228"][0].source == "local-curated"
    low_confidence = bundle.mappings_by_cve["CVE-2021-26855"][0]
    assert low_confidence.confidence == "low"
    assert low_confidence.review_status == "needs_review"
    assert bundle.techniques_by_id["T1195.002"].tactics == ["initial-access"]
    assert any("Low-confidence curated" in warning for warning in bundle.warnings)


def test_curated_attack_mapping_provider_rejects_missing_suffix_and_top_level_shape(
    tmp_path: Path,
) -> None:
    provider = CuratedAttackMappingProvider()

    with pytest.raises(FileNotFoundError, match="mapping file not found"):
        provider.load(tmp_path / "missing.yml")

    txt_file = tmp_path / "mapping.txt"
    txt_file.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="must be JSON, YAML, or YML"):
        provider.load(txt_file)

    top_level_array = tmp_path / "mapping.yml"
    top_level_array.write_text("- not\n- an object\n", encoding="utf-8")
    with pytest.raises(ValueError, match="top-level object"):
        provider.load(top_level_array)

    missing_metadata = tmp_path / "missing-metadata.yml"
    missing_metadata.write_text("mapping_objects: []\n", encoding="utf-8")
    with pytest.raises(ValueError, match="missing a metadata object"):
        provider.load(missing_metadata)

    missing_mapping_objects = tmp_path / "missing-mapping-objects.yml"
    missing_mapping_objects.write_text("metadata: {}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="missing a mapping_objects array"):
        provider.load(missing_mapping_objects)

    empty_mapping_objects = tmp_path / "empty-mapping-objects.yml"
    empty_mapping_objects.write_text("metadata: {}\nmapping_objects: []\n", encoding="utf-8")
    with pytest.raises(ValueError, match="mapping_objects array must not be empty"):
        provider.load(empty_mapping_objects)

    invalid_yaml = tmp_path / "invalid.yml"
    invalid_yaml.write_text("metadata: [broken\n", encoding="utf-8")
    with pytest.raises(ValueError, match="YAML is not valid YAML"):
        provider.load(invalid_yaml)


def test_curated_attack_mapping_provider_reports_non_object_and_duplicate_mappings(
    tmp_path: Path,
) -> None:
    mapping_file = tmp_path / "curated.yml"
    mapping_file.write_text(
        """
metadata:
  mapping_framework: vuln-prioritizer-curated-attack
  mapping_framework_version: "1.0"
  attack_version: "16.1"
  technology_domain: enterprise-attack
  mapping_types:
    exploitation: reviewed defensive context
mapping_objects:
  - not an object
  - cve_id: CVE-2024-0001
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    tactic_ids: [TA0001, TA0001, TA0043]
    mapping_type: exploitation
    source: reviewed source
    confidence: medium
    rationale: defensive rationale
    review_status: needs_review
    defensive_note: defensive note only
    references: [null, " https://example.test/a ", "https://example.test/a"]
  - capability_id: CVE-2024-0001
    attack_object_id: T1190
    attack_object_name: Exploit Public-Facing Application duplicate
    mapping_type: exploitation
    source: reviewed source
    confidence: medium
    rationale: defensive rationale
    review_status: needs_review
    defensive_note: defensive note only
""",
        encoding="utf-8",
    )

    with pytest.raises(CuratedAttackMappingValidationError) as exc_info:
        CuratedAttackMappingProvider().load(mapping_file)

    message = str(exc_info.value)
    assert "mapping_objects[0] must be an object" in message
    assert "duplicates CVE-2024-0001 / T1190 / exploitation" in message


def test_curated_attack_mapping_provider_rejects_missing_reviewer_for_reviewed(
    tmp_path: Path,
) -> None:
    mapping_file = tmp_path / "curated.yml"
    mapping_file.write_text(
        """
metadata:
  mapping_framework: vuln-prioritizer-curated-attack
  mapping_framework_version: "1.0"
  attack_version: "16.1"
  technology_domain: enterprise-attack
  mapping_types:
    exploitation: reviewed defensive context
mapping_objects:
  - cve_id: CVE-2024-0001
    technique_id: T1190
    mapping_type: exploitation
    source: reviewed source
    confidence: high
    rationale: defensive rationale
    review_status: reviewed
    defensive_note: defensive note only
""",
        encoding="utf-8",
    )

    with pytest.raises(CuratedAttackMappingValidationError, match="reviewer is required"):
        CuratedAttackMappingProvider().load(mapping_file)


def test_curated_attack_mapping_provider_rejects_numeric_confidence(tmp_path: Path) -> None:
    mapping_file = tmp_path / "curated.yml"
    mapping_file.write_text(
        """
metadata:
  mapping_framework: vuln-prioritizer-curated-attack
  mapping_framework_version: "1.0"
  attack_version: "16.1"
  technology_domain: enterprise-attack
  mapping_types:
    exploitation: reviewed defensive context
mapping_objects:
  - cve_id: CVE-2024-0001
    technique_id: T1190
    mapping_type: exploitation
    source: reviewed source
    confidence: 0.9
    rationale: defensive rationale
    review_status: reviewed
    reviewer: security-review
    reviewed_at: "2026-04-29"
    defensive_note: defensive note only
""",
        encoding="utf-8",
    )

    with pytest.raises(CuratedAttackMappingValidationError, match="confidence must be one"):
        CuratedAttackMappingProvider().load(mapping_file)


def test_curated_attack_mapping_provider_rejects_invalid_cve_and_attack_ids(
    tmp_path: Path,
) -> None:
    mapping_file = tmp_path / "curated.yml"
    mapping_file.write_text(
        """
metadata:
  mapping_framework: vuln-prioritizer-curated-attack
  mapping_framework_version: "1.0"
  attack_version: "16.1"
  technology_domain: enterprise-attack
  mapping_types:
    exploitation: reviewed defensive context
mapping_objects:
  - cve_id: NOT-A-CVE
    technique_id: T1190
    mapping_type: exploitation
    source: reviewed source
    confidence: medium
    rationale: defensive rationale
    review_status: needs_review
    defensive_note: defensive note only
  - cve_id: CVE-2024-0001
    technique_id: TA0001
    mapping_type: exploitation
    source: reviewed source
    confidence: medium
    rationale: defensive rationale
    review_status: needs_review
    defensive_note: defensive note only
""",
        encoding="utf-8",
    )

    with pytest.raises(CuratedAttackMappingValidationError) as exc_info:
        CuratedAttackMappingProvider().load(mapping_file)

    message = str(exc_info.value)
    assert "cve_id must be a valid CVE identifier" in message
    assert "ATT&CK technique IDs must match" in message


def test_attack_provider_local_curated_enriches_structured_attack_data() -> None:
    provider = AttackProvider()

    results, metadata, warnings = provider.fetch_many(
        ["CVE-2023-34362", "CVE-2024-3094", "CVE-2024-9999"],
        enabled=True,
        source="local-curated",
        mapping_file=DATA_ROOT / "cve_attack_mappings.yml",
    )

    assert metadata["source"] == "local-curated"
    assert metadata["metadata_format"] == "vuln-prioritizer-curated-yml"
    assert len(metadata["mapping_file_sha256"] or "") == 64
    assert any("Low-confidence curated" in warning for warning in warnings)
    assert results["CVE-2023-34362"].mapped is True
    assert results["CVE-2023-34362"].attack_relevance == "High"
    assert results["CVE-2023-34362"].attack_techniques == ["T1190"]
    assert results["CVE-2024-3094"].attack_techniques == ["T1195.002"]
    assert results["CVE-2024-9999"].mapped is False


def test_ctid_provider_rejects_invalid_json(tmp_path: Path) -> None:
    mapping_file = tmp_path / "invalid.json"
    mapping_file.write_text("{broken", encoding="utf-8")

    provider = CtidMappingsProvider()

    try:
        provider.load(mapping_file)
    except ValueError as exc:
        assert "CTID ATT&CK mapping JSON is not valid JSON" in str(exc)
        assert "Expecting property name enclosed in double quotes" in str(exc)
    else:
        raise AssertionError("Expected ValueError for invalid CTID JSON")


def test_attack_metadata_provider_rejects_invalid_json(tmp_path: Path) -> None:
    metadata_file = tmp_path / "invalid.json"
    metadata_file.write_text("{broken", encoding="utf-8")

    provider = AttackMetadataProvider()

    try:
        provider.load(metadata_file)
    except ValueError as exc:
        assert "ATT&CK technique metadata JSON is not valid JSON" in str(exc)
        assert "Expecting property name enclosed in double quotes" in str(exc)
    else:
        raise AssertionError("Expected ValueError for invalid ATT&CK metadata JSON")


def test_attack_provider_ctid_json_marks_missing_metadata_in_output(tmp_path: Path) -> None:
    mapping_file = tmp_path / "mapping.json"
    metadata_file = tmp_path / "metadata.json"
    mapping_file.write_text(
        json.dumps(
            {
                "metadata": {
                    "technology_domain": "enterprise",
                    "attack_version": "16.1",
                    "mapping_framework": "kev",
                    "mapping_framework_version": "07/28/2025",
                    "mapping_types": {
                        "primary_impact": {},
                    },
                },
                "mapping_objects": [
                    {
                        "capability_id": "CVE-2024-0001",
                        "attack_object_id": "T1190",
                        "attack_object_name": "Exploit Public-Facing Application",
                        "mapping_type": "primary_impact",
                        "comments": "Demo mapping comment",
                    },
                    {
                        "capability_id": "CVE-2024-0001",
                        "attack_object_id": "T1059",
                        "attack_object_name": "Command and Scripting Interpreter",
                        "mapping_type": "primary_impact",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    metadata_file.write_text(
        json.dumps(
            {
                "attack_version": "16.1",
                "domain": "enterprise",
                "techniques": [
                    {
                        "attack_object_id": "T1190",
                        "name": "Exploit Public-Facing Application",
                        "tactics": ["initial-access"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    provider = AttackProvider()

    results, _, warnings = provider.fetch_many(
        ["CVE-2024-0001"],
        enabled=True,
        source="ctid-json",
        mapping_file=mapping_file,
        technique_metadata_file=metadata_file,
    )

    attack = results["CVE-2024-0001"]
    assert warnings == []
    assert attack.attack_note is not None
    assert "Local ATT&CK technique metadata is unavailable for: T1059." in attack.attack_note
    assert attack.attack_rationale is not None
    assert "Local ATT&CK technique metadata is unavailable for: T1059." in attack.attack_rationale

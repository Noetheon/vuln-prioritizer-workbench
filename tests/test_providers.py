from __future__ import annotations

import json
from pathlib import Path

import requests

from vuln_prioritizer.cache import FileCache
from vuln_prioritizer.providers.attack import AttackProvider
from vuln_prioritizer.providers.attack_metadata import AttackMetadataProvider
from vuln_prioritizer.providers.ctid_mappings import CtidMappingsProvider
from vuln_prioritizer.providers.epss import EpssProvider
from vuln_prioritizer.providers.kev import KevProvider
from vuln_prioritizer.providers.nvd import NvdProvider


class FakeResponse:
    def __init__(self, json_data: dict | None = None, status_code: int = 200) -> None:
        self._json_data = json_data or {}
        self.status_code = status_code

    def json(self) -> dict:
        return self._json_data

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            error = requests.HTTPError(f"{self.status_code} error")
            error.response = self
            raise error


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
                    "weaknesses": [
                        {"description": [{"lang": "en", "value": "CWE-79"}]},
                    ],
                    "references": [{"url": "https://example.com/advisory"}],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {"baseScore": 8.0, "baseSeverity": "HIGH"},
                            }
                        ],
                        "cvssMetricV40": [
                            {
                                "cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"},
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
    assert parsed.cwes == ["CWE-79"]
    assert parsed.references == ["https://example.com/advisory"]


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


def test_epss_fetch_many_parses_batch_payload() -> None:
    class Session:
        def get(self, *args, **kwargs):  # noqa: ANN002, ANN003
            return FakeResponse(
                {
                    "data": [
                        {
                            "cve": "CVE-2021-44228",
                            "epss": "0.973",
                            "percentile": "0.999",
                            "date": "2026-04-18",
                        }
                    ]
                }
            )

    provider = EpssProvider(session=Session())
    results, warnings = provider.fetch_many(["CVE-2021-44228"])

    assert warnings == []
    assert results["CVE-2021-44228"].epss == 0.973
    assert results["CVE-2021-44228"].percentile == 0.999


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
                        "dateAdded": "2021-12-10",
                        "requiredAction": "Patch now",
                        "dueDate": "2021-12-24",
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
    assert results["CVE-2024-3094"].in_kev is False


def test_kev_uses_mirror_when_primary_feed_fails() -> None:
    class Session:
        def get(self, url: str, **kwargs):  # noqa: ANN003
            if "cisa.gov" in url:
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
    assert any("legacy compatibility mode" in warning for warning in warnings)
    assert any("invalid CVE identifier" in warning for warning in warnings)
    assert any("overrides duplicate row" in warning for warning in warnings)


def test_ctid_provider_loads_official_subset_fixture() -> None:
    provider = CtidMappingsProvider()

    results, metadata, warnings = provider.load(
        Path("data/attack/ctid_kev_enterprise_2025-07-28_attack-16.1_subset.json")
    )

    assert warnings == []
    assert metadata["mapping_framework"] == "kev"
    assert metadata["mapping_framework_version"] == "07/28/2025"
    assert metadata["attack_version"] == "16.1"
    assert metadata["domain"] == "enterprise"
    assert len(results["CVE-2023-34362"]) == 7
    assert results["CVE-2023-34362"][0].mapping_type == "exploitation_technique"


def test_attack_metadata_provider_loads_subset_fixture() -> None:
    provider = AttackMetadataProvider()

    results, metadata, warnings = provider.load(
        Path("data/attack/attack_techniques_enterprise_16.1_subset.json")
    )

    assert warnings == []
    assert metadata["attack_version"] == "16.1"
    assert metadata["domain"] == "enterprise"
    assert results["T1059"].name == "Command and Scripting Interpreter"
    assert results["T1059"].tactics == ["execution"]


def test_attack_provider_ctid_json_enriches_structured_attack_data() -> None:
    provider = AttackProvider()

    results, metadata, warnings = provider.fetch_many(
        ["CVE-2023-34362", "CVE-2024-3094"],
        enabled=True,
        source="ctid-json",
        mapping_file=Path("data/attack/ctid_kev_enterprise_2025-07-28_attack-16.1_subset.json"),
        technique_metadata_file=Path("data/attack/attack_techniques_enterprise_16.1_subset.json"),
    )

    assert warnings == []
    assert metadata["source"] == "ctid-mappings-explorer"
    assert metadata["attack_version"] == "16.1"
    assert results["CVE-2023-34362"].mapped is True
    assert results["CVE-2023-34362"].attack_relevance == "High"
    assert results["CVE-2023-34362"].mapping_types == [
        "exploitation_technique",
        "primary_impact",
        "secondary_impact",
    ]
    assert results["CVE-2023-34362"].techniques[0].name == "Exploit Public-Facing Application"
    assert results["CVE-2024-3094"].mapped is False
    assert results["CVE-2024-3094"].attack_relevance == "Unmapped"


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

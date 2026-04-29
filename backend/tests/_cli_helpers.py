from __future__ import annotations

from pathlib import Path
from typing import Any

from typer.testing import CliRunner

from vuln_prioritizer.models import AttackData, EpssData, KevData, NvdData
from vuln_prioritizer.providers.attack import AttackProvider
from vuln_prioritizer.providers.epss import EpssProvider
from vuln_prioritizer.providers.kev import KevProvider
from vuln_prioritizer.providers.nvd import NvdProvider

runner: CliRunner = CliRunner()


def write_input_file(tmp_path: Path) -> Path:
    input_file = tmp_path / "cves.txt"
    input_file.write_text(
        "\n".join(
            [
                "CVE-2021-44228",
                "CVE-2023-44487",
                "CVE-2024-3094",
                "CVE-2024-0004",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    return input_file


def install_fake_providers(monkeypatch: Any) -> None:
    def fake_nvd_fetch_many(
        self: Any,
        cve_ids: list[str],
    ) -> tuple[dict[str, NvdData], list[str]]:
        catalog = {
            "CVE-2021-44228": NvdData(
                cve_id="CVE-2021-44228",
                description="Log4Shell",
                cvss_base_score=10.0,
                cvss_severity="CRITICAL",
            ),
            "CVE-2023-44487": NvdData(
                cve_id="CVE-2023-44487",
                description="HTTP/2 Rapid Reset",
                cvss_base_score=7.5,
                cvss_severity="HIGH",
            ),
            "CVE-2024-3094": NvdData(
                cve_id="CVE-2024-3094",
                description="XZ Utils backdoor",
                cvss_base_score=5.0,
                cvss_severity="MEDIUM",
            ),
            "CVE-2023-34362": NvdData(
                cve_id="CVE-2023-34362",
                description="MOVEit Transfer SQL injection",
                cvss_base_score=9.8,
                cvss_severity="CRITICAL",
            ),
            "CVE-2024-4577": NvdData(
                cve_id="CVE-2024-4577",
                description="PHP-CGI argument injection",
                cvss_base_score=9.8,
                cvss_severity="CRITICAL",
            ),
            "CVE-2024-0004": NvdData(
                cve_id="CVE-2024-0004",
                description="Synthetic medium case",
                cvss_base_score=8.0,
                cvss_severity="HIGH",
            ),
        }
        return (
            {cve_id: catalog[cve_id] for cve_id in cve_ids if cve_id in catalog},
            [],
        )

    def fake_epss_fetch_many(
        self: Any,
        cve_ids: list[str],
    ) -> tuple[dict[str, EpssData], list[str]]:
        catalog = {
            "CVE-2021-44228": EpssData(
                cve_id="CVE-2021-44228",
                epss=0.97,
                percentile=0.999,
            ),
            "CVE-2023-44487": EpssData(
                cve_id="CVE-2023-44487",
                epss=0.42,
                percentile=0.91,
            ),
            "CVE-2024-3094": EpssData(
                cve_id="CVE-2024-3094",
                epss=0.45,
                percentile=0.88,
            ),
            "CVE-2023-34362": EpssData(
                cve_id="CVE-2023-34362",
                epss=0.98,
                percentile=0.999,
            ),
            "CVE-2024-4577": EpssData(
                cve_id="CVE-2024-4577",
                epss=0.83,
                percentile=0.994,
            ),
            "CVE-2024-0004": EpssData(
                cve_id="CVE-2024-0004",
                epss=0.30,
                percentile=0.66,
            ),
        }
        return (
            {cve_id: catalog[cve_id] for cve_id in cve_ids if cve_id in catalog},
            [],
        )

    def fake_kev_fetch_many(
        self: Any,
        cve_ids: list[str],
        offline_file: Path | None = None,
    ) -> tuple[dict[str, KevData], list[str]]:
        catalog = {
            "CVE-2021-44228": KevData(cve_id="CVE-2021-44228", in_kev=True),
            "CVE-2023-44487": KevData(cve_id="CVE-2023-44487", in_kev=False),
            "CVE-2024-3094": KevData(cve_id="CVE-2024-3094", in_kev=False),
            "CVE-2023-34362": KevData(cve_id="CVE-2023-34362", in_kev=True),
            "CVE-2024-4577": KevData(cve_id="CVE-2024-4577", in_kev=False),
            "CVE-2024-0004": KevData(cve_id="CVE-2024-0004", in_kev=False),
        }
        return (
            {cve_id: catalog[cve_id] for cve_id in cve_ids if cve_id in catalog},
            [],
        )

    def fake_attack_fetch_many(
        self: Any,
        cve_ids: list[str],
        *,
        enabled: bool,
        source: str = "none",
        mapping_file: Path | None = None,
        technique_metadata_file: Path | None = None,
        offline_file: Path | None = None,
    ) -> tuple[dict[str, AttackData], dict[str, Any], list[str]]:
        return (
            {
                "CVE-2021-44228": AttackData(
                    cve_id="CVE-2021-44228",
                    mapped=enabled,
                    source="local-csv" if enabled else source,
                    attack_relevance="Medium" if enabled else "Unmapped",
                    attack_rationale=(
                        "Legacy local ATT&CK CSV context is available for this CVE."
                        if enabled
                        else "No ATT&CK context was provided for this CVE."
                    ),
                    attack_techniques=["T1190"],
                    attack_tactics=["Initial Access"],
                    attack_note="Representative demo mapping note.",
                )
            }
            if enabled
            else {},
            {
                "source": "local-csv" if enabled else "none",
                "mapping_file": (
                    str(mapping_file or offline_file) if (mapping_file or offline_file) else None
                ),
                "technique_metadata_file": (
                    str(technique_metadata_file) if technique_metadata_file is not None else None
                ),
                "source_version": None,
                "attack_version": None,
                "domain": None,
                "mapping_framework": None,
                "mapping_framework_version": None,
            },
            [],
        )

    monkeypatch.setattr(NvdProvider, "fetch_many", fake_nvd_fetch_many)
    monkeypatch.setattr(EpssProvider, "fetch_many", fake_epss_fetch_many)
    monkeypatch.setattr(KevProvider, "fetch_many", fake_kev_fetch_many)
    monkeypatch.setattr(AttackProvider, "fetch_many", fake_attack_fetch_many)

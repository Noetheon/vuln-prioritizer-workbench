from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from typer.testing import CliRunner

from vuln_prioritizer.cache import FileCache
from vuln_prioritizer.cli import app
from vuln_prioritizer.models import EpssData, KevData, NvdData
from vuln_prioritizer.providers.epss import EpssProvider
from vuln_prioritizer.providers.kev import KevProvider
from vuln_prioritizer.providers.nvd import NvdProvider

runner = CliRunner()
ATTACK_ROOT = Path(__file__).resolve().parents[1] / "data" / "attack"


def _install_fake_data_update_providers(monkeypatch: Any) -> None:
    def fake_nvd_fetch_many(
        self: NvdProvider,
        cve_ids: list[str],
        *,
        refresh: bool = False,
    ) -> tuple[dict[str, NvdData], list[str]]:
        assert refresh is True
        results = {
            cve_id: NvdData(
                cve_id=cve_id,
                description=f"{cve_id} description",
                cvss_base_score=8.0,
                cvss_severity="HIGH",
                cvss_version="3.1",
            )
            for cve_id in cve_ids
        }
        assert self.cache is not None
        for item in results.values():
            self.cache.set_json("nvd", item.cve_id, item.model_dump())
        return results, []

    def fake_epss_fetch_many(
        self: EpssProvider,
        cve_ids: list[str],
        *,
        refresh: bool = False,
    ) -> tuple[dict[str, EpssData], list[str]]:
        assert refresh is True
        results = {
            cve_id: EpssData(cve_id=cve_id, epss=0.42, percentile=0.91, date="2026-04-20")
            for cve_id in cve_ids
        }
        assert self.cache is not None
        for item in results.values():
            self.cache.set_json("epss", item.cve_id, item.model_dump())
        return results, []

    def fake_kev_fetch_many(
        self: KevProvider,
        cve_ids: list[str],
        offline_file: Path | None = None,
        *,
        refresh: bool = False,
    ) -> tuple[dict[str, KevData], list[str]]:
        assert refresh is True
        results = {
            cve_id: KevData(cve_id=cve_id, in_kev=(cve_id == "CVE-2021-44228"))
            for cve_id in cve_ids
        }
        catalog = {cve_id: item.model_dump() for cve_id, item in results.items()}
        assert self.cache is not None
        self.cache.set_json("kev", "catalog", catalog)
        return results, []

    monkeypatch.setattr(NvdProvider, "fetch_many", fake_nvd_fetch_many)
    monkeypatch.setattr(EpssProvider, "fetch_many", fake_epss_fetch_many)
    monkeypatch.setattr(KevProvider, "fetch_many", fake_kev_fetch_many)


def test_data_update_refreshes_requested_sources(monkeypatch, tmp_path: Path) -> None:
    _install_fake_data_update_providers(monkeypatch)

    cache_dir = tmp_path / "cache"
    input_file = tmp_path / "cves.txt"
    input_file.write_text("CVE-2021-44228\nCVE-2024-3094\n", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "data",
            "update",
            "--source",
            "nvd",
            "--source",
            "epss",
            "--source",
            "kev",
            "--input",
            str(input_file),
            "--cache-dir",
            str(cache_dir),
        ],
    )

    assert result.exit_code == 0
    assert "Updated Sources" in result.stdout
    assert "Requested CVEs: 2" in result.stdout

    cache = FileCache(cache_dir, ttl_hours=24)
    assert cache.get_json("nvd", "CVE-2021-44228") is not None
    assert cache.get_json("epss", "CVE-2024-3094") is not None
    assert cache.get_json("kev", "catalog") is not None


def test_data_update_json_quiet_writes_only_file(monkeypatch, tmp_path: Path) -> None:
    _install_fake_data_update_providers(monkeypatch)

    cache_dir = tmp_path / "cache"
    input_file = tmp_path / "cves.txt"
    output_file = tmp_path / "data-update.json"
    input_file.write_text("CVE-2021-44228\nCVE-2024-3094\n", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "data",
            "update",
            "--source",
            "nvd",
            "--source",
            "kev",
            "--input",
            str(input_file),
            "--cache-dir",
            str(cache_dir),
            "--output",
            str(output_file),
            "--format",
            "json",
            "--quiet",
        ],
    )

    assert result.exit_code == 0
    assert result.stdout == ""
    payload = json.loads(output_file.read_text(encoding="utf-8"))
    assert payload["metadata"]["command"] == "data update"
    assert payload["summary"]["selected_sources"] == ["nvd", "kev"]
    assert payload["requested_cve_ids"] == ["CVE-2021-44228", "CVE-2024-3094"]
    assert [item["source"] for item in payload["sources"]] == ["nvd", "kev"]


def test_data_update_json_output_file_does_not_echo_json_payload(
    monkeypatch,
    tmp_path: Path,
) -> None:
    _install_fake_data_update_providers(monkeypatch)

    cache_dir = tmp_path / "cache"
    input_file = tmp_path / "cves.txt"
    output_file = tmp_path / "data-update.json"
    input_file.write_text("CVE-2021-44228\n", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "data",
            "update",
            "--source",
            "nvd",
            "--input",
            str(input_file),
            "--cache-dir",
            str(cache_dir),
            "--output",
            str(output_file),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0
    assert output_file.exists()
    assert result.stdout == ""


def test_data_update_accepts_multiple_inputs(monkeypatch, tmp_path: Path) -> None:
    _install_fake_data_update_providers(monkeypatch)

    cache_dir = tmp_path / "cache"
    first_input = tmp_path / "cves-a.txt"
    second_input = tmp_path / "cves-b.txt"
    output_file = tmp_path / "data-update.json"
    first_input.write_text("CVE-2021-44228\n", encoding="utf-8")
    second_input.write_text("CVE-2024-3094\nCVE-2021-44228\n", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "data",
            "update",
            "--source",
            "nvd",
            "--input",
            str(first_input),
            "--input",
            str(second_input),
            "--output",
            str(output_file),
            "--cache-dir",
            str(cache_dir),
            "--format",
            "json",
            "--quiet",
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(output_file.read_text(encoding="utf-8"))
    assert payload["metadata"]["input_path"] == str(first_input)
    assert payload["metadata"]["input_paths"] == [str(first_input), str(second_input)]
    assert payload["metadata"]["merged_input_count"] == 2
    assert payload["requested_cve_ids"] == ["CVE-2021-44228", "CVE-2024-3094"]


def test_data_update_rejects_nvd_or_epss_without_cves(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "data",
            "update",
            "--source",
            "nvd",
            "--cache-dir",
            str(tmp_path / "cache"),
        ],
    )

    assert result.exit_code == 2
    assert "requires --input or at least" in result.stdout
    assert "--cve" in result.stdout


def test_data_verify_reports_cache_coverage_and_local_file_checksums(tmp_path: Path) -> None:
    cache = FileCache(tmp_path / "cache", ttl_hours=24)
    cache.set_json(
        "nvd",
        "CVE-2021-44228",
        NvdData(
            cve_id="CVE-2021-44228",
            description="Log4Shell",
            cvss_base_score=10.0,
            cvss_severity="CRITICAL",
            cvss_version="3.1",
        ).model_dump(),
    )
    cache.set_json(
        "epss",
        "CVE-2021-44228",
        EpssData(
            cve_id="CVE-2021-44228",
            epss=0.97,
            percentile=0.99,
            date="2026-04-20",
        ).model_dump(),
    )
    cache.set_json(
        "kev",
        "catalog",
        {
            "CVE-2021-44228": KevData(
                cve_id="CVE-2021-44228",
                in_kev=True,
                vendor_project="Apache",
                product="Log4j",
            ).model_dump()
        },
    )

    result = runner.invoke(
        app,
        [
            "data",
            "verify",
            "--cache-dir",
            str(tmp_path / "cache"),
            "--cve",
            "CVE-2021-44228",
            "--cve",
            "CVE-2024-3094",
            "--attack-mapping-file",
            str(ATTACK_ROOT / "ctid_kev_enterprise_2025-07-28_attack-16.1_subset.json"),
            "--attack-technique-metadata-file",
            str(ATTACK_ROOT / "attack_techniques_enterprise_16.1_subset.json"),
        ],
    )

    assert result.exit_code == 0
    assert "Cache Namespaces" in result.stdout
    assert "Cache Coverage" in result.stdout
    assert "1/2" in result.stdout
    assert "Pinned Local Files" in result.stdout
    assert "ATT&CK Verification" in result.stdout


def test_data_verify_json_stdout_is_raw_json(tmp_path: Path) -> None:
    cache = FileCache(tmp_path / "cache", ttl_hours=24)
    cache.set_json(
        "nvd",
        "CVE-2021-44228",
        NvdData(
            cve_id="CVE-2021-44228",
            description="Log4Shell",
            cvss_base_score=10.0,
            cvss_severity="CRITICAL",
            cvss_version="3.1",
        ).model_dump(),
    )
    cache.set_json(
        "epss",
        "CVE-2021-44228",
        EpssData(
            cve_id="CVE-2021-44228",
            epss=0.97,
            percentile=0.99,
            date="2026-04-20",
        ).model_dump(),
    )
    cache.set_json(
        "kev",
        "catalog",
        {
            "CVE-2021-44228": KevData(
                cve_id="CVE-2021-44228",
                in_kev=True,
                vendor_project="Apache",
                product="Log4j",
            ).model_dump()
        },
    )

    result = runner.invoke(
        app,
        [
            "data",
            "verify",
            "--cache-dir",
            str(tmp_path / "cache"),
            "--cve",
            "CVE-2021-44228",
            "--cve",
            "CVE-2024-3094",
            "--attack-mapping-file",
            str(ATTACK_ROOT / "ctid_kev_enterprise_2025-07-28_attack-16.1_subset.json"),
            "--attack-technique-metadata-file",
            str(ATTACK_ROOT / "attack_techniques_enterprise_16.1_subset.json"),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["metadata"]["command"] == "data verify"
    assert payload["summary"]["requested_cves"] == 2
    assert payload["coverage"][0]["coverage"] == "1/2"


def test_data_verify_accepts_multiple_inputs(tmp_path: Path) -> None:
    cache = FileCache(tmp_path / "cache", ttl_hours=24)
    cache.set_json(
        "nvd",
        "CVE-2021-44228",
        NvdData(
            cve_id="CVE-2021-44228",
            description="Log4Shell",
            cvss_base_score=10.0,
            cvss_severity="CRITICAL",
            cvss_version="3.1",
        ).model_dump(),
    )

    first_input = tmp_path / "cves-a.txt"
    second_input = tmp_path / "cves-b.txt"
    output_file = tmp_path / "data-verify.json"
    first_input.write_text("CVE-2021-44228\n", encoding="utf-8")
    second_input.write_text("CVE-2024-3094\n", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "data",
            "verify",
            "--cache-dir",
            str(tmp_path / "cache"),
            "--input",
            str(first_input),
            "--input",
            str(second_input),
            "--output",
            str(output_file),
            "--format",
            "json",
            "--quiet",
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(output_file.read_text(encoding="utf-8"))
    assert payload["metadata"]["input_path"] == str(first_input)
    assert payload["metadata"]["input_paths"] == [str(first_input), str(second_input)]
    assert payload["metadata"]["merged_input_count"] == 2
    assert payload["requested_cve_ids"] == ["CVE-2021-44228", "CVE-2024-3094"]
    assert "Cache Namespaces" not in result.stdout


def test_data_export_provider_snapshot_writes_replay_artifact(monkeypatch, tmp_path: Path) -> None:
    _install_fake_data_update_providers(monkeypatch)

    cache_dir = tmp_path / "cache"
    input_file = tmp_path / "cves.txt"
    output_file = tmp_path / "provider-snapshot.json"
    input_file.write_text("CVE-2021-44228\nCVE-2024-3094\n", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "data",
            "export-provider-snapshot",
            "--input",
            str(input_file),
            "--output",
            str(output_file),
            "--cache-dir",
            str(cache_dir),
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(output_file.read_text(encoding="utf-8"))
    assert payload["metadata"]["artifact_kind"] == "provider-snapshot"
    assert payload["metadata"]["selected_sources"] == ["nvd", "epss", "kev"]
    assert [item["cve_id"] for item in payload["items"]] == ["CVE-2021-44228", "CVE-2024-3094"]
    assert all(item["nvd"] is not None for item in payload["items"])
    assert all(item["epss"] is not None for item in payload["items"])
    assert all(item["kev"] is not None for item in payload["items"])


def test_data_export_provider_snapshot_cache_only_uses_local_cache(
    monkeypatch,
    tmp_path: Path,
) -> None:
    def fail_fetch_many(*args, **kwargs):  # noqa: ANN002, ANN003, ANN202
        raise AssertionError("cache-only export must not call live provider fetch_many")

    monkeypatch.setattr(NvdProvider, "fetch_many", fail_fetch_many)
    monkeypatch.setattr(EpssProvider, "fetch_many", fail_fetch_many)
    monkeypatch.setattr(KevProvider, "fetch_many", fail_fetch_many)

    cache_dir = tmp_path / "cache"
    cache = FileCache(cache_dir, ttl_hours=24)
    input_file = tmp_path / "cves.txt"
    output_file = tmp_path / "provider-snapshot.json"
    input_file.write_text("CVE-2021-44228\nCVE-2024-3094\n", encoding="utf-8")
    cache.set_json(
        "nvd",
        "CVE-2021-44228",
        NvdData(cve_id="CVE-2021-44228", cvss_base_score=10.0).model_dump(),
    )
    cache.set_json(
        "epss",
        "CVE-2021-44228",
        EpssData(cve_id="CVE-2021-44228", epss=0.97, percentile=0.99).model_dump(),
    )
    cache.set_json(
        "kev",
        "catalog",
        {"CVE-2021-44228": KevData(cve_id="CVE-2021-44228", in_kev=True).model_dump()},
    )

    result = runner.invoke(
        app,
        [
            "data",
            "export-provider-snapshot",
            "--input",
            str(input_file),
            "--output",
            str(output_file),
            "--cache-dir",
            str(cache_dir),
            "--cache-only",
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(output_file.read_text(encoding="utf-8"))
    first_item, second_item = payload["items"]
    assert payload["metadata"]["cache_only"] is True
    assert first_item["nvd"] is not None
    assert first_item["epss"] is not None
    assert first_item["kev"]["in_kev"] is True
    assert second_item["nvd"] is None
    assert second_item["epss"] is None
    assert second_item["kev"]["in_kev"] is False
    assert any("cache-only NVD data missing" in warning for warning in payload["warnings"])

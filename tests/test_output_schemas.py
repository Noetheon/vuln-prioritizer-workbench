from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import jsonschema
from typer.testing import CliRunner

TESTS_DIR = Path(__file__).resolve().parent
if str(TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_DIR))

from test_cli import _install_fake_providers, _write_input_file  # noqa: E402

from vuln_prioritizer.cache import FileCache  # noqa: E402
from vuln_prioritizer.cli import app  # noqa: E402
from vuln_prioritizer.models import EpssData, KevData, NvdData  # noqa: E402
from vuln_prioritizer.providers.epss import EpssProvider  # noqa: E402
from vuln_prioritizer.providers.kev import KevProvider  # noqa: E402
from vuln_prioritizer.providers.nvd import NvdProvider  # noqa: E402

runner = CliRunner()
SCHEMA_ROOT = Path(__file__).resolve().parents[1] / "docs" / "schemas"
ATTACK_ROOT = Path(__file__).resolve().parents[1] / "data" / "attack"


def _load_schema(name: str) -> dict:
    return json.loads((SCHEMA_ROOT / name).read_text(encoding="utf-8"))


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
        assert self.cache is not None
        self.cache.set_json(
            "kev",
            "catalog",
            {cve_id: item.model_dump() for cve_id, item in results.items()},
        )
        return results, []

    monkeypatch.setattr(NvdProvider, "fetch_many", fake_nvd_fetch_many)
    monkeypatch.setattr(EpssProvider, "fetch_many", fake_epss_fetch_many)
    monkeypatch.setattr(KevProvider, "fetch_many", fake_kev_fetch_many)


def test_analysis_json_matches_published_schema(monkeypatch, tmp_path: Path) -> None:
    input_file = _write_input_file(tmp_path)
    output_file = tmp_path / "analysis.json"
    _install_fake_providers(monkeypatch)

    result = runner.invoke(
        app,
        [
            "analyze",
            "--input",
            str(input_file),
            "--output",
            str(output_file),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(output_file.read_text(encoding="utf-8"))
    jsonschema.validate(payload, _load_schema("analysis-report.schema.json"))


def test_compare_json_matches_published_schema(monkeypatch, tmp_path: Path) -> None:
    input_file = _write_input_file(tmp_path)
    output_file = tmp_path / "compare.json"
    _install_fake_providers(monkeypatch)

    result = runner.invoke(
        app,
        [
            "compare",
            "--input",
            str(input_file),
            "--output",
            str(output_file),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(output_file.read_text(encoding="utf-8"))
    jsonschema.validate(payload, _load_schema("compare-report.schema.json"))


def test_explain_json_matches_published_schema(monkeypatch, tmp_path: Path) -> None:
    output_file = tmp_path / "explain.json"
    _install_fake_providers(monkeypatch)

    result = runner.invoke(
        app,
        [
            "explain",
            "--cve",
            "CVE-2021-44228",
            "--offline-attack-file",
            str(tmp_path / "attack.csv"),
            "--output",
            str(output_file),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(output_file.read_text(encoding="utf-8"))
    jsonschema.validate(payload, _load_schema("explain-report.schema.json"))


def test_attack_validation_json_matches_published_schema(tmp_path: Path) -> None:
    output_file = tmp_path / "attack-validation.json"

    result = runner.invoke(
        app,
        [
            "attack",
            "validate",
            "--attack-mapping-file",
            str(ATTACK_ROOT / "ctid_kev_enterprise_2025-07-28_attack-16.1_subset.json"),
            "--attack-technique-metadata-file",
            str(ATTACK_ROOT / "attack_techniques_enterprise_16.1_subset.json"),
            "--output",
            str(output_file),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(output_file.read_text(encoding="utf-8"))
    jsonschema.validate(payload, _load_schema("attack-validation-report.schema.json"))


def test_attack_coverage_json_matches_published_schema(tmp_path: Path) -> None:
    output_file = tmp_path / "attack-coverage.json"

    result = runner.invoke(
        app,
        [
            "attack",
            "coverage",
            "--input",
            "data/sample_cves_mixed.txt",
            "--attack-mapping-file",
            str(ATTACK_ROOT / "ctid_kev_enterprise_2025-07-28_attack-16.1_subset.json"),
            "--attack-technique-metadata-file",
            str(ATTACK_ROOT / "attack_techniques_enterprise_16.1_subset.json"),
            "--output",
            str(output_file),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(output_file.read_text(encoding="utf-8"))
    jsonschema.validate(payload, _load_schema("attack-coverage-report.schema.json"))


def test_input_validation_json_matches_published_schema(tmp_path: Path) -> None:
    input_file = tmp_path / "cves.txt"
    output_file = tmp_path / "input-validation.json"
    input_file.write_text("CVE-2021-44228\n", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "input",
            "validate",
            "--input",
            str(input_file),
            "--output",
            str(output_file),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(output_file.read_text(encoding="utf-8"))
    jsonschema.validate(payload, _load_schema("input-validation-report.schema.json"))


def test_data_status_json_matches_published_schema(tmp_path: Path) -> None:
    output_file = tmp_path / "data-status.json"

    result = runner.invoke(
        app,
        [
            "data",
            "status",
            "--cache-dir",
            str(tmp_path / "cache"),
            "--attack-mapping-file",
            str(ATTACK_ROOT / "ctid_kev_enterprise_2025-07-28_attack-16.1_subset.json"),
            "--attack-technique-metadata-file",
            str(ATTACK_ROOT / "attack_techniques_enterprise_16.1_subset.json"),
            "--output",
            str(output_file),
            "--format",
            "json",
            "--quiet",
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(output_file.read_text(encoding="utf-8"))
    jsonschema.validate(payload, _load_schema("data-status-report.schema.json"))


def test_data_update_json_matches_published_schema(monkeypatch, tmp_path: Path) -> None:
    _install_fake_data_update_providers(monkeypatch)
    output_file = tmp_path / "data-update.json"
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
            str(tmp_path / "cache"),
            "--output",
            str(output_file),
            "--format",
            "json",
            "--quiet",
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(output_file.read_text(encoding="utf-8"))
    jsonschema.validate(payload, _load_schema("data-update-report.schema.json"))


def test_data_verify_json_matches_published_schema(tmp_path: Path) -> None:
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
    output_file = tmp_path / "data-verify.json"

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
            "--output",
            str(output_file),
            "--format",
            "json",
            "--quiet",
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(output_file.read_text(encoding="utf-8"))
    jsonschema.validate(payload, _load_schema("data-verify-report.schema.json"))


def test_provider_snapshot_json_matches_published_schema(monkeypatch, tmp_path: Path) -> None:
    _install_fake_data_update_providers(monkeypatch)
    output_file = tmp_path / "provider-snapshot.json"
    input_file = tmp_path / "cves.txt"
    input_file.write_text("CVE-2021-44228\nCVE-2024-3094\n", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "data",
            "export-provider-snapshot",
            "--input",
            str(input_file),
            "--cache-dir",
            str(tmp_path / "cache"),
            "--output",
            str(output_file),
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(output_file.read_text(encoding="utf-8"))
    jsonschema.validate(payload, _load_schema("provider-snapshot-report.schema.json"))

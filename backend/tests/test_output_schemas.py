from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import jsonschema
from _cli_helpers import (
    install_fake_providers as _install_fake_providers,
)
from _cli_helpers import (
    write_input_file as _write_input_file,
)
from paths import DATA_ROOT, DOCS_ROOT, REPO_ROOT
from typer.testing import CliRunner

from vuln_prioritizer.cache import FileCache
from vuln_prioritizer.cli import app
from vuln_prioritizer.models import EpssData, KevData, NvdData, ProviderSnapshotReport
from vuln_prioritizer.providers.epss import EpssProvider
from vuln_prioritizer.providers.kev import KevProvider
from vuln_prioritizer.providers.nvd import NvdProvider

runner = CliRunner()
PROJECT_ROOT = REPO_ROOT
SCHEMA_ROOT = DOCS_ROOT / "schemas"
CONTRACTS_FILE = DOCS_ROOT / "contracts.md"
ATTACK_ROOT = DATA_ROOT / "attack"


def _schema_paths() -> list[Path]:
    return sorted(SCHEMA_ROOT.glob("*.schema.json"))


def _load_schema(name: str) -> dict:
    return json.loads((SCHEMA_ROOT / name).read_text(encoding="utf-8"))


def _documented_schema_names() -> list[str]:
    marker = "Published JSON schemas in `docs/schemas/` cover:"
    document = CONTRACTS_FILE.read_text(encoding="utf-8")
    _, schema_section = document.split(marker, maxsplit=1)
    schema_names: list[str] = []

    for line in schema_section.splitlines():
        stripped = line.strip()
        if not stripped:
            if schema_names:
                break
            continue
        if stripped.startswith("- `") and stripped.endswith("`"):
            schema_names.append(stripped.removeprefix("- `").removesuffix("`"))
            continue
        if schema_names:
            break

    return schema_names


def test_published_schema_documents_are_valid_json_schema() -> None:
    for schema_path in _schema_paths():
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator.check_schema(schema)


def test_contracts_schema_list_matches_schema_directory() -> None:
    documented_names = _documented_schema_names()
    schema_names = [path.name for path in _schema_paths()]

    assert len(documented_names) == len(set(documented_names))
    assert sorted(documented_names) == schema_names


def test_kev_enrichment_response_example_matches_model() -> None:
    payload = json.loads(
        (DOCS_ROOT / "examples" / "example_kev_enrichment_response.json").read_text(
            encoding="utf-8"
        )
    )

    kev = KevData.model_validate(payload)

    assert kev.in_kev is True
    assert kev.vulnerability_name == "Example Product command injection vulnerability"


def test_nvd_provider_record_example_matches_model() -> None:
    payload = json.loads(
        (DOCS_ROOT / "examples" / "example_nvd_provider_record.json").read_text(encoding="utf-8")
    )

    nvd = NvdData.model_validate(payload)

    assert nvd.cve_id == "CVE-2026-2001"
    assert nvd.cvss_version == "4.0"
    assert nvd.cvss_vector.startswith("CVSS:4.0/")
    assert nvd.reference_tags == {
        "https://example.invalid/advisory/CVE-2026-2001": [
            "Vendor Advisory",
            "Patch",
        ]
    }


def test_provider_snapshot_v1_example_matches_schema_and_model() -> None:
    payload = json.loads(
        (DOCS_ROOT / "examples" / "example_provider_snapshot.v1.json").read_text(encoding="utf-8")
    )

    jsonschema.validate(payload, _load_schema("provider-snapshot-report.schema.json"))
    snapshot = ProviderSnapshotReport.model_validate(payload)

    assert snapshot.metadata.snapshot_format == "provider-snapshot.v1.json"
    assert snapshot.metadata.snapshot_id == "example-provider-snapshot-v1"
    assert snapshot.metadata.source_metadata["nvd"]["source"] == "NVD CVE API 2.0"


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
            cve_id: KevData(
                cve_id=cve_id,
                in_kev=(cve_id == "CVE-2021-44228"),
                vulnerability_name=(
                    "Apache Log4j2 remote code execution vulnerability"
                    if cve_id == "CVE-2021-44228"
                    else None
                ),
            )
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
            str(DATA_ROOT / "sample_cves_mixed.txt"),
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


def test_input_inspect_json_matches_published_schema(tmp_path: Path) -> None:
    input_file = tmp_path / "cves.txt"
    output_file = tmp_path / "input-inspect.json"
    input_file.write_text("CVE-2021-44228\n", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "input",
            "inspect",
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
    jsonschema.validate(payload, _load_schema("input-inspect-report.schema.json"))


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
    assert payload["metadata"]["snapshot_format"] == "provider-snapshot.v1.json"
    assert payload["metadata"]["snapshot_id"]
    assert set(payload["metadata"]["source_hashes"]) == {"nvd", "epss", "kev"}
    assert payload["metadata"]["source_metadata"]["nvd"]["record_count"] == 2
    assert payload["items"][0]["kev"]["vulnerability_name"] == (
        "Apache Log4j2 remote code execution vulnerability"
    )

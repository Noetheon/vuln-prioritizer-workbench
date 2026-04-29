from __future__ import annotations

import json
import re
from pathlib import Path

from vuln_prioritizer.cli import app
from vuln_prioritizer.models import (
    EpssData,
    KevData,
    NvdData,
    ProviderSnapshotItem,
    ProviderSnapshotMetadata,
    ProviderSnapshotReport,
)
from vuln_prioritizer.provider_snapshot import generate_provider_snapshot_json
from vuln_prioritizer.providers.epss import EpssProvider
from vuln_prioritizer.providers.kev import KevProvider
from vuln_prioritizer.providers.nvd import NvdProvider


def _write_provider_snapshot(snapshot_file: Path, input_file: Path) -> None:
    snapshot_file.write_text(
        generate_provider_snapshot_json(
            ProviderSnapshotReport(
                metadata=ProviderSnapshotMetadata(
                    generated_at="2026-04-22T12:00:00Z",
                    input_path=str(input_file),
                    input_paths=[str(input_file)],
                    input_format="cve-list",
                    selected_sources=["nvd", "epss", "kev"],
                    requested_cves=2,
                    output_path=str(snapshot_file),
                    cache_enabled=False,
                ),
                items=[
                    ProviderSnapshotItem(
                        cve_id="CVE-2021-44228",
                        nvd=NvdData(
                            cve_id="CVE-2021-44228",
                            description="Log4Shell",
                            cvss_base_score=10.0,
                            cvss_severity="CRITICAL",
                            cvss_version="3.1",
                        ),
                        epss=EpssData(
                            cve_id="CVE-2021-44228",
                            epss=0.97,
                            percentile=0.999,
                            date="2026-04-20",
                        ),
                        kev=KevData(cve_id="CVE-2021-44228", in_kev=True),
                    ),
                    ProviderSnapshotItem(
                        cve_id="CVE-2023-44487",
                        nvd=NvdData(
                            cve_id="CVE-2023-44487",
                            description="HTTP/2 Rapid Reset",
                            cvss_base_score=7.5,
                            cvss_severity="HIGH",
                            cvss_version="3.1",
                        ),
                        epss=EpssData(
                            cve_id="CVE-2023-44487",
                            epss=0.42,
                            percentile=0.91,
                            date="2026-04-20",
                        ),
                        kev=KevData(cve_id="CVE-2023-44487", in_kev=False),
                    ),
                ],
            )
        ),
        encoding="utf-8",
    )


def test_cli_compare_table_mode(
    install_fake_providers,
    runner,
    tmp_path: Path,
    write_input_file,
) -> None:
    input_file = write_input_file(tmp_path)
    install_fake_providers()

    result = runner.invoke(
        app,
        [
            "compare",
            "--input",
            str(input_file),
            "--sort-by",
            "cve",
        ],
    )

    assert result.exit_code == 0
    assert "CVSS-only vs Enriched Prioritization" in result.stdout
    assert "Changed rows:" in result.stdout
    assert "Unchanged rows:" in result.stdout


def test_cli_compare_table_mode_surfaces_under_investigation(
    install_fake_providers,
    runner,
    tmp_path: Path,
) -> None:
    input_file = tmp_path / "cves.txt"
    input_file.write_text("CVE-2021-44228\n", encoding="utf-8")
    vex_file = tmp_path / "vex.json"
    vex_file.write_text(
        json.dumps(
            {
                "statements": [
                    {
                        "vulnerability": {"name": "CVE-2021-44228"},
                        "status": "under_investigation",
                        "products": [{"subcomponents": [{"kind": "generic", "name": "default"}]}],
                    }
                ]
            }
        )
        + "\n",
        encoding="utf-8",
    )
    install_fake_providers()

    result = runner.invoke(
        app,
        [
            "compare",
            "--input",
            str(input_file),
            "--vex-file",
            str(vex_file),
            "--target-kind",
            "generic",
            "--target-ref",
            "default",
            "--sort-by",
            "cve",
        ],
    )

    assert result.exit_code == 0
    assert "Under investigation" in result.stdout


def test_cli_compare_json_export(
    install_fake_providers,
    runner,
    tmp_path: Path,
    write_input_file,
) -> None:
    input_file = write_input_file(tmp_path)
    output_file = tmp_path / "compare.json"
    install_fake_providers()

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
            "--priority",
            "high",
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(output_file.read_text(encoding="utf-8"))

    assert "comparisons" in payload
    assert payload["metadata"]["active_filters"] == ["priority=High"]
    assert any(item["changed"] for item in payload["comparisons"])
    assert payload["attack_summary"]["mapped_cves"] == 0
    assert all("under_investigation" in item for item in payload["comparisons"])


def test_cli_compare_surfaces_waiver_details(
    install_fake_providers,
    runner,
    tmp_path: Path,
    write_input_file,
    write_waiver_file,
) -> None:
    input_file = write_input_file(tmp_path)
    compare_file = tmp_path / "compare.json"
    waiver_file = write_waiver_file(
        tmp_path,
        cve_id="CVE-2021-44228",
        owner="risk-review",
        reason="Approved until the next maintenance window.",
    )
    install_fake_providers()

    result = runner.invoke(
        app,
        [
            "compare",
            "--input",
            str(input_file),
            "--output",
            str(compare_file),
            "--format",
            "json",
            "--waiver-file",
            str(waiver_file),
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(compare_file.read_text(encoding="utf-8"))
    waived_row = next(item for item in payload["comparisons"] if item["cve_id"] == "CVE-2021-44228")
    assert waived_row["waived"] is True
    assert waived_row["waiver_owner"] == "risk-review"


def test_cli_compare_rejects_output_with_table_format(
    runner,
    tmp_path: Path,
    write_input_file,
) -> None:
    input_file = write_input_file(tmp_path)

    result = runner.invoke(
        app,
        [
            "compare",
            "--input",
            str(input_file),
            "--output",
            str(tmp_path / "compare.txt"),
            "--format",
            "table",
        ],
    )

    assert result.exit_code == 2
    assert "--output cannot be used together with --format table." in result.stdout


def test_cli_compare_rejects_sarif_format(
    normalize_output,
    runner,
    tmp_path: Path,
    write_input_file,
) -> None:
    input_file = write_input_file(tmp_path)

    result = runner.invoke(
        app,
        [
            "compare",
            "--input",
            str(input_file),
            "--format",
            "sarif",
        ],
    )

    assert result.exit_code == 2
    normalized = normalize_output(result.output)
    assert "Invalid value for '--format': 'sarif'" in normalized
    assert "'markdown', 'json'" in normalized
    assert "'table'." in normalized


def test_cli_compare_rejects_misaligned_input_format_counts(
    runner,
    tmp_path: Path,
) -> None:
    first_input = tmp_path / "cves-a.txt"
    second_input = tmp_path / "cves-b.txt"
    first_input.write_text("CVE-2021-44228\n", encoding="utf-8")
    second_input.write_text("CVE-2024-3094\n", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "compare",
            "--input",
            str(first_input),
            "--input",
            str(second_input),
            "--input-format",
            "cve-list",
            "--input-format",
            "cve-list",
            "--input-format",
            "cve-list",
        ],
    )

    assert result.exit_code == 2
    normalized = re.sub(r"\s+", " ", result.stdout)
    assert "received 2 --input value(s) but 3 --input-format value(s)" in normalized


def test_cli_compare_supports_locked_provider_snapshot_replay(
    runner,
    tmp_path: Path,
    monkeypatch,
) -> None:
    input_file = tmp_path / "cves.txt"
    output_file = tmp_path / "compare.json"
    snapshot_file = tmp_path / "provider-snapshot.json"
    input_file.write_text("CVE-2021-44228\nCVE-2023-44487\n", encoding="utf-8")
    _write_provider_snapshot(snapshot_file, input_file)

    def _fail_nvd(*args, **kwargs):  # noqa: ANN002, ANN003
        raise AssertionError("live NVD lookup should not run in locked mode")

    def _fail_epss(*args, **kwargs):  # noqa: ANN002, ANN003
        raise AssertionError("live EPSS lookup should not run in locked mode")

    def _fail_kev(*args, **kwargs):  # noqa: ANN002, ANN003
        raise AssertionError("live KEV lookup should not run in locked mode")

    monkeypatch.setattr(NvdProvider, "fetch_many", _fail_nvd)
    monkeypatch.setattr(EpssProvider, "fetch_many", _fail_epss)
    monkeypatch.setattr(KevProvider, "fetch_many", _fail_kev)

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
            "--provider-snapshot-file",
            str(snapshot_file),
            "--locked-provider-data",
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(output_file.read_text(encoding="utf-8"))
    assert payload["metadata"]["provider_snapshot_file"] == str(snapshot_file)
    assert payload["metadata"]["locked_provider_data"] is True
    assert payload["metadata"]["provider_snapshot_sources"] == ["nvd", "epss", "kev"]

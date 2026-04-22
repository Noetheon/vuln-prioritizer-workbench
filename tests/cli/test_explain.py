from __future__ import annotations

import json
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


def _write_provider_snapshot(snapshot_file: Path) -> None:
    snapshot_file.write_text(
        generate_provider_snapshot_json(
            ProviderSnapshotReport(
                metadata=ProviderSnapshotMetadata(
                    generated_at="2026-04-22T12:00:00Z",
                    input_path="inline:CVE-2021-44228",
                    input_paths=[],
                    input_format="cve-list",
                    selected_sources=["nvd", "epss", "kev"],
                    requested_cves=1,
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
                    )
                ],
            )
        ),
        encoding="utf-8",
    )


def test_cli_explain_rejects_sarif_format(normalize_output, runner) -> None:
    result = runner.invoke(
        app,
        [
            "explain",
            "--cve",
            "CVE-2021-44228",
            "--format",
            "sarif",
        ],
    )

    assert result.exit_code == 2
    normalized = normalize_output(result.output)
    assert "Invalid value for '--format': 'sarif'" in normalized
    assert "'markdown', 'json'" in normalized
    assert "'table'." in normalized


def test_cli_explain_end_to_end_with_mocked_providers(
    install_fake_providers,
    runner,
    tmp_path: Path,
) -> None:
    output_file = tmp_path / "explain.json"
    install_fake_providers()

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
    assert "Explanation for CVE-2021-44228" in result.stdout
    assert output_file.exists()
    payload = json.loads(output_file.read_text(encoding="utf-8"))
    assert payload["finding"]["priority_label"] == "Critical"
    assert payload["comparison"]["cvss_only_label"] == "Critical"
    assert payload["attack"]["attack_note"] == "Representative demo mapping note."
    assert payload["metadata"]["attack_source"] == "local-csv"
    assert payload["finding"]["remediation"]["strategy"] in {
        "generic-priority-guidance",
        "review-upgrade-options",
        "upgrade",
    }


def test_cli_explain_surfaces_waiver_details(
    install_fake_providers,
    runner,
    tmp_path: Path,
    write_waiver_file,
) -> None:
    explain_file = tmp_path / "explain.json"
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
            "explain",
            "--cve",
            "CVE-2021-44228",
            "--output",
            str(explain_file),
            "--format",
            "json",
            "--waiver-file",
            str(waiver_file),
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(explain_file.read_text(encoding="utf-8"))
    assert payload["finding"]["waived"] is True
    assert payload["finding"]["waiver_scope"] == "global"
    assert payload["metadata"]["waiver_file"] == str(waiver_file)


def test_cli_explain_supports_locked_provider_snapshot_replay(
    runner,
    tmp_path: Path,
    monkeypatch,
) -> None:
    output_file = tmp_path / "explain.json"
    snapshot_file = tmp_path / "provider-snapshot.json"
    _write_provider_snapshot(snapshot_file)

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
            "explain",
            "--cve",
            "CVE-2021-44228",
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

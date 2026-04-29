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


def test_cli_snapshot_create_emits_snapshot_json(
    install_fake_providers,
    runner,
    tmp_path: Path,
    write_input_file,
) -> None:
    input_file = write_input_file(tmp_path)
    output_file = tmp_path / "snapshot.json"
    install_fake_providers()

    result = runner.invoke(
        app,
        [
            "snapshot",
            "create",
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
    assert payload["metadata"]["schema_version"] == "1.1.0"
    assert payload["metadata"]["snapshot_kind"] == "snapshot"
    assert len(payload["findings"]) == 4


def test_cli_snapshot_create_uses_discovered_runtime_config(
    install_fake_providers,
    runner,
    monkeypatch,
    tmp_path: Path,
    write_input_file,
) -> None:
    input_file = write_input_file(tmp_path)
    output_file = tmp_path / "snapshot.json"
    (tmp_path / "vuln-prioritizer.yml").write_text(
        "\n".join(
            [
                "version: 1",
                "defaults:",
                "  policy_profile: enterprise",
                "commands:",
                "  snapshot:",
                "    create:",
                "      priority:",
                "        - high",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    install_fake_providers()
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(
        app,
        [
            "snapshot",
            "create",
            "--input",
            str(input_file),
            "--output",
            str(output_file),
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(output_file.read_text(encoding="utf-8"))
    assert payload["metadata"]["policy_profile"] == "enterprise"
    assert payload["metadata"]["active_filters"] == ["priority=High"]


def test_cli_snapshot_create_emits_markdown(
    install_fake_providers,
    runner,
    tmp_path: Path,
    write_input_file,
) -> None:
    input_file = write_input_file(tmp_path)
    output_file = tmp_path / "snapshot.md"
    install_fake_providers()

    result = runner.invoke(
        app,
        [
            "snapshot",
            "create",
            "--input",
            str(input_file),
            "--output",
            str(output_file),
            "--format",
            "markdown",
        ],
    )

    assert result.exit_code == 0
    report = output_file.read_text(encoding="utf-8")
    assert "# Vulnerability Prioritization Report" in report
    assert "- Findings shown: 4" in report


def test_cli_snapshot_create_supports_multi_input_metadata(
    install_fake_providers,
    runner,
    tmp_path: Path,
) -> None:
    first_input = tmp_path / "cves-a.txt"
    second_input = tmp_path / "cves-b.txt"
    output_file = tmp_path / "snapshot.json"
    first_input.write_text("CVE-2021-44228\nCVE-2024-3094\n", encoding="utf-8")
    second_input.write_text("CVE-2021-44228\nCVE-2023-44487\n", encoding="utf-8")
    install_fake_providers()

    result = runner.invoke(
        app,
        [
            "snapshot",
            "create",
            "--input",
            str(first_input),
            "--input",
            str(second_input),
            "--output",
            str(output_file),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(output_file.read_text(encoding="utf-8"))
    assert payload["metadata"]["input_path"] == str(first_input)
    assert payload["metadata"]["input_paths"] == [str(first_input), str(second_input)]
    assert payload["metadata"]["merged_input_count"] == 2
    assert payload["metadata"]["duplicate_cve_count"] == 1
    assert payload["metadata"]["input_format"] == "cve-list"


def test_cli_snapshot_create_supports_locked_provider_snapshot_replay(
    runner,
    tmp_path: Path,
    monkeypatch,
) -> None:
    input_file = tmp_path / "cves.txt"
    output_file = tmp_path / "snapshot.json"
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
            "snapshot",
            "create",
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


def test_cli_snapshot_diff_reports_all_change_categories(runner, tmp_path: Path) -> None:
    before_file = tmp_path / "before.json"
    after_file = tmp_path / "after.json"
    output_file = tmp_path / "diff.json"

    before_file.write_text(
        json.dumps(
            {
                "metadata": {"schema_version": "1.1.0", "snapshot_kind": "snapshot"},
                "findings": [
                    {
                        "cve_id": "CVE-2024-0001",
                        "priority_label": "High",
                        "priority_rank": 2,
                        "in_kev": False,
                        "attack_mapped": False,
                        "attack_relevance": "Unmapped",
                        "attack_techniques": [],
                        "attack_tactics": [],
                        "provenance": {
                            "targets": ["host:app-01"],
                            "asset_ids": ["asset-a"],
                            "occurrences": [{"asset_business_service": "payments"}],
                            "vex_statuses": {},
                        },
                    },
                    {
                        "cve_id": "CVE-2024-0002",
                        "priority_label": "High",
                        "priority_rank": 2,
                        "in_kev": False,
                        "attack_mapped": False,
                        "attack_relevance": "Unmapped",
                        "attack_techniques": [],
                        "attack_tactics": [],
                        "provenance": {
                            "targets": [],
                            "asset_ids": [],
                            "occurrences": [],
                            "vex_statuses": {},
                        },
                    },
                    {
                        "cve_id": "CVE-2024-0003",
                        "priority_label": "Medium",
                        "priority_rank": 3,
                        "in_kev": False,
                        "attack_mapped": False,
                        "attack_relevance": "Unmapped",
                        "attack_techniques": [],
                        "attack_tactics": [],
                        "provenance": {
                            "targets": [],
                            "asset_ids": [],
                            "occurrences": [],
                            "vex_statuses": {},
                        },
                    },
                ],
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    after_file.write_text(
        json.dumps(
            {
                "metadata": {"schema_version": "1.1.0", "snapshot_kind": "snapshot"},
                "findings": [
                    {
                        "cve_id": "CVE-2024-0001",
                        "priority_label": "High",
                        "priority_rank": 2,
                        "in_kev": False,
                        "attack_mapped": False,
                        "attack_relevance": "Unmapped",
                        "attack_techniques": [],
                        "attack_tactics": [],
                        "provenance": {
                            "targets": ["host:app-02"],
                            "asset_ids": ["asset-a"],
                            "occurrences": [{"asset_business_service": "identity"}],
                            "vex_statuses": {},
                        },
                    },
                    {
                        "cve_id": "CVE-2024-0002",
                        "priority_label": "Critical",
                        "priority_rank": 1,
                        "in_kev": True,
                        "attack_mapped": False,
                        "attack_relevance": "Unmapped",
                        "attack_techniques": [],
                        "attack_tactics": [],
                        "provenance": {
                            "targets": [],
                            "asset_ids": [],
                            "occurrences": [],
                            "vex_statuses": {},
                        },
                    },
                    {
                        "cve_id": "CVE-2024-0004",
                        "priority_label": "Low",
                        "priority_rank": 4,
                        "in_kev": False,
                        "attack_mapped": False,
                        "attack_relevance": "Unmapped",
                        "attack_techniques": [],
                        "attack_tactics": [],
                        "provenance": {
                            "targets": [],
                            "asset_ids": [],
                            "occurrences": [],
                            "vex_statuses": {},
                        },
                    },
                ],
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "snapshot",
            "diff",
            "--before",
            str(before_file),
            "--after",
            str(after_file),
            "--output",
            str(output_file),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(output_file.read_text(encoding="utf-8"))
    assert payload["summary"] == {
        "added": 1,
        "removed": 1,
        "priority_up": 1,
        "priority_down": 0,
        "context_changed": 1,
        "unchanged": 0,
    }
    categories = {item["cve_id"]: item["category"] for item in payload["items"]}
    assert categories["CVE-2024-0001"] == "context_changed"
    assert categories["CVE-2024-0002"] == "priority_up"
    assert categories["CVE-2024-0003"] == "removed"
    assert categories["CVE-2024-0004"] == "added"


def test_cli_snapshot_diff_includes_unchanged_for_cli_produced_snapshots(
    install_fake_providers,
    runner,
    tmp_path: Path,
    write_input_file,
) -> None:
    input_file = write_input_file(tmp_path)
    before_file = tmp_path / "before.json"
    after_file = tmp_path / "after.json"
    diff_file = tmp_path / "diff.json"
    install_fake_providers()

    before_result = runner.invoke(
        app,
        [
            "snapshot",
            "create",
            "--input",
            str(input_file),
            "--output",
            str(before_file),
            "--format",
            "json",
        ],
    )
    after_result = runner.invoke(
        app,
        [
            "snapshot",
            "create",
            "--input",
            str(input_file),
            "--output",
            str(after_file),
            "--format",
            "json",
        ],
    )

    assert before_result.exit_code == 0
    assert after_result.exit_code == 0

    diff_result = runner.invoke(
        app,
        [
            "snapshot",
            "diff",
            "--before",
            str(before_file),
            "--after",
            str(after_file),
            "--include-unchanged",
            "--output",
            str(diff_file),
            "--format",
            "json",
        ],
    )

    assert diff_result.exit_code == 0
    payload = json.loads(diff_file.read_text(encoding="utf-8"))
    assert payload["summary"] == {
        "added": 0,
        "removed": 0,
        "priority_up": 0,
        "priority_down": 0,
        "context_changed": 0,
        "unchanged": 4,
    }
    assert {item["category"] for item in payload["items"]} == {"unchanged"}


def test_cli_rollup_groups_analysis_results_by_service(
    fixture_root,
    install_fake_providers,
    runner,
    tmp_path: Path,
    write_waiver_file,
) -> None:
    analysis_file = tmp_path / "analysis.json"
    rollup_file = tmp_path / "rollup.json"
    asset_context_file = tmp_path / "assets.csv"
    waiver_file = write_waiver_file(
        tmp_path,
        cve_id="CVE-2023-34362",
        owner="risk-review",
        reason="Deferred until the coordinated service restart.",
    )
    asset_context_file.write_text(
        "\n".join(
            [
                "target_kind,target_ref,asset_id,criticality,exposure,environment,owner,business_service",
                "host,app-01.example.internal,payments-api,high,internal,prod,team-payments,payments",
                "host,app-02.example.internal,identity-api,critical,internet-facing,prod,team-identity,identity",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    install_fake_providers()

    analyze_result = runner.invoke(
        app,
        [
            "analyze",
            "--input",
            str(fixture_root / "openvas_report.xml"),
            "--input-format",
            "openvas-xml",
            "--asset-context",
            str(asset_context_file),
            "--waiver-file",
            str(waiver_file),
            "--output",
            str(analysis_file),
            "--format",
            "json",
        ],
    )

    assert analyze_result.exit_code == 0

    rollup_result = runner.invoke(
        app,
        [
            "rollup",
            "--input",
            str(analysis_file),
            "--by",
            "service",
            "--output",
            str(rollup_file),
            "--format",
            "json",
        ],
    )

    assert rollup_result.exit_code == 0
    payload = json.loads(rollup_file.read_text(encoding="utf-8"))
    buckets = {item["bucket"]: item for item in payload["buckets"]}
    assert payload["metadata"]["schema_version"] == "1.2.0"
    assert payload["metadata"]["input_kind"] == "analysis"
    assert payload["metadata"]["dimension"] == "service"
    assert payload["metadata"]["top"] == 5
    assert set(buckets) == {"identity", "payments"}
    assert buckets["identity"]["finding_count"] == 3
    assert buckets["identity"]["actionable_count"] == 2
    assert buckets["payments"]["finding_count"] == 1
    assert buckets["payments"]["actionable_count"] == 0
    assert buckets["identity"]["waived_count"] == 1
    assert buckets["payments"]["waived_count"] == 1
    assert buckets["identity"]["waiver_review_due_count"] == 0
    assert buckets["identity"]["expired_waiver_count"] == 0
    assert "team-identity" in buckets["identity"]["owners"]
    assert "team-payments" in buckets["payments"]["owners"]
    assert "risk-review" in buckets["payments"]["owners"]
    assert buckets["identity"]["recommended_actions"]
    assert "CVE-2023-34362" in buckets["identity"]["top_cves"]
    assert "CVE-2023-34362" in buckets["payments"]["top_cves"]
    assert buckets["identity"]["remediation_rank"] > 0
    assert buckets["identity"]["rank_reason"]
    assert buckets["identity"]["context_hints"]
    assert buckets["identity"]["top_candidates"]
    assert buckets["identity"]["top_candidates"][0]["rank_reason"]
    assert buckets["payments"]["top_candidates"][0]["waived"] is True


def test_cli_rollup_groups_snapshot_results_by_asset(
    fixture_root,
    install_fake_providers,
    runner,
    tmp_path: Path,
    write_waiver_file,
) -> None:
    snapshot_file = tmp_path / "snapshot.json"
    rollup_file = tmp_path / "rollup.json"
    asset_context_file = tmp_path / "assets.csv"
    waiver_file = write_waiver_file(
        tmp_path,
        cve_id="CVE-2023-34362",
        owner="risk-review",
        reason="Deferred until the coordinated service restart.",
    )
    asset_context_file.write_text(
        "\n".join(
            [
                "target_kind,target_ref,asset_id,criticality,exposure,environment,owner,business_service",
                "host,app-01.example.internal,payments-api,high,internal,prod,team-payments,payments",
                "host,app-02.example.internal,identity-api,critical,internet-facing,prod,team-identity,identity",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    install_fake_providers()

    snapshot_result = runner.invoke(
        app,
        [
            "snapshot",
            "create",
            "--input",
            str(fixture_root / "openvas_report.xml"),
            "--input-format",
            "openvas-xml",
            "--asset-context",
            str(asset_context_file),
            "--waiver-file",
            str(waiver_file),
            "--output",
            str(snapshot_file),
            "--format",
            "json",
        ],
    )

    assert snapshot_result.exit_code == 0

    rollup_result = runner.invoke(
        app,
        [
            "rollup",
            "--input",
            str(snapshot_file),
            "--by",
            "asset",
            "--output",
            str(rollup_file),
            "--format",
            "json",
        ],
    )

    assert rollup_result.exit_code == 0
    payload = json.loads(rollup_file.read_text(encoding="utf-8"))
    buckets = {item["bucket"]: item for item in payload["buckets"]}
    assert payload["metadata"]["schema_version"] == "1.2.0"
    assert payload["metadata"]["input_kind"] == "snapshot"
    assert payload["metadata"]["dimension"] == "asset"
    assert set(buckets) == {"identity-api", "payments-api"}
    assert buckets["identity-api"]["finding_count"] == 3
    assert buckets["identity-api"]["actionable_count"] == 2
    assert buckets["payments-api"]["finding_count"] == 1
    assert buckets["payments-api"]["actionable_count"] == 0
    assert buckets["identity-api"]["top_candidates"][0]["asset_ids"] == ["identity-api"]
    assert "payments-api" in buckets["payments-api"]["top_candidates"][0]["asset_ids"]

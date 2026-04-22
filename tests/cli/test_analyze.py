from __future__ import annotations

import json
from pathlib import Path

from vuln_prioritizer.cli import _build_attack_summary_from_findings, app
from vuln_prioritizer.models import (
    AttackData,
    AttackMapping,
    EpssData,
    KevData,
    NvdData,
    PrioritizedFinding,
    ProviderSnapshotItem,
    ProviderSnapshotMetadata,
    ProviderSnapshotReport,
)
from vuln_prioritizer.provider_snapshot import generate_provider_snapshot_json
from vuln_prioritizer.providers.attack import AttackProvider
from vuln_prioritizer.providers.epss import EpssProvider
from vuln_prioritizer.providers.kev import KevProvider
from vuln_prioritizer.providers.nvd import NvdProvider


def test_cli_analyze_end_to_end_with_mocked_providers(
    install_fake_providers,
    runner,
    tmp_path: Path,
    write_input_file,
) -> None:
    input_file = write_input_file(tmp_path)
    output_file = tmp_path / "report.md"
    install_fake_providers()

    result = runner.invoke(
        app,
        [
            "analyze",
            "--input",
            str(input_file),
            "--output",
            str(output_file),
            "--format",
            "markdown",
        ],
    )

    assert result.exit_code == 0
    assert "Vulnerability Prioritization" in result.stdout
    assert "Total input rows: 4" in result.stdout
    assert output_file.exists()
    report = output_file.read_text(encoding="utf-8")
    assert "# Vulnerability Prioritization Report" in report
    assert "- Findings shown: 4" in report
    assert "- NVD hits: 4/4" in report
    assert "## ATT&CK Context Summary" in report


def test_cli_analyze_supports_priority_threshold_filters_and_sorting(
    install_fake_providers,
    runner,
    tmp_path: Path,
    write_input_file,
) -> None:
    input_file = write_input_file(tmp_path)
    output_file = tmp_path / "report.json"
    install_fake_providers()

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
            "--priority",
            "high",
            "--min-epss",
            "0.40",
            "--sort-by",
            "cve",
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(output_file.read_text(encoding="utf-8"))

    assert [item["cve_id"] for item in payload["findings"]] == [
        "CVE-2023-44487",
        "CVE-2024-3094",
    ]
    assert payload["metadata"]["filtered_out_count"] == 2
    assert payload["metadata"]["active_filters"] == ["priority=High", "min-epss>=0.400"]
    assert payload["attack_summary"]["mapped_cves"] == 0


def test_cli_analyze_supports_kev_only_and_min_cvss(
    install_fake_providers,
    runner,
    tmp_path: Path,
    write_input_file,
) -> None:
    input_file = write_input_file(tmp_path)
    output_file = tmp_path / "filtered.json"
    install_fake_providers()

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
            "--kev-only",
            "--min-cvss",
            "7.0",
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(output_file.read_text(encoding="utf-8"))

    assert [item["cve_id"] for item in payload["findings"]] == ["CVE-2021-44228"]
    assert payload["metadata"]["active_filters"] == ["kev-only", "min-cvss>=7.0"]


def test_cli_analyze_supports_custom_policy_thresholds(
    install_fake_providers,
    runner,
    tmp_path: Path,
    write_input_file,
) -> None:
    input_file = write_input_file(tmp_path)
    output_file = tmp_path / "policy.json"
    install_fake_providers()

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
            "--high-epss-threshold",
            "0.30",
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(output_file.read_text(encoding="utf-8"))

    finding = next(item for item in payload["findings"] if item["cve_id"] == "CVE-2024-0004")
    assert finding["priority_label"] == "High"
    assert payload["metadata"]["policy_overrides"] == ["high-epss=0.300"]


def test_cli_analyze_merges_multiple_inputs_and_surfaces_source_metadata(
    install_fake_providers,
    runner,
    tmp_path: Path,
    fixture_root: Path,
) -> None:
    first_input = tmp_path / "cves-a.txt"
    first_input.write_text("CVE-2021-44228\n", encoding="utf-8")
    github_input = fixture_root / "github_alerts_export.json"
    output_file = tmp_path / "analysis.json"
    install_fake_providers()

    result = runner.invoke(
        app,
        [
            "analyze",
            "--input",
            str(first_input),
            "--input",
            str(github_input),
            "--input-format",
            "cve-list",
            "--input-format",
            "github-alerts-json",
            "--output",
            str(output_file),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(output_file.read_text(encoding="utf-8"))

    assert {item["cve_id"] for item in payload["findings"]} == {
        "CVE-2021-44228",
        "CVE-2023-34362",
    }
    assert payload["metadata"]["input_path"] == str(first_input)
    assert payload["metadata"]["input_paths"] == [str(first_input), str(github_input)]
    assert payload["metadata"]["input_format"] == "mixed"
    assert payload["metadata"]["merged_input_count"] == 2
    assert payload["metadata"]["duplicate_cve_count"] == 1
    assert len(payload["metadata"]["input_sources"]) == 2
    assert "Merged input set collapsed duplicate CVEs" in "\n".join(payload["metadata"]["warnings"])


def test_cli_analyze_supports_locked_provider_snapshot_replay(
    runner,
    tmp_path: Path,
    monkeypatch,
) -> None:
    input_file = tmp_path / "cves.txt"
    input_file.write_text("CVE-2021-44228\nCVE-2023-44487\n", encoding="utf-8")
    snapshot_file = tmp_path / "provider-snapshot.json"
    output_file = tmp_path / "analysis.json"
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
            "analyze",
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


def test_cli_analyze_rejects_locked_provider_snapshot_with_missing_coverage(
    runner,
    tmp_path: Path,
) -> None:
    input_file = tmp_path / "cves.txt"
    input_file.write_text("CVE-2021-44228\nCVE-2023-44487\n", encoding="utf-8")
    snapshot_file = tmp_path / "provider-snapshot.json"
    snapshot_file.write_text(
        generate_provider_snapshot_json(
            ProviderSnapshotReport(
                metadata=ProviderSnapshotMetadata(
                    generated_at="2026-04-22T12:00:00Z",
                    input_path=str(input_file),
                    input_paths=[str(input_file)],
                    input_format="cve-list",
                    selected_sources=["nvd", "epss", "kev"],
                    requested_cves=1,
                    output_path=str(snapshot_file),
                    cache_enabled=False,
                ),
                items=[
                    ProviderSnapshotItem(
                        cve_id="CVE-2021-44228",
                        nvd=NvdData(cve_id="CVE-2021-44228"),
                        epss=EpssData(cve_id="CVE-2021-44228"),
                        kev=KevData(cve_id="CVE-2021-44228", in_kev=False),
                    )
                ],
            )
        ),
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "analyze",
            "--input",
            str(input_file),
            "--provider-snapshot-file",
            str(snapshot_file),
            "--locked-provider-data",
        ],
    )

    assert result.exit_code == 2
    assert "Provider snapshot is missing NVD coverage" in result.stdout


def test_cli_analyze_can_emit_direct_html_sidecar(
    install_fake_providers,
    runner,
    tmp_path: Path,
    write_input_file,
) -> None:
    input_file = write_input_file(tmp_path)
    output_file = tmp_path / "analysis.json"
    html_file = tmp_path / "report.html"
    install_fake_providers()

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
            "--html-output",
            str(html_file),
        ],
    )

    assert result.exit_code == 0
    assert output_file.exists()
    assert html_file.exists()
    html = html_file.read_text(encoding="utf-8")
    assert "Known exploited" in html
    assert "Critical / KEV" in html
    assert "Known exploited (KEV)" in html


def test_cli_analyze_can_emit_markdown_summary_sidecar(
    install_fake_providers,
    runner,
    tmp_path: Path,
    write_input_file,
) -> None:
    input_file = write_input_file(tmp_path)
    output_file = tmp_path / "analysis.json"
    summary_file = tmp_path / "summary.md"
    install_fake_providers()

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
            "--summary-output",
            str(summary_file),
        ],
    )

    assert result.exit_code == 0
    assert summary_file.exists()
    summary = summary_file.read_text(encoding="utf-8")
    assert "# Vulnerability Prioritization Summary" in summary
    assert "- Findings shown: 4" in summary
    assert "- Critical: 1" in summary
    assert "CVE-2021-44228" in summary


def test_cli_analyze_applies_waiver_file_and_hide_waived(
    install_fake_providers,
    runner,
    tmp_path: Path,
    write_input_file,
    write_waiver_file,
) -> None:
    input_file = write_input_file(tmp_path)
    output_file = tmp_path / "analysis.json"
    hidden_output_file = tmp_path / "analysis-hidden.json"
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
            "analyze",
            "--input",
            str(input_file),
            "--output",
            str(output_file),
            "--format",
            "json",
            "--waiver-file",
            str(waiver_file),
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(output_file.read_text(encoding="utf-8"))
    waived = next(item for item in payload["findings"] if item["cve_id"] == "CVE-2021-44228")
    assert waived["waived"] is True
    assert waived["waiver_owner"] == "risk-review"
    assert waived["waiver_reason"] == "Approved until the next maintenance window."
    assert payload["metadata"]["waived_count"] == 1
    assert payload["metadata"]["waiver_file"] == str(waiver_file)

    hidden_result = runner.invoke(
        app,
        [
            "analyze",
            "--input",
            str(input_file),
            "--output",
            str(hidden_output_file),
            "--format",
            "json",
            "--waiver-file",
            str(waiver_file),
            "--hide-waived",
        ],
    )

    assert hidden_result.exit_code == 0
    hidden_payload = json.loads(hidden_output_file.read_text(encoding="utf-8"))
    assert "CVE-2021-44228" not in [item["cve_id"] for item in hidden_payload["findings"]]
    assert hidden_payload["metadata"]["waived_count"] == 1
    assert "hide-waived" in hidden_payload["metadata"]["active_filters"]


def test_cli_analyze_fail_on_ignores_waived_findings(
    install_fake_providers,
    runner,
    tmp_path: Path,
    write_input_file,
    write_waiver_file,
) -> None:
    input_file = write_input_file(tmp_path)
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
            "analyze",
            "--input",
            str(input_file),
            "--waiver-file",
            str(waiver_file),
            "--priority",
            "critical",
            "--fail-on",
            "critical",
        ],
    )

    assert result.exit_code == 0


def test_cli_analyze_surfaces_review_due_waiver_state(
    install_fake_providers,
    runner,
    tmp_path: Path,
    write_input_file,
    write_waiver_file,
) -> None:
    input_file = write_input_file(tmp_path)
    output_file = tmp_path / "review-due.json"
    waiver_file = write_waiver_file(
        tmp_path,
        cve_id="CVE-2021-44228",
        owner="risk-review",
        reason="Needs scheduled revalidation.",
        expires_on="2026-04-25",
        review_on="2026-04-20",
    )
    install_fake_providers()

    result = runner.invoke(
        app,
        [
            "analyze",
            "--input",
            str(input_file),
            "--waiver-file",
            str(waiver_file),
            "--output",
            str(output_file),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(output_file.read_text(encoding="utf-8"))
    finding = next(item for item in payload["findings"] if item["cve_id"] == "CVE-2021-44228")
    assert finding["waived"] is True
    assert finding["waiver_status"] == "review_due"
    assert finding["waiver_review_on"] == "2026-04-20"
    assert payload["metadata"]["waiver_review_due_count"] == 1
    assert payload["metadata"]["expired_waiver_count"] == 0


def test_cli_analyze_surfaces_expired_waiver_and_optional_fail_hooks(
    install_fake_providers,
    runner,
    tmp_path: Path,
    write_input_file,
    write_waiver_file,
) -> None:
    input_file = write_input_file(tmp_path)
    output_file = tmp_path / "expired.json"
    waiver_file = write_waiver_file(
        tmp_path,
        cve_id="CVE-2021-44228",
        owner="risk-review",
        reason="Expired waiver for validation.",
        expires_on="2026-04-01",
    )
    install_fake_providers()

    result = runner.invoke(
        app,
        [
            "analyze",
            "--input",
            str(input_file),
            "--waiver-file",
            str(waiver_file),
            "--output",
            str(output_file),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(output_file.read_text(encoding="utf-8"))
    finding = next(item for item in payload["findings"] if item["cve_id"] == "CVE-2021-44228")
    assert finding["waived"] is False
    assert finding["waiver_status"] == "expired"
    assert payload["metadata"]["waived_count"] == 0
    assert payload["metadata"]["expired_waiver_count"] == 1

    fail_result = runner.invoke(
        app,
        [
            "analyze",
            "--input",
            str(input_file),
            "--waiver-file",
            str(waiver_file),
            "--fail-on-expired-waivers",
        ],
    )

    assert fail_result.exit_code == 1
    assert "expired waivers" in fail_result.stdout
    assert "Matched fail-on threshold" not in result.stdout


def test_cli_analyze_rejects_duplicate_primary_and_html_outputs(
    install_fake_providers,
    runner,
    tmp_path: Path,
    write_input_file,
) -> None:
    input_file = write_input_file(tmp_path)
    output_file = tmp_path / "report.json"
    install_fake_providers()

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
            "--html-output",
            str(output_file),
        ],
    )

    assert result.exit_code == 2
    assert "--output and --html-output must point to different" in result.stdout


def test_cli_analyze_rejects_duplicate_primary_and_summary_outputs(
    install_fake_providers,
    runner,
    tmp_path: Path,
    write_input_file,
) -> None:
    input_file = write_input_file(tmp_path)
    output_file = tmp_path / "report.json"
    install_fake_providers()

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
            "--summary-output",
            str(output_file),
        ],
    )

    assert result.exit_code == 2
    assert "--output and --summary-output must point to different" in result.stdout


def test_cli_rejects_invalid_policy_thresholds(
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
            "analyze",
            "--input",
            str(input_file),
            "--high-epss-threshold",
            "0.30",
            "--medium-epss-threshold",
            "0.35",
        ],
    )

    assert result.exit_code == 2
    assert "EPSS thresholds must descend" in result.stdout


def test_cli_analyze_sarif_export_and_fail_on(
    install_fake_providers,
    runner,
    tmp_path: Path,
    write_input_file,
) -> None:
    input_file = write_input_file(tmp_path)
    output_file = tmp_path / "results.sarif"
    install_fake_providers()

    result = runner.invoke(
        app,
        [
            "analyze",
            "--input",
            str(input_file),
            "--output",
            str(output_file),
            "--format",
            "sarif",
            "--fail-on",
            "high",
        ],
    )

    assert result.exit_code == 1
    assert output_file.exists()
    payload = json.loads(output_file.read_text(encoding="utf-8"))
    assert payload["version"] == "2.1.0"
    assert payload["runs"][0]["tool"]["driver"]["name"] == "vuln-prioritizer"
    assert len(payload["runs"][0]["results"]) == 4


def test_cli_analyze_supports_nessus_auto_detection(
    fixture_root,
    install_fake_providers,
    runner,
    tmp_path: Path,
) -> None:
    output_file = tmp_path / "nessus.json"
    install_fake_providers()

    result = runner.invoke(
        app,
        [
            "analyze",
            "--input",
            str(fixture_root / "nessus_report.nessus"),
            "--output",
            str(output_file),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(output_file.read_text(encoding="utf-8"))
    assert payload["metadata"]["input_format"] == "nessus-xml"
    assert payload["metadata"]["occurrences_count"] == 4
    assert payload["metadata"]["source_stats"] == {"nessus-xml": 4}
    finding = next(item for item in payload["findings"] if item["cve_id"] == "CVE-2023-34362")
    assert "host:web-01.example.internal" in finding["provenance"]["targets"]
    assert "host:192.0.2.20" in finding["provenance"]["targets"]


def test_cli_analyze_supports_openvas_xml_input_format(
    fixture_root,
    install_fake_providers,
    runner,
    tmp_path: Path,
) -> None:
    output_file = tmp_path / "openvas.json"
    install_fake_providers()

    result = runner.invoke(
        app,
        [
            "analyze",
            "--input",
            str(fixture_root / "openvas_report.xml"),
            "--input-format",
            "openvas-xml",
            "--output",
            str(output_file),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(output_file.read_text(encoding="utf-8"))
    assert payload["metadata"]["input_format"] == "openvas-xml"
    assert payload["metadata"]["occurrences_count"] == 4
    assert payload["metadata"]["source_stats"] == {"openvas-xml": 4}
    finding = next(item for item in payload["findings"] if item["cve_id"] == "CVE-2021-44228")
    assert finding["provenance"]["targets"] == ["host:app-02.example.internal"]


def test_build_attack_summary_from_findings_preserves_mapping_type_distribution() -> None:
    finding = PrioritizedFinding(
        cve_id="CVE-2023-34362",
        attack_mapped=True,
        attack_relevance="High",
        attack_mappings=[
            AttackMapping(
                capability_id="CVE-2023-34362",
                attack_object_id="T1190",
                attack_object_name="Exploit Public-Facing Application",
                mapping_type="exploitation_technique",
                capability_group="sql_injection",
            )
        ],
        attack_techniques=["T1190"],
        attack_tactics=["Initial Access"],
        priority_label="Critical",
        priority_rank=1,
        rationale="Representative rationale.",
        recommended_action="Patch immediately.",
    )

    summary = _build_attack_summary_from_findings([finding])

    assert summary.mapped_cves == 1
    assert summary.unmapped_cves == 0
    assert summary.mapping_type_distribution == {"exploitation_technique": 1}
    assert summary.technique_distribution == {"T1190": 1}
    assert summary.tactic_distribution == {"Initial Access": 1}


def test_cli_analyze_attack_hits_matches_visible_attack_summary(
    install_fake_providers,
    monkeypatch,
    runner,
    tmp_path: Path,
    write_input_file,
) -> None:
    input_file = write_input_file(tmp_path)
    output_file = tmp_path / "filtered.json"
    install_fake_providers()

    def fake_filtered_attack_fetch_many(  # noqa: ANN001
        self,
        cve_ids,
        *,
        enabled,
        source="none",
        mapping_file=None,
        technique_metadata_file=None,
        offline_file=None,
    ):
        return (
            {
                "CVE-2024-0004": AttackData(
                    cve_id="CVE-2024-0004",
                    mapped=enabled,
                    source="local-csv" if enabled else source,
                    attack_relevance="Low" if enabled else "Unmapped",
                    attack_rationale=(
                        "Legacy local ATT&CK CSV context is available for this CVE."
                        if enabled
                        else "No ATT&CK context was provided for this CVE."
                    ),
                    mapping_types=["uncategorized"],
                    attack_techniques=["T1595"],
                    attack_tactics=["Reconnaissance"],
                    attack_note="Filtered mapping.",
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

    monkeypatch.setattr(AttackProvider, "fetch_many", fake_filtered_attack_fetch_many)

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
            "--min-epss",
            "0.40",
            "--offline-attack-file",
            str(tmp_path / "attack.csv"),
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(output_file.read_text(encoding="utf-8"))
    assert payload["metadata"]["attack_hits"] == 0
    assert payload["attack_summary"]["mapped_cves"] == 0


def test_cli_analyze_supports_trivy_vex_asset_context_and_custom_policy(
    fixture_root,
    install_fake_providers,
    runner,
    tmp_path: Path,
) -> None:
    output_file = tmp_path / "scanner-analysis.json"
    asset_context_file = tmp_path / "assets.csv"
    asset_context_file.write_text(
        "\n".join(
            [
                "target_kind,target_ref,asset_id,criticality,exposure,environment,owner,business_service",
                '"image","ghcr.io/acme/demo-app:1.0.0 (alpine 3.19)","api-gateway",'
                + '"critical","internet-facing","prod","platform-team","customer-login"',
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(
        "\n".join(
            [
                "profiles:",
                "  prod-urgent:",
                "    narrative_only: false",
                "    enterprise_escalation: true",
                "    internet_facing_boost: true",
                "    prod_asset_boost: true",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    install_fake_providers()

    result = runner.invoke(
        app,
        [
            "analyze",
            "--input",
            str(fixture_root / "trivy_report.json"),
            "--input-format",
            "trivy-json",
            "--asset-context",
            str(asset_context_file),
            "--vex-file",
            str(fixture_root / "openvex_statements.json"),
            "--policy-file",
            str(policy_file),
            "--policy-profile",
            "prod-urgent",
            "--output",
            str(output_file),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(output_file.read_text(encoding="utf-8"))

    assert payload["metadata"]["input_format"] == "trivy-json"
    assert payload["metadata"]["policy_profile"] == "prod-urgent"
    assert payload["metadata"]["suppressed_by_vex"] == 1
    assert payload["metadata"]["under_investigation_count"] == 1
    assert payload["metadata"]["asset_match_conflict_count"] == 0
    assert payload["metadata"]["vex_conflict_count"] == 0
    assert payload["metadata"]["source_stats"] == {"trivy-json": 3}
    assert payload["metadata"]["schema_version"] == "1.0.0"

    finding_ids = [item["cve_id"] for item in payload["findings"]]
    assert "CVE-2023-34362" not in finding_ids
    assert finding_ids == ["CVE-2024-4577", "CVE-2024-3094"]

    context_finding = next(
        item for item in payload["findings"] if item["cve_id"] == "CVE-2024-3094"
    )
    assert context_finding["highest_asset_criticality"] == "critical"
    assert context_finding["asset_count"] == 1
    assert context_finding["remediation"]["strategy"] == "upgrade"
    occurrence = context_finding["provenance"]["occurrences"][0]
    assert occurrence["asset_match_mode"] == "exact"
    assert occurrence["asset_match_candidate_count"] == 1
    assert (
        context_finding["context_recommendation"]
        == "Escalate validation and remediation because context indicates "
        "internet-facing exposure, production environment."
    )


def test_cli_analyze_show_suppressed_keeps_vex_hidden_findings_visible(
    fixture_root,
    install_fake_providers,
    runner,
    tmp_path: Path,
) -> None:
    output_file = tmp_path / "show-suppressed.json"
    install_fake_providers()

    result = runner.invoke(
        app,
        [
            "analyze",
            "--input",
            str(fixture_root / "trivy_report.json"),
            "--input-format",
            "trivy-json",
            "--vex-file",
            str(fixture_root / "openvex_statements.json"),
            "--show-suppressed",
            "--output",
            str(output_file),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(output_file.read_text(encoding="utf-8"))
    assert payload["metadata"]["active_filters"] == ["show-suppressed"]

    suppressed = next(item for item in payload["findings"] if item["cve_id"] == "CVE-2023-34362")
    assert suppressed["suppressed_by_vex"] is True
    assert suppressed["provenance"]["vex_statuses"] == {"not_affected": 1}


def test_cli_analyze_reports_asset_and_vex_conflicts_with_deterministic_winners(
    install_fake_providers,
    runner,
    tmp_path: Path,
) -> None:
    input_file = tmp_path / "cves.txt"
    input_file.write_text("CVE-2021-44228\n", encoding="utf-8")
    asset_context_file = tmp_path / "assets.csv"
    asset_context_file.write_text(
        "\n".join(
            [
                "rule_id,target_kind,target_ref,asset_id,match_mode,precedence,criticality",
                "glob-rule,host,app-*,asset-glob,glob,10,medium",
                "exact-rule,host,app-01,asset-exact,exact,10,critical",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    vex_file = tmp_path / "vex.json"
    vex_file.write_text(
        json.dumps(
            {
                "statements": [
                    {
                        "vulnerability": {"name": "CVE-2021-44228"},
                        "status": "under_investigation",
                        "products": [{"subcomponents": [{"kind": "host", "name": "app-01"}]}],
                    },
                    {
                        "vulnerability": {"name": "CVE-2021-44228"},
                        "status": "fixed",
                        "products": [{"subcomponents": [{"kind": "host", "name": "app-01"}]}],
                    },
                ]
            }
        )
        + "\n",
        encoding="utf-8",
    )
    output_file = tmp_path / "analysis.json"
    install_fake_providers()

    result = runner.invoke(
        app,
        [
            "analyze",
            "--input",
            str(input_file),
            "--asset-context",
            str(asset_context_file),
            "--vex-file",
            str(vex_file),
            "--target-kind",
            "host",
            "--target-ref",
            "app-01",
            "--output",
            str(output_file),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(output_file.read_text(encoding="utf-8"))
    assert payload["metadata"]["asset_match_conflict_count"] == 1
    assert payload["metadata"]["vex_conflict_count"] == 1
    assert any("Asset context resolved" in warning for warning in payload["metadata"]["warnings"])
    assert any("VEX resolved" in warning for warning in payload["metadata"]["warnings"])

    finding = payload["findings"][0]
    occurrence = finding["provenance"]["occurrences"][0]
    assert occurrence["asset_id"] == "asset-exact"
    assert occurrence["asset_match_rule_id"] == "exact-rule"
    assert occurrence["asset_match_mode"] == "exact"
    assert occurrence["asset_match_candidate_count"] == 2
    assert occurrence["vex_status"] == "under_investigation"
    assert occurrence["vex_match_type"] == "target"
    assert occurrence["vex_candidate_count"] == 2

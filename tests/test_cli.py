from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from typer.testing import CliRunner

from vuln_prioritizer import __version__
from vuln_prioritizer.cli import _build_attack_summary_from_findings, app
from vuln_prioritizer.models import (
    AttackData,
    AttackMapping,
    EpssData,
    KevData,
    NvdData,
    PrioritizedFinding,
)
from vuln_prioritizer.providers.attack import AttackProvider
from vuln_prioritizer.providers.epss import EpssProvider
from vuln_prioritizer.providers.kev import KevProvider
from vuln_prioritizer.providers.nvd import NvdProvider

runner = CliRunner()
FIXTURE_ROOT = Path(__file__).resolve().parents[1] / "data" / "input_fixtures"
ATTACK_ROOT = Path(__file__).resolve().parents[1] / "data" / "attack"


def _format_help_block(*args: str) -> str:
    result = runner.invoke(app, [*args, "--help"])

    assert result.exit_code == 0
    lines = result.stdout.splitlines()
    for index, line in enumerate(lines):
        if "--format" not in line:
            continue
        block = [line]
        next_index = index + 1
        while next_index < len(lines):
            next_line = lines[next_index]
            if "--" in next_line:
                break
            block.append(next_line)
            next_index += 1
        return " ".join(part.strip() for part in block)

    raise AssertionError("Expected a --format option in command help.")


def test_cli_analyze_end_to_end_with_mocked_providers(monkeypatch, tmp_path: Path) -> None:
    input_file = _write_input_file(tmp_path)
    output_file = tmp_path / "report.md"
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
    monkeypatch,
    tmp_path: Path,
) -> None:
    input_file = _write_input_file(tmp_path)
    output_file = tmp_path / "report.json"
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


def test_cli_analyze_supports_kev_only_and_min_cvss(monkeypatch, tmp_path: Path) -> None:
    input_file = _write_input_file(tmp_path)
    output_file = tmp_path / "filtered.json"
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
            "--kev-only",
            "--min-cvss",
            "7.0",
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(output_file.read_text(encoding="utf-8"))

    assert [item["cve_id"] for item in payload["findings"]] == ["CVE-2021-44228"]
    assert payload["metadata"]["active_filters"] == ["kev-only", "min-cvss>=7.0"]


def test_cli_compare_table_mode(monkeypatch, tmp_path: Path) -> None:
    input_file = _write_input_file(tmp_path)
    _install_fake_providers(monkeypatch)

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


def test_cli_compare_json_export(monkeypatch, tmp_path: Path) -> None:
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


def test_cli_compare_and_explain_surface_waiver_details(monkeypatch, tmp_path: Path) -> None:
    input_file = _write_input_file(tmp_path)
    compare_file = tmp_path / "compare.json"
    explain_file = tmp_path / "explain.json"
    waiver_file = _write_waiver_file(
        tmp_path,
        cve_id="CVE-2021-44228",
        owner="risk-review",
        reason="Approved until the next maintenance window.",
    )
    _install_fake_providers(monkeypatch)

    compare_result = runner.invoke(
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

    assert compare_result.exit_code == 0
    compare_payload = json.loads(compare_file.read_text(encoding="utf-8"))
    waived_row = next(
        item for item in compare_payload["comparisons"] if item["cve_id"] == "CVE-2021-44228"
    )
    assert waived_row["waived"] is True
    assert waived_row["waiver_owner"] == "risk-review"

    explain_result = runner.invoke(
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

    assert explain_result.exit_code == 0
    explain_payload = json.loads(explain_file.read_text(encoding="utf-8"))
    assert explain_payload["finding"]["waived"] is True
    assert explain_payload["finding"]["waiver_scope"] == "global"
    assert explain_payload["metadata"]["waiver_file"] == str(waiver_file)


def test_cli_analyze_supports_custom_policy_thresholds(monkeypatch, tmp_path: Path) -> None:
    input_file = _write_input_file(tmp_path)
    output_file = tmp_path / "policy.json"
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
            "--high-epss-threshold",
            "0.30",
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(output_file.read_text(encoding="utf-8"))

    finding = next(item for item in payload["findings"] if item["cve_id"] == "CVE-2024-0004")
    assert finding["priority_label"] == "High"
    assert payload["metadata"]["policy_overrides"] == ["high-epss=0.300"]


def test_cli_analyze_can_emit_direct_html_sidecar(monkeypatch, tmp_path: Path) -> None:
    input_file = _write_input_file(tmp_path)
    output_file = tmp_path / "analysis.json"
    html_file = tmp_path / "report.html"
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


def test_cli_analyze_can_emit_markdown_summary_sidecar(monkeypatch, tmp_path: Path) -> None:
    input_file = _write_input_file(tmp_path)
    output_file = tmp_path / "analysis.json"
    summary_file = tmp_path / "summary.md"
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


def test_cli_analyze_applies_waiver_file_and_hide_waived(monkeypatch, tmp_path: Path) -> None:
    input_file = _write_input_file(tmp_path)
    output_file = tmp_path / "analysis.json"
    hidden_output_file = tmp_path / "analysis-hidden.json"
    waiver_file = _write_waiver_file(
        tmp_path,
        cve_id="CVE-2021-44228",
        owner="risk-review",
        reason="Approved until the next maintenance window.",
    )
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


def test_cli_analyze_fail_on_ignores_waived_findings(monkeypatch, tmp_path: Path) -> None:
    input_file = _write_input_file(tmp_path)
    waiver_file = _write_waiver_file(
        tmp_path,
        cve_id="CVE-2021-44228",
        owner="risk-review",
        reason="Approved until the next maintenance window.",
    )
    _install_fake_providers(monkeypatch)

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


def test_cli_analyze_surfaces_review_due_waiver_state(monkeypatch, tmp_path: Path) -> None:
    input_file = _write_input_file(tmp_path)
    output_file = tmp_path / "review-due.json"
    waiver_file = _write_waiver_file(
        tmp_path,
        cve_id="CVE-2021-44228",
        owner="risk-review",
        reason="Needs scheduled revalidation.",
        expires_on="2026-04-25",
        review_on="2026-04-20",
    )
    _install_fake_providers(monkeypatch)

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
    monkeypatch,
    tmp_path: Path,
) -> None:
    input_file = _write_input_file(tmp_path)
    output_file = tmp_path / "expired.json"
    waiver_file = _write_waiver_file(
        tmp_path,
        cve_id="CVE-2021-44228",
        owner="risk-review",
        reason="Expired waiver for validation.",
        expires_on="2026-04-01",
    )
    _install_fake_providers(monkeypatch)

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
    monkeypatch,
    tmp_path: Path,
) -> None:
    input_file = _write_input_file(tmp_path)
    _install_fake_providers(monkeypatch)
    output_file = tmp_path / "report.json"

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
    monkeypatch,
    tmp_path: Path,
) -> None:
    input_file = _write_input_file(tmp_path)
    _install_fake_providers(monkeypatch)
    output_file = tmp_path / "report.json"

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


def test_cli_rejects_invalid_policy_thresholds(monkeypatch, tmp_path: Path) -> None:
    input_file = _write_input_file(tmp_path)
    _install_fake_providers(monkeypatch)

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


def test_cli_compare_rejects_output_with_table_format(tmp_path: Path) -> None:
    input_file = _write_input_file(tmp_path)

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


def test_cli_compare_rejects_sarif_format(tmp_path: Path) -> None:
    input_file = _write_input_file(tmp_path)

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
    assert "compare supports only --format json, markdown, table." in result.stdout


def test_cli_analyze_help_lists_all_supported_formats() -> None:
    help_block = _format_help_block("analyze")

    assert "markdown" in help_block
    assert "json" in help_block
    assert "sarif" in help_block
    assert "table" in help_block


def test_cli_compare_help_omits_sarif_format() -> None:
    help_block = _format_help_block("compare")

    assert "markdown" in help_block
    assert "json" in help_block
    assert "table" in help_block
    assert "sarif" not in help_block


def test_cli_doctor_help_lists_only_table_and_json_formats() -> None:
    help_block = _format_help_block("doctor")

    assert "table" in help_block
    assert "json" in help_block
    assert "markdown" not in help_block
    assert "sarif" not in help_block


def test_cli_snapshot_create_help_lists_only_snapshot_export_formats() -> None:
    help_block = _format_help_block("snapshot", "create")

    assert "json" in help_block
    assert "markdown" in help_block
    assert "table" not in help_block
    assert "sarif" not in help_block


def test_cli_explain_rejects_sarif_format() -> None:
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
    assert "explain supports only --format json, markdown, table." in result.stdout


def test_cli_explain_end_to_end_with_mocked_providers(monkeypatch, tmp_path: Path) -> None:
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
    assert "Explanation for CVE-2021-44228" in result.stdout
    assert output_file.exists()
    payload = json.loads(output_file.read_text(encoding="utf-8"))
    assert payload["finding"]["priority_label"] == "Critical"
    assert payload["comparison"]["cvss_only_label"] == "Critical"
    assert payload["attack"]["attack_note"] == "Representative demo mapping note."
    assert payload["metadata"]["attack_source"] == "local-csv"


def test_cli_analyze_sarif_export_and_fail_on(monkeypatch, tmp_path: Path) -> None:
    input_file = _write_input_file(tmp_path)
    output_file = tmp_path / "results.sarif"
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


def test_cli_data_status_shows_cache_and_attack_metadata(tmp_path: Path) -> None:
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
        ],
    )

    assert result.exit_code == 0
    assert "Data Status" in result.stdout
    assert "Cache directory:" in result.stdout
    assert "ATT&CK source:" in result.stdout
    assert "ATT&CK version:" in result.stdout


def test_cli_report_html_renders_from_analysis_json(monkeypatch, tmp_path: Path) -> None:
    input_file = _write_input_file(tmp_path)
    analysis_file = tmp_path / "analysis.json"
    html_file = tmp_path / "report.html"
    _install_fake_providers(monkeypatch)

    analyze_result = runner.invoke(
        app,
        [
            "analyze",
            "--input",
            str(input_file),
            "--output",
            str(analysis_file),
            "--format",
            "json",
        ],
    )

    assert analyze_result.exit_code == 0

    html_result = runner.invoke(
        app,
        [
            "report",
            "html",
            "--input",
            str(analysis_file),
            "--output",
            str(html_file),
        ],
    )

    assert html_result.exit_code == 0
    html = html_file.read_text(encoding="utf-8")
    assert "<h1>vuln-prioritizer Executive Report</h1>" in html
    assert "CVE-2021-44228" in html


def test_cli_analyze_uses_discovered_runtime_config_and_no_config_disables_it(
    monkeypatch,
    tmp_path: Path,
) -> None:
    input_file = _write_input_file(tmp_path)
    configured_output = tmp_path / "configured.json"
    no_config_output = tmp_path / "no-config.json"
    (tmp_path / "vuln-prioritizer.yml").write_text(
        "\n".join(
            [
                "version: 1",
                "defaults:",
                "  policy_profile: enterprise",
                "commands:",
                "  analyze:",
                "    priority:",
                "      - high",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    _install_fake_providers(monkeypatch)
    monkeypatch.chdir(tmp_path)

    configured = runner.invoke(
        app,
        [
            "analyze",
            "--input",
            str(input_file),
            "--output",
            str(configured_output),
            "--format",
            "json",
        ],
    )

    assert configured.exit_code == 0
    configured_payload = json.loads(configured_output.read_text(encoding="utf-8"))
    assert configured_payload["metadata"]["policy_profile"] == "enterprise"
    assert configured_payload["metadata"]["active_filters"] == ["priority=High"]

    no_config = runner.invoke(
        app,
        [
            "--no-config",
            "analyze",
            "--input",
            str(input_file),
            "--output",
            str(no_config_output),
            "--format",
            "json",
        ],
    )

    assert no_config.exit_code == 0
    no_config_payload = json.loads(no_config_output.read_text(encoding="utf-8"))
    assert no_config_payload["metadata"]["policy_profile"] == "default"
    assert no_config_payload["metadata"]["active_filters"] == []


def test_cli_doctor_fails_cleanly_for_missing_runtime_config(tmp_path: Path) -> None:
    missing_config = tmp_path / "missing-runtime-config.yml"

    result = runner.invoke(
        app,
        [
            "--config",
            str(missing_config),
            "doctor",
        ],
    )

    assert result.exit_code == 2
    assert "Input validation failed:" in result.stdout
    assert missing_config.name in result.stdout
    assert isinstance(result.exception, SystemExit)
    assert "Traceback" not in result.stdout


def test_cli_root_version_reports_package_version_without_loading_runtime_config(
    monkeypatch,
    tmp_path: Path,
) -> None:
    (tmp_path / "vuln-prioritizer.yml").write_text("version: [broken\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(app, ["--version"])

    assert result.exit_code == 0
    assert result.stdout.strip() == f"vuln-prioritizer {__version__}"


def test_cli_doctor_json_reports_healthy_local_state(tmp_path: Path) -> None:
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    output_file = tmp_path / "doctor.json"

    result = runner.invoke(
        app,
        [
            "doctor",
            "--cache-dir",
            str(cache_dir),
            "--output",
            str(output_file),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(output_file.read_text(encoding="utf-8"))
    checks = {item["check_id"]: item for item in payload["checks"]}
    assert payload["schema_version"] == "1.2.0"
    assert payload["summary"]["overall_status"] == "ok"
    assert checks["runtime.python"]["status"] == "ok"
    assert checks["runtime.python"]["category"] == "runtime"
    assert checks["runtime.config"]["status"] == "ok"
    assert checks["cache.nvd"]["status"] == "ok"
    assert checks["cache.epss"]["status"] == "ok"
    assert checks["cache.kev"]["status"] == "ok"


def test_cli_doctor_reports_missing_files_as_degraded(tmp_path: Path) -> None:
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    output_file = tmp_path / "doctor.json"
    missing_mapping = tmp_path / "missing-mapping.json"

    result = runner.invoke(
        app,
        [
            "doctor",
            "--cache-dir",
            str(cache_dir),
            "--attack-mapping-file",
            str(missing_mapping),
            "--output",
            str(output_file),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 1
    payload = json.loads(output_file.read_text(encoding="utf-8"))
    checks = {item["check_id"]: item for item in payload["checks"]}
    assert payload["summary"]["overall_status"] == "error"
    assert checks["path.attack_mapping_file"]["status"] == "error"
    assert checks["attack.validation"]["status"] == "error"


def test_cli_doctor_reports_waiver_health(tmp_path: Path) -> None:
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    output_file = tmp_path / "doctor-waivers.json"
    waiver_file = _write_waiver_file(
        tmp_path,
        cve_id="CVE-2021-44228",
        owner="risk-review",
        reason="Needs formal review.",
        expires_on="2026-04-25",
        review_on="2026-04-20",
    )

    result = runner.invoke(
        app,
        [
            "doctor",
            "--cache-dir",
            str(cache_dir),
            "--waiver-file",
            str(waiver_file),
            "--output",
            str(output_file),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 1
    payload = json.loads(output_file.read_text(encoding="utf-8"))
    checks = {item["check_id"]: item for item in payload["checks"]}
    assert payload["summary"]["overall_status"] == "degraded"
    assert checks["path.waiver_file"]["status"] == "ok"
    assert checks["waiver.health"]["status"] == "degraded"
    assert "review due" in checks["waiver.health"]["detail"]


def test_cli_doctor_marks_dirty_cache_namespaces_as_degraded(tmp_path: Path) -> None:
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    output_file = tmp_path / "doctor-cache.json"
    expired_cache = cache_dir / "nvd" / "expired.json"
    expired_cache.parent.mkdir(parents=True, exist_ok=True)
    expired_cache.write_text(
        json.dumps(
            {
                "key": "CVE-2026-0001",
                "cached_at": (datetime.now(UTC) - timedelta(hours=2)).isoformat(),
                "payload": {"value": 1},
            }
        ),
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "doctor",
            "--cache-dir",
            str(cache_dir),
            "--cache-ttl-hours",
            "1",
            "--output",
            str(output_file),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 1
    payload = json.loads(output_file.read_text(encoding="utf-8"))
    checks = {item["check_id"]: item for item in payload["checks"]}
    assert payload["summary"]["overall_status"] == "degraded"
    assert checks["cache.nvd"]["status"] == "degraded"
    assert "expired" in checks["cache.nvd"]["detail"]


def test_cli_doctor_rejects_invalid_discovered_runtime_config(monkeypatch, tmp_path: Path) -> None:
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    (tmp_path / "vuln-prioritizer.yml").write_text("version: [broken\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(
        app,
        [
            "doctor",
            "--cache-dir",
            str(cache_dir),
        ],
    )

    assert result.exit_code == 2
    assert "Input validation failed:" in result.stdout
    assert "vuln-prioritizer.yml" in result.stdout


def test_cli_doctor_live_mode_runs_reachability_probes(monkeypatch, tmp_path: Path) -> None:
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    output_file = tmp_path / "doctor-live.json"

    class _FakeResponse:
        def __init__(self, status_code: int = 200) -> None:
            self.status_code = status_code

        def raise_for_status(self) -> None:
            return None

    def fake_get(url, params=None, timeout=5):  # noqa: ANN001
        return _FakeResponse()

    monkeypatch.setattr("vuln_prioritizer.cli.requests.get", fake_get)
    monkeypatch.setenv("NVD_API_KEY", "test-key")

    result = runner.invoke(
        app,
        [
            "doctor",
            "--cache-dir",
            str(cache_dir),
            "--live",
            "--output",
            str(output_file),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(output_file.read_text(encoding="utf-8"))
    checks = {item["check_id"]: item for item in payload["checks"]}
    assert payload["summary"]["overall_status"] == "ok"
    assert checks["auth.nvd_api_key"]["status"] == "ok"
    assert checks["live.nvd_api"]["status"] == "ok"
    assert checks["live.epss_api"]["status"] == "ok"
    assert checks["live.kev_feed"]["status"] == "ok"


def test_cli_doctor_live_mode_warns_when_nvd_api_key_is_missing(
    monkeypatch,
    tmp_path: Path,
) -> None:
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    output_file = tmp_path / "doctor-live-warn.json"

    class _FakeResponse:
        def __init__(self, status_code: int = 200) -> None:
            self.status_code = status_code

        def raise_for_status(self) -> None:
            return None

    def fake_get(url, params=None, timeout=5):  # noqa: ANN001
        return _FakeResponse()

    monkeypatch.setattr("vuln_prioritizer.cli.requests.get", fake_get)
    monkeypatch.delenv("NVD_API_KEY", raising=False)

    result = runner.invoke(
        app,
        [
            "doctor",
            "--cache-dir",
            str(cache_dir),
            "--live",
            "--output",
            str(output_file),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 1
    payload = json.loads(output_file.read_text(encoding="utf-8"))
    checks = {item["check_id"]: item for item in payload["checks"]}
    assert payload["summary"]["overall_status"] == "degraded"
    assert checks["auth.nvd_api_key"]["status"] == "degraded"
    assert "anonymous rate limits" in checks["auth.nvd_api_key"]["detail"]


def test_cli_analyze_supports_nessus_auto_detection(monkeypatch, tmp_path: Path) -> None:
    output_file = tmp_path / "nessus.json"
    _install_fake_providers(monkeypatch)

    result = runner.invoke(
        app,
        [
            "analyze",
            "--input",
            str(FIXTURE_ROOT / "nessus_report.nessus"),
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


def test_cli_analyze_supports_openvas_xml_input_format(monkeypatch, tmp_path: Path) -> None:
    output_file = tmp_path / "openvas.json"
    _install_fake_providers(monkeypatch)

    result = runner.invoke(
        app,
        [
            "analyze",
            "--input",
            str(FIXTURE_ROOT / "openvas_report.xml"),
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


def test_cli_report_html_rejects_compare_json(tmp_path: Path) -> None:
    compare_file = tmp_path / "compare.json"
    compare_file.write_text(
        json.dumps({"metadata": {"schema_version": "1.0.0"}, "comparisons": []}),
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "report",
            "html",
            "--input",
            str(compare_file),
            "--output",
            str(tmp_path / "report.html"),
        ],
    )

    assert result.exit_code == 2
    assert "analysis JSON export produced" in result.stdout
    assert "`analyze`" in result.stdout


def test_cli_report_html_rejects_invalid_json(tmp_path: Path) -> None:
    invalid_file = tmp_path / "invalid.json"
    invalid_file.write_text("{not-json", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "report",
            "html",
            "--input",
            str(invalid_file),
            "--output",
            str(tmp_path / "report.html"),
        ],
    )

    assert result.exit_code == 2
    assert "is not valid JSON" in result.stdout


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
    monkeypatch,
    tmp_path: Path,
) -> None:
    input_file = _write_input_file(tmp_path)
    output_file = tmp_path / "filtered.json"
    _install_fake_providers(monkeypatch)

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
    monkeypatch,
    tmp_path: Path,
) -> None:
    output_file = tmp_path / "scanner-analysis.json"
    asset_context_file = tmp_path / "assets.csv"
    asset_context_file.write_text(
        "\n".join(
            [
                "target_kind,target_ref,asset_id,criticality,exposure,environment,owner,business_service",
                '"image","ghcr.io/acme/demo-app:1.0.0 (alpine 3.19)",'
                '"api-gateway","critical","internet-facing","prod",'
                '"platform-team","customer-login"',
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
    _install_fake_providers(monkeypatch)

    result = runner.invoke(
        app,
        [
            "analyze",
            "--input",
            str(FIXTURE_ROOT / "trivy_report.json"),
            "--input-format",
            "trivy-json",
            "--asset-context",
            str(asset_context_file),
            "--vex-file",
            str(FIXTURE_ROOT / "openvex_statements.json"),
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
    assert (
        context_finding["context_recommendation"]
        == "Escalate validation and remediation because context indicates "
        "internet-facing exposure, production environment."
    )


def test_cli_analyze_show_suppressed_keeps_vex_hidden_findings_visible(
    monkeypatch,
    tmp_path: Path,
) -> None:
    output_file = tmp_path / "show-suppressed.json"
    _install_fake_providers(monkeypatch)

    result = runner.invoke(
        app,
        [
            "analyze",
            "--input",
            str(FIXTURE_ROOT / "trivy_report.json"),
            "--input-format",
            "trivy-json",
            "--vex-file",
            str(FIXTURE_ROOT / "openvex_statements.json"),
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


def test_cli_snapshot_create_emits_snapshot_json(monkeypatch, tmp_path: Path) -> None:
    input_file = _write_input_file(tmp_path)
    output_file = tmp_path / "snapshot.json"
    _install_fake_providers(monkeypatch)

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


def test_cli_snapshot_diff_reports_all_change_categories(tmp_path: Path) -> None:
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


def test_cli_rollup_groups_analysis_results_by_service(monkeypatch, tmp_path: Path) -> None:
    analysis_file = tmp_path / "analysis.json"
    rollup_file = tmp_path / "rollup.json"
    asset_context_file = tmp_path / "assets.csv"
    waiver_file = _write_waiver_file(
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
    _install_fake_providers(monkeypatch)

    analyze_result = runner.invoke(
        app,
        [
            "analyze",
            "--input",
            str(FIXTURE_ROOT / "openvas_report.xml"),
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


def _write_input_file(tmp_path: Path) -> Path:
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


def _write_waiver_file(
    tmp_path: Path,
    *,
    cve_id: str,
    owner: str,
    reason: str,
    expires_on: str = "2027-12-31",
    review_on: str | None = None,
) -> Path:
    waiver_file = tmp_path / "waivers.yml"
    lines = [
        "waivers:",
        "  - id: waiver-1",
        f"    cve_id: {cve_id}",
        f"    owner: {owner}",
        f"    reason: {reason}",
        f"    expires_on: {expires_on}",
    ]
    if review_on is not None:
        lines.append(f"    review_on: {review_on}")
    waiver_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return waiver_file


def _install_fake_providers(monkeypatch) -> None:  # noqa: ANN001
    def fake_nvd_fetch_many(self, cve_ids):  # noqa: ANN001
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

    def fake_epss_fetch_many(self, cve_ids):  # noqa: ANN001
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

    def fake_kev_fetch_many(self, cve_ids, offline_file=None):  # noqa: ANN001
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

    def fake_attack_fetch_many(  # noqa: ANN001
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

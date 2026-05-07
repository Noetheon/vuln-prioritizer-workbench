from __future__ import annotations

import json
from pathlib import Path

from app.services.report_contracts import CSV_FINDINGS_COLUMNS
from vuln_prioritizer.cli import app
from vuln_prioritizer.reporting_workbench import (
    _csv_safe_cell,
    _finding_status_label,
    _first_occurrence_value,
    _vex_statuses_label,
    generate_findings_csv,
    generate_workbench_sarif,
)
from vuln_prioritizer.sarif_contract import (
    SARIF_FINGERPRINT_KEY,
    SARIF_WORKBENCH_FINGERPRINT_KEY,
)
from vuln_prioritizer.sarif_validation import validate_sarif_payload


def test_cli_report_html_renders_from_analysis_json(
    install_fake_providers,
    runner,
    tmp_path: Path,
    write_input_file,
) -> None:
    input_file = write_input_file(tmp_path)
    analysis_file = tmp_path / "analysis.json"
    html_file = tmp_path / "report.html"
    install_fake_providers()

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
    assert 'data-section="executive-brief"' in html
    assert "Key Signals" in html
    assert "Decision &amp; Action" in html
    assert "Priority Queue" in html
    assert "CVE-2021-44228" in html


def test_cli_report_html_rejects_compare_json(runner, tmp_path: Path) -> None:
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


def test_cli_report_html_rejects_invalid_json(normalize_output, runner, tmp_path: Path) -> None:
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
    assert "is not valid JSON" in normalize_output(result.stdout)


def test_cli_report_workbench_sarif_and_validation(
    install_fake_providers,
    runner,
    tmp_path: Path,
    write_input_file,
) -> None:
    input_file = write_input_file(tmp_path)
    analysis_file = tmp_path / "analysis.json"
    sarif_file = tmp_path / "workbench.sarif"
    validation_file = tmp_path / "sarif-validation.json"
    install_fake_providers()

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

    expectations = {
        "json": '"findings"',
        "markdown": "# Vulnerability Prioritization Summary",
        "html": "Priority Queue",
        "csv": "cve_id,priority,status",
    }
    for report_format, expected_text in expectations.items():
        output_file = tmp_path / f"workbench.{report_format}"
        result = runner.invoke(
            app,
            [
                "report",
                "workbench",
                "--input",
                str(analysis_file),
                "--output",
                str(output_file),
                "--format",
                report_format,
            ],
        )
        assert result.exit_code == 0
        assert expected_text in output_file.read_text(encoding="utf-8")

    report_result = runner.invoke(
        app,
        [
            "report",
            "workbench",
            "--input",
            str(analysis_file),
            "--output",
            str(sarif_file),
            "--format",
            "sarif",
        ],
    )
    assert report_result.exit_code == 0
    sarif_payload = json.loads(sarif_file.read_text(encoding="utf-8"))
    assert sarif_payload["version"] == "2.1.0"
    assert validate_sarif_payload(sarif_payload) == []
    run = sarif_payload["runs"][0]
    assert run["tool"]["driver"]["name"] == "vuln-prioritizer-workbench"
    rules = {rule["id"]: rule for rule in run["tool"]["driver"]["rules"]}
    log4shell = next(
        result for result in run["results"] if result["properties"]["cve"] == "CVE-2021-44228"
    )
    assert log4shell["ruleId"] == "vuln-prioritizer/cve-2021-44228"
    assert log4shell["properties"]["references"] == [
        "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
    ]
    assert log4shell["partialFingerprints"][SARIF_FINGERPRINT_KEY]
    assert (
        log4shell["partialFingerprints"][SARIF_WORKBENCH_FINGERPRINT_KEY]
        == log4shell["partialFingerprints"][SARIF_FINGERPRINT_KEY]
    )
    assert rules[log4shell["ruleId"]]["properties"]["security-severity"] == "10.0"

    validation_result = runner.invoke(
        app,
        [
            "report",
            "validate-sarif",
            "--input",
            str(sarif_file),
            "--output",
            str(validation_file),
            "--format",
            "json",
        ],
    )
    assert validation_result.exit_code == 0
    validation_payload = json.loads(validation_file.read_text(encoding="utf-8"))
    assert validation_payload["ok"] is True
    assert validation_payload["error_count"] == 0

    table_validation = runner.invoke(
        app,
        [
            "report",
            "validate-sarif",
            "--input",
            str(sarif_file),
        ],
    )
    assert table_validation.exit_code == 0
    assert "Validation result: passed" in table_validation.stdout


def test_cli_report_workbench_rejects_unknown_format(runner, tmp_path: Path) -> None:
    analysis_file = tmp_path / "analysis.json"
    analysis_file.write_text(
        json.dumps({"metadata": {"schema_version": "1.0.0"}, "findings": []}),
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "report",
            "workbench",
            "--input",
            str(analysis_file),
            "--output",
            str(tmp_path / "report.txt"),
            "--format",
            "xml",
        ],
    )

    assert result.exit_code == 2
    assert "Unsupported Workbench report format: xml" in result.stdout


def test_cli_report_validate_sarif_rejects_invalid_document(runner, tmp_path: Path) -> None:
    invalid_file = tmp_path / "invalid.sarif"
    invalid_file.write_text(json.dumps({"version": "2.1.0", "runs": []}), encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "report",
            "validate-sarif",
            "--input",
            str(invalid_file),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 1
    payload = json.loads(result.stdout)
    assert payload["ok"] is False
    assert "runs" in payload["errors"][0]

    table_result = runner.invoke(
        app,
        [
            "report",
            "validate-sarif",
            "--input",
            str(invalid_file),
        ],
    )
    assert table_result.exit_code == 1
    assert "Validation result: failed" in table_result.stdout


def test_checked_in_sarif_example_validates() -> None:
    example = Path(__file__).resolve().parents[3] / "docs/examples/example_results.sarif"
    payload = json.loads(example.read_text(encoding="utf-8"))

    assert validate_sarif_payload(payload) == []
    assert payload["runs"][0]["tool"]["driver"]["rules"]
    assert all(
        result["ruleId"] == f"vuln-prioritizer/{result['properties']['cve'].lower()}"
        for result in payload["runs"][0]["results"]
    )


def test_sarif_validation_requires_declared_rules_and_fingerprints() -> None:
    payload = {
        "version": "2.1.0",
        "runs": [
            {},
            "not-a-run",
            {
                "tool": {"driver": {"name": "vuln-prioritizer", "rules": [{"id": "declared"}]}},
                "results": [
                    {
                        "ruleId": "undeclared",
                        "level": "warning",
                        "message": {"text": "CVE finding"},
                        "locations": [
                            {"physicalLocation": {"artifactLocation": {"uri": "sbom.json"}}}
                        ],
                        "properties": {
                            "cve": "CVE-2024-0001",
                            "references": ["not-a-url"],
                        },
                    },
                    "not-a-result",
                ],
            },
        ],
    }

    errors = validate_sarif_payload(payload)

    assert any("partialFingerprints" in error for error in errors)
    assert any("properties.references.0" in error and "HTTP(S)" in error for error in errors)
    assert any("is not declared in tool.driver.rules" in error for error in errors)


def test_sarif_validation_allows_foreign_tool_properties_without_cve() -> None:
    payload = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "other-tool", "rules": [{"id": "other-rule"}]}},
                "results": [
                    {
                        "ruleId": "other-rule",
                        "level": "warning",
                        "message": {"text": "Other SARIF finding"},
                        "locations": [
                            {"physicalLocation": {"artifactLocation": {"uri": "src/app.py"}}}
                        ],
                        "partialFingerprints": {"other/v1": "stable"},
                    }
                ],
            }
        ],
    }

    assert validate_sarif_payload(payload) == []


def test_workbench_sarif_validates_with_no_findings() -> None:
    payload = {
        "metadata": {"schema_version": "1.1.0", "input_path": "empty.csv"},
        "findings": [],
    }

    sarif_payload = json.loads(generate_workbench_sarif(payload))

    assert sarif_payload["runs"][0]["tool"]["driver"]["rules"] == []
    assert sarif_payload["runs"][0]["results"] == []
    assert validate_sarif_payload(sarif_payload) == []


def test_workbench_sarif_filters_non_http_references() -> None:
    payload = {
        "metadata": {"schema_version": "1.1.0", "input_path": "findings.csv"},
        "findings": [
            {
                "cve_id": "CVE-2024-0001",
                "priority_label": "High",
                "cvss_base_score": 7.5,
                "provider_evidence": {
                    "nvd": {
                        "references": [
                            "GHSA-0000",
                            "https://vendor.example/advisory",
                            "https://vendor.example/advisory",
                            "https://github.com/example/CVE-2024-0001-poc",
                            "https://github.com/rapid7/metasploit-framework/pull/1",
                            "https://github.com/vendor/package/security/advisories/GHSA-0000",
                        ]
                    }
                },
                "defensive_contexts": [
                    {
                        "source": "osv",
                        "url": "OSV-2024-0001",
                        "references": ["https://osv.dev/vulnerability/OSV-2024-0001"],
                    }
                ],
                "provenance": {"affected_paths": ["requirements.txt"]},
            }
        ],
    }

    sarif_payload = json.loads(generate_workbench_sarif(payload))
    references = sarif_payload["runs"][0]["results"][0]["properties"]["references"]

    assert references == [
        "https://nvd.nist.gov/vuln/detail/CVE-2024-0001",
        "https://vendor.example/advisory",
        "https://github.com/vendor/package/security/advisories/GHSA-0000",
        "https://osv.dev/vulnerability/OSV-2024-0001",
    ]
    assert validate_sarif_payload(sarif_payload) == []


def test_workbench_report_private_format_helpers_handle_edge_cases() -> None:
    assert _csv_safe_cell("=cmd") == "'=cmd"
    assert _csv_safe_cell("\tformula") == "'\tformula"
    assert _first_occurrence_value({"occurrences": ["bad", {"path": "service/pom.xml"}]}, "path")
    assert _first_occurrence_value({}, "path") == ""
    assert _finding_status_label({"suppressed_by_vex": True}) == "suppressed"
    assert _finding_status_label({"waived": True}) == "accepted"
    assert _vex_statuses_label({}) == ""
    assert _vex_statuses_label({"vex_statuses": {"fixed": 1, "affected": 2}}) == (
        "affected:2;fixed:1"
    )


def test_cli_workbench_csv_header_matches_api_report_contract() -> None:
    payload = {
        "metadata": {"schema_version": "1.1.0", "input_path": "empty.csv"},
        "findings": [],
    }

    header = generate_findings_csv(payload).splitlines()[0].split(",")

    assert header == CSV_FINDINGS_COLUMNS


def test_cli_report_validate_sarif_rejects_json_array(runner, tmp_path: Path) -> None:
    invalid_file = tmp_path / "array.sarif"
    invalid_file.write_text("[]", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "report",
            "validate-sarif",
            "--input",
            str(invalid_file),
        ],
    )

    assert result.exit_code == 2
    assert "must contain a JSON object." in " ".join(result.stdout.split())


def test_cli_report_validate_sarif_rejects_bad_json(runner, tmp_path: Path) -> None:
    invalid_file = tmp_path / "invalid-json.sarif"
    invalid_file.write_text("{not-json", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "report",
            "validate-sarif",
            "--input",
            str(invalid_file),
        ],
    )

    assert result.exit_code == 2
    assert "is not valid JSON" in result.stdout

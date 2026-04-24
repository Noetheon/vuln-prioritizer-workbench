from __future__ import annotations

import json
from pathlib import Path

from vuln_prioritizer.cli import app


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
    assert sarif_payload["runs"][0]["tool"]["driver"]["name"] == "vuln-prioritizer-workbench"

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

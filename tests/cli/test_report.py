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
    assert "<h1>vuln-prioritizer Executive Report</h1>" in html
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

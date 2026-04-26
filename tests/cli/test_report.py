from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

from vuln_prioritizer.cli import app
from vuln_prioritizer.sarif_validation import validate_sarif_payload
from vuln_prioritizer.services.workbench_reports import (
    _analysis_payload_with_current_lifecycle,
    _csv_safe_cell,
    _finding_status_label,
    _first_occurrence_value,
    _vex_statuses_label,
)


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
                    },
                    "not-a-result",
                ],
            },
        ],
    }

    errors = validate_sarif_payload(payload)

    assert any("partialFingerprints" in error for error in errors)
    assert any("is not declared in tool.driver.rules" in error for error in errors)


def test_workbench_report_lifecycle_overlay_uses_id_and_stable_identity() -> None:
    class FakeRepo:
        def list_project_findings(self, project_id: str) -> list[SimpleNamespace]:
            assert project_id == "project-1"
            return [
                SimpleNamespace(
                    id="finding-1",
                    cve_id="CVE-2024-0001",
                    component=None,
                    asset=None,
                    status="fixed",
                    status_history=[
                        SimpleNamespace(
                            id="history-1",
                            finding_id="finding-1",
                            previous_status="open",
                            new_status="fixed",
                            actor="tester",
                            reason="patched",
                            created_at=datetime(2026, 4, 25, tzinfo=UTC),
                        )
                    ],
                ),
                SimpleNamespace(
                    id="finding-2",
                    cve_id="CVE-2024-0002",
                    component=SimpleNamespace(name="openssl", version="3.0.0"),
                    asset=SimpleNamespace(asset_id="asset-api"),
                    status="accepted",
                    status_history=[],
                ),
            ]

    payload = {
        "metadata": {"schema_version": "1.1.0"},
        "findings": [
            {"cve_id": "CVE-2024-0001", "workbench_finding_id": "finding-1", "status": "open"},
            {
                "cve_id": "CVE-2024-0002",
                "status": "open",
                "provenance": {
                    "occurrences": [
                        {
                            "component_name": "openssl",
                            "component_version": "3.0.0",
                            "asset_id": "asset-api",
                        }
                    ]
                },
            },
            "not-a-finding",
            {"cve_id": "CVE-2024-0003", "status": "open"},
        ],
    }

    overlaid = _analysis_payload_with_current_lifecycle(FakeRepo(), payload, "project-1")  # type: ignore[arg-type]

    assert overlaid["findings"][0]["status"] == "fixed"
    assert overlaid["findings"][0]["status_history"][0]["new_status"] == "fixed"
    assert overlaid["findings"][1]["status"] == "accepted"
    assert overlaid["findings"][3]["status"] == "open"
    assert payload["findings"][0]["status"] == "open"
    assert (
        _analysis_payload_with_current_lifecycle(
            FakeRepo(),  # type: ignore[arg-type]
            {"metadata": {}, "findings": "invalid"},
            "project-1",
        )["findings"]
        == "invalid"
    )


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
    assert "must contain a JSON" in result.stdout
    assert "object." in result.stdout


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

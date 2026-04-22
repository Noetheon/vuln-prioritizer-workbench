from __future__ import annotations

import json
from pathlib import Path

from vuln_prioritizer.cli import app


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

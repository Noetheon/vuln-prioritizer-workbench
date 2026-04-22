from __future__ import annotations

import json
from pathlib import Path

from vuln_prioritizer.cli import app


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

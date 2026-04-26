from __future__ import annotations

import json
from pathlib import Path

from vuln_prioritizer.cli import app


def test_cli_input_validate_json_reports_local_inputs_and_context(
    runner,
    tmp_path: Path,
) -> None:
    input_file = tmp_path / "cves.txt"
    asset_file = tmp_path / "assets.csv"
    vex_file = tmp_path / "vex.json"
    input_file.write_text("CVE-2021-44228\nnot-a-cve\n", encoding="utf-8")
    asset_file.write_text(
        "\n".join(
            [
                "target_kind,target_ref,asset_id,criticality,business_service",
                "generic,,ignored,low,ignored",
                "generic,service-a,asset-a,high,payments",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    vex_file.write_text(
        json.dumps(
            {
                "statements": [
                    {
                        "vulnerability": {"name": "CVE-2021-44228"},
                        "status": "under_investigation",
                        "products": [{"identifiers": {"purl": "pkg:maven/log4j/log4j@2.14.0"}}],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "input",
            "validate",
            "--input",
            str(input_file),
            "--asset-context",
            str(asset_file),
            "--vex-file",
            str(vex_file),
            "--target-kind",
            "generic",
            "--target-ref",
            "service-a",
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["metadata"]["command"] == "input validate"
    assert payload["summary"]["total_rows"] == 2
    assert payload["summary"]["unique_cves"] == 1
    assert payload["summary"]["asset_context_rules"] == 1
    assert payload["summary"]["vex_statement_count"] == 1
    assert payload["vex"]["statuses"] == {"under_investigation": 1}
    assert any("Ignored invalid CVE identifier" in warning for warning in payload["warnings"])


def test_cli_input_validate_rejects_empty_scope(runner) -> None:
    result = runner.invoke(app, ["input", "validate"])

    assert result.exit_code == 2
    assert "requires --input" in result.stdout
    assert "--vex-file" in result.stdout


def test_cli_input_validate_counts_standalone_asset_context_warnings(
    runner,
    tmp_path: Path,
) -> None:
    asset_file = tmp_path / "assets.csv"
    asset_file.write_text(
        "\n".join(
            [
                "target_kind,target_ref,asset_id,criticality,business_service",
                "repository,repo-a,asset-a,high,payments",
                "repository,repo-a,asset-b,critical,payments",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "input",
            "validate",
            "--asset-context",
            str(asset_file),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["summary"]["ok"] is False
    assert payload["summary"]["warning_count"] == 1
    assert payload["warnings"] == payload["asset_context"]["warnings"]


def test_cli_input_validate_strict_fails_on_warnings_with_json_stdout(
    runner,
    tmp_path: Path,
) -> None:
    input_file = tmp_path / "cves.txt"
    input_file.write_text("CVE-2024-0001\nnot-a-cve\n", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "input",
            "validate",
            "--input",
            str(input_file),
            "--format",
            "json",
            "--strict",
        ],
    )

    assert result.exit_code == 1
    payload = json.loads(result.stdout)
    assert payload["summary"]["ok"] is False
    assert payload["summary"]["warning_count"] == 1


def test_cli_input_validate_strict_writes_output_before_failing(
    runner,
    tmp_path: Path,
) -> None:
    input_file = tmp_path / "generic-occurrences.csv"
    output_file = tmp_path / "input-validation.json"
    input_file.write_text(
        "\n".join(
            [
                "cve,component,version,fix_version,target_kind,target,criticality",
                "CVE-2024-0001,django,4.2.0,4.2.8,repository,backend,unknown",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "input",
            "validate",
            "--input",
            str(input_file),
            "--input-format",
            "generic-occurrence-csv",
            "--output",
            str(output_file),
            "--format",
            "json",
            "--strict",
        ],
    )

    assert result.exit_code == 1
    payload = json.loads(output_file.read_text(encoding="utf-8"))
    assert payload["summary"]["ok"] is False
    assert "unknown asset criticality" in "\n".join(payload["warnings"])


def test_cli_input_inspect_emits_normalized_occurrences_without_provider_lookup(
    runner,
    tmp_path: Path,
) -> None:
    input_file = tmp_path / "generic-occurrences.csv"
    output_file = tmp_path / "normalized.json"
    input_file.write_text(
        "\n".join(
            [
                "cve,component,version,target_kind,target_ref,asset_id,owner,business_service",
                "CVE-2024-3094,xz,5.6.0,repository,backend,asset-a,platform,payments",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "input",
            "inspect",
            "--input",
            str(input_file),
            "--input-format",
            "generic-occurrence-csv",
            "--output",
            str(output_file),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(output_file.read_text(encoding="utf-8"))
    assert payload["metadata"]["command"] == "input inspect"
    assert payload["summary"]["occurrence_count"] == 1
    assert payload["unique_cves"] == ["CVE-2024-3094"]
    assert payload["occurrences"][0]["component_name"] == "xz"
    assert payload["occurrences"][0]["asset_owner"] == "platform"
    assert "provider_evidence" not in payload["occurrences"][0]


def test_cli_input_normalize_alias_matches_inspect_contract(runner, tmp_path: Path) -> None:
    input_file = tmp_path / "cves.txt"
    input_file.write_text("CVE-2021-44228\n", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "input",
            "normalize",
            "--input",
            str(input_file),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["metadata"]["command"] == "input normalize"
    assert payload["summary"]["unique_cves"] == 1
    assert payload["occurrences"][0]["cve_id"] == "CVE-2021-44228"

from __future__ import annotations

import json
from pathlib import Path

from paths import DATA_ROOT
from typer.testing import CliRunner

from vuln_prioritizer.cli import app


def _raw_json_payload(stdout: str) -> dict:
    payload = json.loads(stdout)
    assert stdout.lstrip().startswith("{")
    assert "Vulnerability Prioritization" not in stdout
    assert "Wrote json output" not in stdout
    return payload


def test_analyze_json_without_output_emits_only_json_stdout(
    install_fake_providers,
    runner: CliRunner,
    tmp_path: Path,
    write_input_file,
) -> None:
    input_file = write_input_file(tmp_path)
    summary_file = tmp_path / "summary.md"
    install_fake_providers()

    result = runner.invoke(
        app,
        [
            "--no-config",
            "analyze",
            "--input",
            str(input_file),
            "--format",
            "json",
            "--summary-output",
            str(summary_file),
            "--summary-template",
            "compact",
        ],
    )

    assert result.exit_code == 0
    payload = _raw_json_payload(result.stdout)
    assert payload["metadata"]["output_path"] is None
    assert payload["findings"]
    assert summary_file.read_text(encoding="utf-8").startswith(
        "# Vulnerability Prioritization Summary"
    )


def test_compare_json_without_output_emits_only_json_stdout(
    install_fake_providers,
    runner: CliRunner,
    tmp_path: Path,
    write_input_file,
) -> None:
    input_file = write_input_file(tmp_path)
    install_fake_providers()

    result = runner.invoke(
        app,
        [
            "--no-config",
            "compare",
            "--input",
            str(input_file),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0
    payload = _raw_json_payload(result.stdout)
    assert payload["metadata"]["output_path"] is None
    assert payload["comparisons"]


def test_explain_json_without_output_emits_only_json_stdout(
    install_fake_providers,
    runner: CliRunner,
) -> None:
    install_fake_providers()

    result = runner.invoke(
        app,
        [
            "--no-config",
            "explain",
            "--cve",
            "CVE-2021-44228",
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0
    payload = _raw_json_payload(result.stdout)
    assert payload["finding"]["cve_id"] == "CVE-2021-44228"


def test_doctor_json_without_output_emits_only_json_stdout(
    runner: CliRunner,
    tmp_path: Path,
) -> None:
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()

    result = runner.invoke(
        app,
        [
            "--no-config",
            "doctor",
            "--cache-dir",
            str(cache_dir),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0
    payload = _raw_json_payload(result.stdout)
    assert payload["schema_version"] == "1.2.0"
    assert payload["summary"]["overall_status"] == "ok"


def test_attack_json_commands_without_output_emit_only_json_stdout(
    attack_root: Path,
    runner: CliRunner,
) -> None:
    mapping_file = attack_root / "ctid_kev_enterprise_2025-07-28_attack-16.1_subset.json"
    metadata_file = attack_root / "attack_techniques_enterprise_16.1_subset.json"

    validate_result = runner.invoke(
        app,
        [
            "--no-config",
            "attack",
            "validate",
            "--attack-mapping-file",
            str(mapping_file),
            "--attack-technique-metadata-file",
            str(metadata_file),
            "--format",
            "json",
        ],
    )
    coverage_result = runner.invoke(
        app,
        [
            "--no-config",
            "attack",
            "coverage",
            "--input",
            str(DATA_ROOT / "sample_cves_mixed.txt"),
            "--attack-mapping-file",
            str(mapping_file),
            "--attack-technique-metadata-file",
            str(metadata_file),
            "--format",
            "json",
        ],
    )

    assert validate_result.exit_code == 0
    assert coverage_result.exit_code == 0
    assert _raw_json_payload(validate_result.stdout)["source"] == "ctid-mappings-explorer"
    assert _raw_json_payload(coverage_result.stdout)["summary"]["mapped_cves"] == 3


def test_input_validate_json_without_output_emits_only_json_stdout(
    runner: CliRunner,
    tmp_path: Path,
) -> None:
    input_file = tmp_path / "cves.txt"
    input_file.write_text("CVE-2024-0001\n", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "--no-config",
            "input",
            "validate",
            "--input",
            str(input_file),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0
    payload = _raw_json_payload(result.stdout)
    assert payload["metadata"]["command"] == "input validate"
    assert payload["summary"]["unique_cves"] == 1


def test_snapshot_rollup_state_and_report_json_stdout_contracts(
    install_fake_providers,
    runner: CliRunner,
    tmp_path: Path,
    write_input_file,
) -> None:
    input_file = write_input_file(tmp_path)
    analysis_file = tmp_path / "analysis.json"
    snapshot_file = tmp_path / "snapshot.json"
    bundle_file = tmp_path / "evidence.zip"
    db_path = tmp_path / "state.db"
    install_fake_providers()

    analysis_result = runner.invoke(
        app,
        [
            "--no-config",
            "analyze",
            "--input",
            str(input_file),
            "--output",
            str(analysis_file),
            "--format",
            "json",
        ],
    )
    snapshot_result = runner.invoke(
        app,
        [
            "--no-config",
            "snapshot",
            "create",
            "--input",
            str(input_file),
            "--output",
            str(snapshot_file),
            "--format",
            "json",
        ],
    )
    bundle_result = runner.invoke(
        app,
        [
            "--no-config",
            "report",
            "evidence-bundle",
            "--input",
            str(analysis_file),
            "--output",
            str(bundle_file),
        ],
    )

    assert analysis_result.exit_code == 0
    assert snapshot_result.exit_code == 0
    assert bundle_result.exit_code == 0

    diff_result = runner.invoke(
        app,
        [
            "--no-config",
            "snapshot",
            "diff",
            "--before",
            str(snapshot_file),
            "--after",
            str(snapshot_file),
            "--format",
            "json",
        ],
    )
    rollup_result = runner.invoke(
        app,
        [
            "--no-config",
            "rollup",
            "--input",
            str(analysis_file),
            "--format",
            "json",
        ],
    )
    state_init_result = runner.invoke(
        app,
        [
            "--no-config",
            "state",
            "init",
            "--db",
            str(db_path),
            "--format",
            "json",
        ],
    )
    state_import_result = runner.invoke(
        app,
        [
            "--no-config",
            "state",
            "import-snapshot",
            "--db",
            str(db_path),
            "--input",
            str(snapshot_file),
            "--format",
            "json",
        ],
    )
    verify_result = runner.invoke(
        app,
        [
            "--no-config",
            "report",
            "verify-evidence-bundle",
            "--input",
            str(bundle_file),
            "--format",
            "json",
        ],
    )

    assert diff_result.exit_code == 0
    assert rollup_result.exit_code == 0
    assert state_init_result.exit_code == 0
    assert state_import_result.exit_code == 0
    assert verify_result.exit_code == 0
    assert _raw_json_payload(diff_result.stdout)["summary"]["unchanged"] > 0
    assert _raw_json_payload(rollup_result.stdout)["buckets"]
    assert _raw_json_payload(state_init_result.stdout)["summary"]["initialized"] is True
    assert _raw_json_payload(state_import_result.stdout)["summary"]["imported"] is True
    assert _raw_json_payload(verify_result.stdout)["summary"]["ok"] is True

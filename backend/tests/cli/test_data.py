from __future__ import annotations

import json
from pathlib import Path

from vuln_prioritizer.cli import app


def test_cli_data_status_shows_cache_and_attack_metadata(
    attack_root,
    runner,
    tmp_path: Path,
) -> None:
    result = runner.invoke(
        app,
        [
            "data",
            "status",
            "--cache-dir",
            str(tmp_path / "cache"),
            "--attack-mapping-file",
            str(attack_root / "ctid_kev_enterprise_2025-07-28_attack-16.1_subset.json"),
            "--attack-technique-metadata-file",
            str(attack_root / "attack_techniques_enterprise_16.1_subset.json"),
        ],
    )

    assert result.exit_code == 0
    assert "Data Status" in result.stdout
    assert "Cache directory:" in result.stdout
    assert "ATT&CK source:" in result.stdout
    assert "ATT&CK version:" in result.stdout


def test_cli_data_status_json_stdout_is_raw_json(
    attack_root,
    runner,
    tmp_path: Path,
) -> None:
    result = runner.invoke(
        app,
        [
            "data",
            "status",
            "--cache-dir",
            str(tmp_path / "cache"),
            "--attack-mapping-file",
            str(attack_root / "ctid_kev_enterprise_2025-07-28_attack-16.1_subset.json"),
            "--attack-technique-metadata-file",
            str(attack_root / "attack_techniques_enterprise_16.1_subset.json"),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["metadata"]["command"] == "data status"
    assert payload["metadata"]["output_format"] == "json"
    assert payload["attack"]["source"] == "ctid-mappings-explorer"
    assert "Data Status" not in result.stdout


def test_cli_data_status_rejects_quiet_in_table_mode(runner, tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "data",
            "status",
            "--cache-dir",
            str(tmp_path / "cache"),
            "--quiet",
        ],
    )

    assert result.exit_code == 2
    assert "--quiet can only be used together with --format json." in result.stdout

from __future__ import annotations

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

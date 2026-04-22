from __future__ import annotations

import json
from pathlib import Path

from vuln_prioritizer import __version__
from vuln_prioritizer.cli import app


def test_cli_analyze_uses_discovered_runtime_config_and_no_config_disables_it(
    install_fake_providers,
    runner,
    monkeypatch,
    tmp_path: Path,
    write_input_file,
) -> None:
    input_file = write_input_file(tmp_path)
    configured_output = tmp_path / "configured.json"
    no_config_output = tmp_path / "no-config.json"
    (tmp_path / "vuln-prioritizer.yml").write_text(
        "\n".join(
            [
                "version: 1",
                "defaults:",
                "  policy_profile: enterprise",
                "commands:",
                "  analyze:",
                "    priority:",
                "      - high",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    install_fake_providers()
    monkeypatch.chdir(tmp_path)

    configured = runner.invoke(
        app,
        [
            "analyze",
            "--input",
            str(input_file),
            "--output",
            str(configured_output),
            "--format",
            "json",
        ],
    )

    assert configured.exit_code == 0
    configured_payload = json.loads(configured_output.read_text(encoding="utf-8"))
    assert configured_payload["metadata"]["policy_profile"] == "enterprise"
    assert configured_payload["metadata"]["active_filters"] == ["priority=High"]

    no_config = runner.invoke(
        app,
        [
            "--no-config",
            "analyze",
            "--input",
            str(input_file),
            "--output",
            str(no_config_output),
            "--format",
            "json",
        ],
    )

    assert no_config.exit_code == 0
    no_config_payload = json.loads(no_config_output.read_text(encoding="utf-8"))
    assert no_config_payload["metadata"]["policy_profile"] == "default"
    assert no_config_payload["metadata"]["active_filters"] == []


def test_cli_root_version_reports_package_version_without_loading_runtime_config(
    runner,
    monkeypatch,
    tmp_path: Path,
) -> None:
    (tmp_path / "vuln-prioritizer.yml").write_text("version: [broken\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(app, ["--version"])

    assert result.exit_code == 0
    assert result.stdout.strip() == f"vuln-prioritizer {__version__}"

from __future__ import annotations

from pathlib import Path

import pytest

from vuln_prioritizer.runtime_config import (
    CONFIG_FILENAME,
    build_cli_default_map,
    discover_runtime_config,
    load_runtime_config,
)


def test_discover_runtime_config_walks_upward(tmp_path: Path) -> None:
    root = tmp_path / "workspace"
    nested = root / "a" / "b"
    nested.mkdir(parents=True)
    config_file = root / CONFIG_FILENAME
    config_file.write_text("version: 1\n", encoding="utf-8")

    assert discover_runtime_config(nested) == config_file


def test_load_runtime_config_resolves_relative_paths_and_builds_default_map(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "assets.csv").write_text("target_kind,target_ref,asset_id\n", encoding="utf-8")
    (project / "rules").mkdir()
    (project / "rules" / "policy.yml").write_text("profiles: {}\n", encoding="utf-8")
    (project / "rules" / "waivers.yml").write_text("waivers: []\n", encoding="utf-8")
    (project / "vex.json").write_text('{"statements":[]}\n', encoding="utf-8")

    config_file = project / CONFIG_FILENAME
    config_file.write_text(
        "\n".join(
            [
                "version: 1",
                "defaults:",
                "  asset_context: assets.csv",
                "  policy_file: rules/policy.yml",
                "  waiver_file: rules/waivers.yml",
                "  vex_file:",
                "    - vex.json",
                "  cache_dir: .cache/runtime",
                "  policy_profile: enterprise",
                "commands:",
                "  analyze:",
                "    priority:",
                "      - high",
                "    hide_waived: true",
                "  snapshot:",
                "    diff:",
                "      include_unchanged: true",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    loaded = load_runtime_config(config_file)
    default_map = build_cli_default_map(loaded)

    assert loaded.document.defaults.asset_context == str((project / "assets.csv").resolve())
    assert loaded.document.defaults.policy_file == str((project / "rules" / "policy.yml").resolve())
    assert loaded.document.defaults.waiver_file == str(
        (project / "rules" / "waivers.yml").resolve()
    )
    assert loaded.document.defaults.vex_file == [str((project / "vex.json").resolve())]
    assert loaded.document.defaults.cache_dir == str((project / ".cache" / "runtime").resolve())
    assert default_map["analyze"]["policy_profile"] == "enterprise"
    assert default_map["analyze"]["waiver_file"] == str(
        (project / "rules" / "waivers.yml").resolve()
    )
    assert default_map["analyze"]["priority"] == ["high"]
    assert default_map["analyze"]["hide_waived"] is True
    assert default_map["doctor"]["waiver_file"] == str(
        (project / "rules" / "waivers.yml").resolve()
    )
    assert default_map["snapshot"]["diff"]["include_unchanged"] is True


def test_load_runtime_config_rejects_invalid_yaml(tmp_path: Path) -> None:
    config_file = tmp_path / CONFIG_FILENAME
    config_file.write_text("version: [broken\n", encoding="utf-8")

    with pytest.raises(ValueError, match="not valid YAML"):
        load_runtime_config(config_file)


def test_load_runtime_config_rejects_unreadable_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_file = tmp_path / CONFIG_FILENAME
    config_file.write_text("version: 1\n", encoding="utf-8")
    original_read_text = Path.read_text

    def _raise_permission_error(self: Path, *args: object, **kwargs: object) -> str:
        if self == config_file:
            raise PermissionError("permission denied")
        return original_read_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", _raise_permission_error)

    with pytest.raises(ValueError, match="could not be read"):
        load_runtime_config(config_file)

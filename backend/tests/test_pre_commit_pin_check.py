from __future__ import annotations

import importlib.util
from pathlib import Path

from paths import REPO_ROOT


def _load_pin_checker():
    script = REPO_ROOT / "scripts" / "check_pre_commit_pins.py"
    spec = importlib.util.spec_from_file_location("check_pre_commit_pins", script)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_pre_commit_pin_check_accepts_current_config() -> None:
    checker = _load_pin_checker()

    assert checker.main() == 0


def test_pre_commit_pin_check_rejects_mutable_remote_refs(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    checker = _load_pin_checker()
    config = tmp_path / ".pre-commit-config.yaml"
    config.write_text(
        """
repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v5.0.0
    hooks:
      - id: check-yaml
""".strip(),
        encoding="utf-8",
    )
    monkeypatch.setattr(checker, "PRE_COMMIT_CONFIG", config)

    assert checker.main() == 1
    assert "must use a 40-character commit SHA rev" in capsys.readouterr().err

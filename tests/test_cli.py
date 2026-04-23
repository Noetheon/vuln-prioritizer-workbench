from __future__ import annotations

import sys
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
if str(TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_DIR))

import _cli_helpers  # noqa: E402

runner = _cli_helpers.runner


def _install_fake_providers(monkeypatch: object) -> None:
    _cli_helpers.install_fake_providers(monkeypatch)


def _write_input_file(tmp_path: Path) -> Path:
    return _cli_helpers.write_input_file(tmp_path)

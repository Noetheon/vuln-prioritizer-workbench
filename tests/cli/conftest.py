from __future__ import annotations

import re
from collections.abc import Callable
from pathlib import Path

import pytest
from _cli_helpers import (
    install_fake_providers as _install_fake_providers,
)
from _cli_helpers import (
    runner as _runner,
)
from _cli_helpers import (
    write_input_file as _write_input_file,
)
from typer.testing import CliRunner

from vuln_prioritizer.cli import app

ANSI_ESCAPE_PATTERN = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


@pytest.fixture
def runner() -> CliRunner:
    return _runner


@pytest.fixture
def fixture_root() -> Path:
    return Path(__file__).resolve().parents[2] / "data" / "input_fixtures"


@pytest.fixture
def attack_root() -> Path:
    return Path(__file__).resolve().parents[2] / "data" / "attack"


@pytest.fixture
def format_help_block(runner: CliRunner) -> Callable[..., str]:
    def _format_help_block(*args: str) -> str:
        result = runner.invoke(app, [*args, "--help"], env={"COLUMNS": "200", "LINES": "40"})

        assert result.exit_code == 0
        return result.stdout

    return _format_help_block


@pytest.fixture
def normalize_output() -> Callable[[str], str]:
    def _normalize_output(text: str) -> str:
        stripped = ANSI_ESCAPE_PATTERN.sub("", text)
        return re.sub(r"\s+", " ", stripped).strip()

    return _normalize_output


@pytest.fixture
def compact_output() -> Callable[[str], str]:
    def _compact_output(text: str) -> str:
        stripped = ANSI_ESCAPE_PATTERN.sub("", text)
        return re.sub(r"\s+", "", stripped)

    return _compact_output


@pytest.fixture
def write_input_file() -> Callable[[Path], Path]:
    return _write_input_file


@pytest.fixture
def write_waiver_file() -> Callable[..., Path]:
    def _write_waiver_file(
        tmp_path: Path,
        *,
        cve_id: str,
        owner: str,
        reason: str,
        expires_on: str = "2027-12-31",
        review_on: str | None = None,
    ) -> Path:
        waiver_file = tmp_path / "waivers.yml"
        lines = [
            "waivers:",
            "  - id: waiver-1",
            f"    cve_id: {cve_id}",
            f"    owner: {owner}",
            f"    reason: {reason}",
            f"    expires_on: {expires_on}",
        ]
        if review_on is not None:
            lines.append(f"    review_on: {review_on}")
        waiver_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return waiver_file

    return _write_waiver_file


@pytest.fixture
def install_fake_providers(monkeypatch: pytest.MonkeyPatch) -> Callable[[], None]:
    def _install() -> None:
        _install_fake_providers(monkeypatch)

    return _install

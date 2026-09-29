from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import uvicorn

from app.cli import main
from app.core.local_config import (
    LocalConfigError,
    apply_local_config_environment,
    load_local_config,
)


@pytest.fixture(autouse=True)
def _restore_process_environment() -> Iterator[None]:
    original = dict(os.environ)
    try:
        yield
    finally:
        os.environ.clear()
        os.environ.update(original)


def _write(path: Path, text: str, mode: int = 0o600) -> Path:
    path.write_text(text, encoding="utf-8")
    path.chmod(mode)
    return path


def test_config_values_fill_only_what_flags_and_environment_leave_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    data = tmp_path / "data"
    data.mkdir()
    _write(
        data / "vpw.toml",
        """
[serve]
port = 9911
open_browser = false
log_level = "warning"

[providers]
nvd_api_key = "key-from-file"
github_token = "token-from-file"

[imports]
max_upload_mb = 40
grype_executable = "/opt/grype/bin/grype"
""",
    )
    runs: list[dict[str, Any]] = []
    monkeypatch.setattr(uvicorn, "run", lambda _app, **kwargs: runs.append(kwargs))
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    monkeypatch.setenv("GITHUB_TOKEN", "token-from-environment")
    monkeypatch.setenv("MAX_UPLOAD_MB", "30")

    assert main(["serve", "--data-dir", str(data)]) == 0

    assert runs[-1]["port"] == 9911
    assert runs[-1]["log_level"] == "warning"
    assert runs[-1]["host"] == "127.0.0.1"
    assert os.environ["NVD_API_KEY"] == "key-from-file"
    assert os.environ["GITHUB_TOKEN"] == "token-from-environment"
    assert os.environ["MAX_UPLOAD_MB"] == "30"
    assert os.environ["SBOM_GRYPE_EXECUTABLE"] == "/opt/grype/bin/grype"
    output = capsys.readouterr().out
    assert f"Settings: {data / 'vpw.toml'}" in output
    assert "key-from-file" not in output

    assert main(["serve", "--data-dir", str(data), "--port", "9922", "--log-level", "debug"]) == 0
    assert (runs[-1]["port"], runs[-1]["log_level"]) == (9922, "debug")

    with pytest.raises(SystemExit, match="Config file not found"):
        main(["serve", "--data-dir", str(data), "--config", str(tmp_path / "missing.toml")])


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("[serve]\nprot = 1\n", r"Unknown setting \[serve\].prot"),
        ("[server]\nport = 1\n", r"Unknown section \[server\]"),
        ('[serve]\nport = "8765"\n', r"\[serve\].port must be a int"),
        ("[serve]\nopen_browser = 1\n", r"\[serve\].open_browser must be a bool"),
        ("[serve]\nport = true\n", r"\[serve\].port must be a int"),
        ("[serve]\nport = 70000\n", "between 1 and 65535"),
        ('[serve]\nlog_level = "loud"\n', "log_level must be one of"),
        ("[imports]\nmax_upload_mb = 0\n", "must be positive"),
        ("serve = 1\n", r"\[serve\] must be a table"),
        ("[serve\n", "not valid TOML"),
    ],
)
def test_invalid_config_files_are_rejected(tmp_path: Path, text: str, message: str) -> None:
    with pytest.raises(LocalConfigError, match=message):
        load_local_config(_write(tmp_path / "vpw.toml", text))


def test_missing_optional_config_is_empty_and_secrets_warn_when_shared(tmp_path: Path) -> None:
    assert load_local_config(tmp_path / "absent.toml").path is None
    shared = _write(tmp_path / "vpw.toml", '[providers]\nnvd_api_key = "k"\n', mode=0o644)

    config = load_local_config(shared)

    if os.name != "nt":
        assert config.warnings and "chmod 600" in config.warnings[0]
    environment: dict[str, str] = {"WORKBENCH_NVD_API_KEY_ENV": "CUSTOM_NVD_KEY"}
    assert apply_local_config_environment(config, environment) == ["CUSTOM_NVD_KEY"]
    assert environment["CUSTOM_NVD_KEY"] == "k"
    blank = load_local_config(_write(tmp_path / "blank.toml", '[providers]\nnvd_api_key = " "\n'))
    assert blank.secrets == {}
    assert blank.warnings == ()

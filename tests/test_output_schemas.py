from __future__ import annotations

import json
import sys
from pathlib import Path

import jsonschema
from typer.testing import CliRunner

TESTS_DIR = Path(__file__).resolve().parent
if str(TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_DIR))

from test_cli import _install_fake_providers, _write_input_file  # noqa: E402

from vuln_prioritizer.cli import app  # noqa: E402

runner = CliRunner()
SCHEMA_ROOT = Path(__file__).resolve().parents[1] / "docs" / "schemas"


def _load_schema(name: str) -> dict:
    return json.loads((SCHEMA_ROOT / name).read_text(encoding="utf-8"))


def test_analysis_json_matches_published_schema(monkeypatch, tmp_path: Path) -> None:
    input_file = _write_input_file(tmp_path)
    output_file = tmp_path / "analysis.json"
    _install_fake_providers(monkeypatch)

    result = runner.invoke(
        app,
        [
            "analyze",
            "--input",
            str(input_file),
            "--output",
            str(output_file),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(output_file.read_text(encoding="utf-8"))
    jsonschema.validate(payload, _load_schema("analysis-report.schema.json"))


def test_compare_json_matches_published_schema(monkeypatch, tmp_path: Path) -> None:
    input_file = _write_input_file(tmp_path)
    output_file = tmp_path / "compare.json"
    _install_fake_providers(monkeypatch)

    result = runner.invoke(
        app,
        [
            "compare",
            "--input",
            str(input_file),
            "--output",
            str(output_file),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(output_file.read_text(encoding="utf-8"))
    jsonschema.validate(payload, _load_schema("compare-report.schema.json"))


def test_explain_json_matches_published_schema(monkeypatch, tmp_path: Path) -> None:
    output_file = tmp_path / "explain.json"
    _install_fake_providers(monkeypatch)

    result = runner.invoke(
        app,
        [
            "explain",
            "--cve",
            "CVE-2021-44228",
            "--offline-attack-file",
            str(tmp_path / "attack.csv"),
            "--output",
            str(output_file),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(output_file.read_text(encoding="utf-8"))
    jsonschema.validate(payload, _load_schema("explain-report.schema.json"))

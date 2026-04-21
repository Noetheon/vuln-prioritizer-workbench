from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from vuln_prioritizer.cli import app

runner = CliRunner()
PROJECT_ROOT = Path(__file__).resolve().parents[1]
MANIFEST_FILE = PROJECT_ROOT / "data" / "benchmarks" / "snapshot_diff_regressions.json"


def _load_manifest() -> dict:
    return json.loads(MANIFEST_FILE.read_text(encoding="utf-8"))


def _load_cases() -> list[dict]:
    return _load_manifest()["cases"]


def test_snapshot_diff_manifest_covers_all_diff_categories() -> None:
    categories = {item["category"] for case in _load_cases() for item in case["expected_items"]}
    assert categories == {
        "added",
        "removed",
        "priority_up",
        "priority_down",
        "context_changed",
        "unchanged",
    }


def test_snapshot_diff_manifest_covers_all_context_change_fields() -> None:
    manifest = _load_manifest()
    covered_fields = {
        field
        for case in manifest["cases"]
        for item in case["expected_items"]
        if item["category"] == "context_changed"
        for field in item["context_change_fields"]
    }
    assert covered_fields == set(manifest["context_change_fields"])


@pytest.mark.parametrize("case", _load_cases(), ids=lambda item: str(item["name"]))
def test_snapshot_diff_fixture_regressions(tmp_path: Path, case: dict) -> None:
    output_file = tmp_path / f"{case['name']}.json"
    args = [
        "snapshot",
        "diff",
        "--before",
        str(PROJECT_ROOT / case["before"]),
        "--after",
        str(PROJECT_ROOT / case["after"]),
        "--output",
        str(output_file),
        "--format",
        "json",
    ]
    if case.get("include_unchanged"):
        args.append("--include-unchanged")

    result = runner.invoke(app, args)

    assert result.exit_code == 0
    payload = json.loads(output_file.read_text(encoding="utf-8"))
    assert payload["summary"] == case["expected_summary"]

    simplified_items = [
        {
            "cve_id": item["cve_id"],
            "category": item["category"],
            "before_priority": item["before_priority"],
            "after_priority": item["after_priority"],
            "context_change_fields": item["context_change_fields"],
        }
        for item in payload["items"]
    ]
    assert simplified_items == case["expected_items"]

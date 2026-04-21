from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path

import pytest
from typer.testing import CliRunner

TESTS_DIR = Path(__file__).resolve().parent
if str(TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_DIR))

from _input_fixture_contracts import load_input_fixture_contracts  # noqa: E402
from test_cli import _install_fake_providers  # noqa: E402

from vuln_prioritizer.cli import app  # noqa: E402

runner = CliRunner()
PROJECT_ROOT = Path(__file__).resolve().parents[1]
BENCHMARK_FILE = PROJECT_ROOT / "data" / "benchmarks" / "fixture_regressions.json"
_INPUT_CONTRACTS = load_input_fixture_contracts()["inputs"]


def _load_benchmark_manifest() -> dict:
    return json.loads(BENCHMARK_FILE.read_text(encoding="utf-8"))


def _load_cases() -> list[dict]:
    return _load_benchmark_manifest()["cases"]


def test_benchmark_manifest_covers_all_supported_input_fixtures() -> None:
    covered_formats = {case["input_format"] for case in _load_cases()}
    assert covered_formats == set(_INPUT_CONTRACTS)


def test_benchmark_manifest_has_edge_case_coverage_for_each_family() -> None:
    manifest = _load_benchmark_manifest()
    edge_coverage: dict[str, list[str]] = defaultdict(list)
    for case in manifest["cases"]:
        if case.get("edge_case"):
            edge_coverage[case["family"]].append(case["name"])

    for family in manifest["families"]:
        assert edge_coverage[family["id"]], family["id"]


@pytest.mark.parametrize("case", _load_cases(), ids=lambda item: str(item["name"]))
def test_fixture_benchmarks_remain_stable(monkeypatch, tmp_path: Path, case: dict) -> None:
    _install_fake_providers(monkeypatch)
    output_file = tmp_path / f"{case['name']}.json"
    args = [
        "analyze",
        "--input",
        str(PROJECT_ROOT / case["input"]),
        "--input-format",
        case["input_format"],
        "--output",
        str(output_file),
        "--format",
        "json",
    ]
    for value in case.get("extra_args", []):
        args.append(str(PROJECT_ROOT / value) if value.startswith("data/") else value)

    result = runner.invoke(app, args)

    assert result.exit_code == 0
    payload = json.loads(output_file.read_text(encoding="utf-8"))
    assert payload["metadata"]["findings_count"] == case["expected_findings_count"]
    assert payload["metadata"]["filtered_out_count"] == case["expected_filtered_out_count"]
    assert payload["metadata"]["occurrences_count"] == case["expected_occurrences_count"]
    assert payload["metadata"]["source_stats"] == case["expected_source_stats"]
    for label, expected_count in case["expected_counts_by_priority"].items():
        assert payload["metadata"]["counts_by_priority"].get(label, 0) == expected_count
    assert [finding["cve_id"] for finding in payload["findings"]] == case["expected_cves"]
    warnings = payload["metadata"].get("warnings", [])
    for expected_warning in case["expected_warning_substrings"]:
        assert any(expected_warning in warning for warning in warnings)

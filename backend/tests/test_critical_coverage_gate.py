from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest
from paths import REPO_ROOT


def gate():
    spec = importlib.util.spec_from_file_location(
        "coverage_gate", REPO_ROOT / "scripts/check_critical_coverage.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def report(module):
    return {
        "meta": {"branch_coverage": True},
        "files": {
            name: {
                "summary": {
                    "covered_lines": 90,
                    "num_statements": 100,
                    "covered_branches": 80,
                    "num_branches": 100,
                }
            }
            for name in module.CRITICAL_MODULES
        },
    }


def test_coverage_floor_accepts_exact_independent_boundaries(tmp_path: Path):
    module = gate()
    path = tmp_path / "coverage.json"
    path.write_text(json.dumps(report(module)))
    assert module.main(["check", str(path)]) == 0


@pytest.mark.parametrize(
    "defect",
    ["lines", "branches", "missing", "empty", "zero", "nan", "bool", "line-only", "ambiguous"],
)
def test_coverage_gate_fails_closed_on_insufficient_or_absent_evidence(tmp_path: Path, defect: str):
    module = gate()
    payload = report(module)
    name = module.CRITICAL_MODULES[0]
    summary = payload["files"][name]["summary"]
    if defect == "lines":
        summary["covered_lines"] = 89
    elif defect == "branches":
        summary["covered_branches"] = 79
    elif defect == "missing":
        del payload["files"][name]
    elif defect == "empty":
        payload["files"][name] = {}
    elif defect == "zero":
        summary.update(covered_branches=0, num_branches=0)
    elif defect == "nan":
        summary["covered_branches"] = float("nan")
    elif defect == "bool":
        summary["num_branches"] = True
    elif defect == "line-only":
        payload["meta"]["branch_coverage"] = False
    elif defect == "ambiguous":
        payload["files"]["/other/" + name] = payload["files"][name]
    path = tmp_path / "coverage.json"
    path.write_text(json.dumps(payload))
    assert module.main(["check", str(path)]) != 0

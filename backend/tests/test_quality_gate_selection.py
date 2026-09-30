from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from paths import REPO_ROOT
from scripts.select_quality_gates import select_gates


@pytest.mark.parametrize(
    "paths,expected",
    [
        (None, {"core", "evidence", "properties", "history", "recovery", "grype"}),
        ([], set()),
        (["docs/testing-strategy.md", "frontend/src/components/Queue.tsx"], set()),
        (
            ["backend/app/decision_core/evaluation.py"],
            {"core", "properties", "history", "recovery"},
        ),
        (
            ["backend/tests/live/test_sbom_live_contract.py"],
            {"properties", "history", "recovery", "grype"},
        ),
        (["docker/security-tools/Dockerfile"], {"grype"}),
        (
            ["scripts/select_quality_gates.py"],
            {"core", "evidence", "properties", "history", "recovery", "grype"},
        ),
        (
            ["backend/mutation-policy.toml"],
            {"core", "evidence", "properties", "history", "recovery", "grype"},
        ),
    ],
)
def test_quality_selection_protects_affected_contracts(paths, expected):
    assert {gate for gate, enabled in select_gates(paths).items() if enabled} == expected


def test_missing_git_base_runs_every_gate_and_explains_the_fallback(tmp_path: Path):
    output, github = tmp_path / "selection.json", tmp_path / "github-output"
    result = subprocess.run(
        [
            sys.executable,
            str(REPO_ROOT / "scripts/select_quality_gates.py"),
            "--base",
            "missing-quality-base",
            "--output",
            str(output),
        ],
        cwd=tmp_path,
        env={**os.environ, "GITHUB_OUTPUT": str(github)},
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    evidence = json.loads(output.read_text())
    assert all(evidence["gates"].values())
    assert "diff unavailable" in evidence["reason"]
    assert json.loads(github.read_text().removeprefix("gates=")) == evidence["gates"]


def test_each_mutated_source_selects_its_policy_gate():
    import tomllib

    policy = tomllib.loads((REPO_ROOT / "backend/mutation-policy.toml").read_text())
    for profile, group in policy.items():
        for pattern in group["patterns"]:
            source = "backend/" + pattern.rsplit(".x_", 1)[0].replace(".", "/") + ".py"
            assert select_gates([source])[profile], source


def test_changes_to_any_selected_mutation_test_rerun_both_profiles():
    import tomllib

    config = tomllib.loads((REPO_ROOT / "backend/pyproject.toml").read_text())
    for path in config["tool"]["mutmut"]["pytest_add_cli_args_test_selection"]:
        selected = select_gates(["backend/" + path])
        assert selected["core"] and selected["evidence"], path

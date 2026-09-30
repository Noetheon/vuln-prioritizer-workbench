from __future__ import annotations

import argparse
import importlib
import json
from pathlib import Path

from paths import REPO_ROOT


def test_failed_fresh_tree_cleanup_cannot_publish_a_cached_success(tmp_path: Path, monkeypatch):
    monkeypatch.syspath_prepend(str(REPO_ROOT / "scripts"))
    runner = importlib.import_module("run_mutation_checks")
    backend = tmp_path / "backend"
    backend.mkdir()
    (backend / "example.py").write_text("def example(): return True\n")
    (backend / "test_example.py").write_text("def test_example(): assert True\n")
    (backend / "pyproject.toml").write_text(
        '[tool.mutmut]\nsource_paths=["example.py"]\n'
        'pytest_add_cli_args_test_selection=["test_example.py"]\n'
    )
    (backend / "mutation-policy.toml").write_text('[core]\npatterns=["example.x_example*"]\n')
    (backend / "mutation-equivalents.json").write_text('{"mutants": []}')
    (backend / "mutants").mkdir()
    output = tmp_path / "build/mutation/core"
    output.mkdir(parents=True)
    (output / "results.json").write_text('{"stale": "passed"}')
    monkeypatch.setattr(runner, "ROOT", tmp_path)
    monkeypatch.setattr(runner.subprocess, "check_output", lambda *args, **kwargs: "fixture-head")

    def denied(*args, **kwargs):
        raise PermissionError("Cannot remove old mutant tree")

    def never_run(*args, **kwargs):
        raise AssertionError("A campaign must not reuse this mutant tree")

    monkeypatch.setattr(runner.shutil, "rmtree", denied)
    monkeypatch.setattr(runner.subprocess, "Popen", never_run)
    assert runner.run_campaign(argparse.Namespace(profile="core", max_children=1, timeout=1)) == 1
    assert not (output / "results.json").exists()
    evidence = json.loads((output / "campaign.json").read_text())
    assert "Cannot remove old mutant tree" in evidence["runner_error"]
    assert "runner_exit_code" not in evidence

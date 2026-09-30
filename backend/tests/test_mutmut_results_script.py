from __future__ import annotations

import ast
import fnmatch
import importlib.util
import json
import tomllib
from pathlib import Path

import pytest
from paths import REPO_ROOT


def _load_mutmut_results_module() -> object:
    script_path = REPO_ROOT / "scripts" / "check_mutmut_results.py"
    spec = importlib.util.spec_from_file_location("check_mutmut_results", script_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_mutmut_results_rejects_signal_exit_as_infrastructure_failure(tmp_path: Path) -> None:
    module = _load_mutmut_results_module()
    mutants_dir = tmp_path / "mutants"
    mutants_dir.mkdir()
    meta_path = mutants_dir / "selected.py.meta"
    meta_path.write_text(
        json.dumps(
            {
                "exit_code_by_key": {
                    "app.services.report_sarif_validation.x_validate_sarif_file__mutmut_1": -11,
                    "app.services.report_sarif_validation.x_validate_sarif_file__mutmut_2": 1,
                }
            }
        ),
        encoding="utf-8",
    )

    result = module.main(
        [
            "check_mutmut_results.py",
            str(mutants_dir),
            "app.services.report_sarif_validation.x_validate_sarif_file*",
        ]
    )

    assert result == 1


def test_mutmut_results_still_fails_surviving_selected_mutants(tmp_path: Path) -> None:
    module = _load_mutmut_results_module()
    mutants_dir = tmp_path / "mutants"
    mutants_dir.mkdir()
    meta_path = mutants_dir / "selected.py.meta"
    meta_path.write_text(
        json.dumps(
            {
                "exit_code_by_key": {
                    "app.services.report_sarif_validation.x_validate_sarif_file__mutmut_1": 0,
                }
            }
        ),
        encoding="utf-8",
    )

    result = module.main(
        [
            "check_mutmut_results.py",
            str(mutants_dir),
            "app.services.report_sarif_validation.x_validate_sarif_file*",
        ]
    )

    assert result == 1


def test_mutmut_results_requires_results_for_every_selected_pattern(tmp_path: Path) -> None:
    module = _load_mutmut_results_module()
    mutants_dir = tmp_path / "mutants"
    mutants_dir.mkdir()
    (mutants_dir / "selected.py.meta").write_text(
        json.dumps({"exit_code_by_key": {"app.present.x_function__mutmut_1": 1}}),
        encoding="utf-8",
    )
    assert (
        module.main(
            [
                "check_mutmut_results.py",
                str(mutants_dir),
                "app.present.x_function*",
                "app.missing.x_function*",
            ]
        )
        == 1
    )
    assert (
        module.main(["check_mutmut_results.py", str(mutants_dir), "app.present.x_function*"]) == 0
    )


def test_mutation_generation_scope_matches_the_gate_selection() -> None:
    config = tomllib.loads((REPO_ROOT / "backend" / "pyproject.toml").read_text(encoding="utf-8"))
    paths = set(config["tool"]["mutmut"]["source_paths"])
    policy = tomllib.loads((REPO_ROOT / "backend" / "mutation-policy.toml").read_text())
    patterns = [pattern for group in policy.values() for pattern in group["patterns"]]
    assert len(patterns) == len(set(patterns))
    selected_paths = set()
    for pattern in patterns:
        module_name, function_pattern = pattern.rsplit(".x_", maxsplit=1)
        path = module_name.replace(".", "/") + ".py"
        selected_paths.add(path)
        tree = ast.parse((REPO_ROOT / "backend" / path).read_text(encoding="utf-8"))
        functions = {
            node.name
            for node in tree.body
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
        }
        assert any(fnmatch.fnmatchcase(name, function_pattern) for name in functions), pattern
    assert paths == selected_paths
    for test_path in config["tool"]["mutmut"]["pytest_add_cli_args_test_selection"]:
        assert (REPO_ROOT / "backend" / test_path).is_file(), test_path


@pytest.mark.parametrize("exit_code", [None, 0, 2, 3, 33, -9, -11, 127])
def test_mutation_report_preserves_unchecked_and_infrastructure_failures(
    tmp_path: Path,
    exit_code: int | None,
) -> None:
    module = _load_mutmut_results_module()
    mutants = tmp_path / "mutants"
    mutants.mkdir()
    name = "app.scoring.x_priority__mutmut_1"
    (mutants / "test.py.meta").write_text(json.dumps({"exit_code_by_key": {name: exit_code}}))
    report = tmp_path / "report.json"
    assert module.main(["check", str(mutants), "app.scoring.*", "--report", str(report)]) == 1
    payload = json.loads(report.read_text())
    assert payload["selected_count"] == 1
    assert payload["mutants"][name] != "killed"


def test_mutation_gate_accepts_only_observed_test_failure(tmp_path: Path) -> None:
    module = _load_mutmut_results_module()
    (tmp_path / "test.py.meta").write_text(
        json.dumps({"exit_code_by_key": {"app.scoring.x_priority__mutmut_1": 1}})
    )
    assert module.main(["check", str(tmp_path), "app.scoring.*"]) == 0


@pytest.mark.parametrize(
    "drift", [None, "source", "mutation", "killed", "signal", "unchecked", "reason"]
)
def test_equivalent_review_is_bound_to_mutation_source_and_survival(tmp_path: Path, drift):
    import hashlib

    module = _load_mutmut_results_module()
    mutants = tmp_path / "mutants"
    (mutants / "app").mkdir(parents=True)
    (tmp_path / "app").mkdir()
    name = "app.sample.x_check__mutmut_1"
    source = "def check():\n    return False\n"
    mutation = "def x_check__mutmut_1():\n    return None"
    (tmp_path / "app/sample.py").write_text(source)
    (mutants / "app/sample.py").write_text(mutation)
    item = {
        "name": name,
        "reason": "Both branches use only truth-value checks.",
        "context_sha256": {"app/sample.py": hashlib.sha256(source.encode()).hexdigest()},
        "mutant_sha256": hashlib.sha256(mutation.encode()).hexdigest(),
    }
    code = {"killed": 1, "signal": -11, "unchecked": None}.get(drift, 0)
    if drift == "source":
        (tmp_path / "app/sample.py").write_text(source + "# changed")
    if drift == "mutation":
        (mutants / "app/sample.py").write_text(mutation.replace("None", "True"))
    if drift == "reason":
        item["reason"] = ""
    (mutants / "sample.py.meta").write_text(json.dumps({"exit_code_by_key": {name: code}}))
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"schema": "vpw.mutation-equivalents.v1", "mutants": [item]}))
    assert module.main(["check", str(mutants), "app.sample.*", "--equivalents", str(policy)]) == (
        0 if drift is None else 1
    )

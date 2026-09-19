from __future__ import annotations

import ast
import importlib.util
import json
import shlex
import tomllib
from pathlib import Path

from paths import REPO_ROOT


def _load_mutmut_results_module() -> object:
    script_path = REPO_ROOT / "scripts" / "check_mutmut_results.py"
    spec = importlib.util.spec_from_file_location("check_mutmut_results", script_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_mutmut_results_treats_signal_exit_as_killed(tmp_path: Path) -> None:
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

    assert result == 0


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
    paths = set(config["tool"]["mutmut"]["paths_to_mutate"])
    makefile = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")
    pattern_line = next(
        line for line in makefile.splitlines() if line.startswith("MUTATION_PATTERNS :=")
    )
    patterns = shlex.split(pattern_line.split(":=", maxsplit=1)[1])
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
        assert function_pattern.removesuffix("*") in functions, pattern
    assert paths == selected_paths

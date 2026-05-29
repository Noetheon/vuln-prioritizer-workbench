from __future__ import annotations

import importlib.util
import json
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

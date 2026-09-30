"""Select bounded quality jobs from changed paths; uncertain diffs run every gate."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import tomllib
from pathlib import Path

GATES = ("core", "evidence", "properties", "history", "recovery", "grype")


def select_gates(paths: list[str] | None) -> dict[str, bool]:
    """Keep docs/UI-only work cheap; conservatively protect backend contracts."""
    enabled = dict.fromkeys(GATES, False)
    if paths is None:
        return dict.fromkeys(GATES, True)
    try:
        config = tomllib.loads(
            (Path(__file__).resolve().parents[1] / "backend/pyproject.toml").read_text()
        )
        mutation_tests = {
            "backend/" + name
            for name in config["tool"]["mutmut"]["pytest_add_cli_args_test_selection"]
        }
    except (OSError, ValueError, KeyError, TypeError):
        return dict.fromkeys(GATES, True)
    for path in paths:
        # Both profiles use this shared test selection. A test-only weakening
        # must rerun mutation analysis just like changing the production rule.
        if path in mutation_tests:
            enabled.update(core=True, evidence=True)
        if path in {"Makefile", "pyproject.toml", "uv.lock"} or path.startswith(
            (
                "backend/pyproject.toml",
                "backend/requirements",
                "backend/mutation-",
                "scripts/",
                ".github/workflows/test-quality.yml",
            )
        ):
            return dict.fromkeys(GATES, True)
        if path.startswith(("backend/app/", "backend/tests/")):
            for gate in ("properties", "history", "recovery"):
                enabled[gate] = True
        if path.startswith(
            ("backend/app/decision_core/", "backend/app/domain/engine/")
        ) or path in {
            "backend/tests/test_scope_evaluation.py",
            "backend/tests/test_scoring.py",
            "backend/tests/test_waivers.py",
            "backend/tests/test_severity_proxy.py",
            "backend/tests/property/test_decision_properties.py",
        }:
            enabled["core"] = True
        if path.startswith("backend/app/services/report") or path in {
            "backend/app/decision_core/builders.py",
            "backend/app/domain/engine/services/analysis_quality.py",
            "backend/app/domain/engine/services/analysis_snapshot.py",
            "backend/tests/property/test_evidence_properties.py",
            "backend/tests/test_analysis_refactor.py",
            "backend/tests/api/test_workbench_evidence_verification_unit.py",
            "backend/tests/api/import_contracts/test_decision_evidence_contract.py",
        }:
            enabled["evidence"] = True
        if path.startswith("backend/tests/utils/") or path.endswith("conftest.py"):
            enabled.update(
                core=True, evidence=True, properties=True, history=True, recovery=True, grype=True
            )
        if path.startswith(("backend/app/", "backend/tests/")) and (
            any(term in path.lower() for term in ("sbom", "grype", "scanner"))
            or path.startswith(
                (
                    "backend/app/workers/",
                    "backend/app/services/import",
                    "backend/app/core/config",
                    "backend/app/domain/engine/inputs/",
                )
            )
        ):
            enabled["grype"] = True
        if path.startswith(("docker/security-tools/", "docs/examples/sbom-")):
            enabled["grype"] = True
    return enabled


def main() -> int:
    """Write inspectable selection evidence and optional GitHub output."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base")
    parser.add_argument("--output", type=Path, default=Path("build/quality-selection.json"))
    args = parser.parse_args()
    paths = None
    reason = "scheduled, manual, or main-branch full campaign"
    if args.base:
        try:
            result = subprocess.run(
                ["git", "diff", "--no-renames", "--name-only", "-z", f"{args.base}...HEAD"],
                capture_output=True,
                check=True,
                timeout=30,
            )
            paths = [path.decode("utf-8") for path in result.stdout.split(b"\0") if path]
            reason = "changed paths"
        except (OSError, UnicodeError, subprocess.SubprocessError):
            reason = "diff unavailable; all gates selected"
    selected = select_gates(paths)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps({"gates": selected, "reason": reason, "paths": paths}, indent=2) + "\n"
    )
    print(json.dumps(selected, sort_keys=True))
    if output := os.environ.get("GITHUB_OUTPUT"):
        with Path(output).open("a") as stream:
            stream.write("gates=" + json.dumps(selected) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Enforce per-module coverage floors for critical Workbench code paths."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

CRITICAL_COVERAGE_FLOOR = 90.0
CRITICAL_MODULES = (
    "backend/app/services/decision_kernel.py",
    "backend/app/services/report_bundle_archive_verification.py",
    "backend/app/services/report_sarif_validation.py",
    "backend/app/domain/engine/services/analysis_pipeline.py",
)


def main(argv: list[str]) -> int:
    """Validate configured critical modules against the coverage JSON report."""
    coverage_path = Path(argv[1]) if len(argv) > 1 else Path("build/coverage-current.json")
    try:
        payload = json.loads(coverage_path.read_text(encoding="utf-8"))
    except OSError as exc:
        print(f"Could not read coverage JSON {coverage_path}: {exc}", file=sys.stderr)
        return 2
    except json.JSONDecodeError as exc:
        print(f"Coverage JSON {coverage_path} is invalid JSON: {exc}", file=sys.stderr)
        return 2

    raw_files = payload.get("files")
    if not isinstance(raw_files, dict):
        print(f"Coverage JSON {coverage_path} does not contain a files object.", file=sys.stderr)
        return 2

    coverage_by_path = {_normalize_path(path): data for path, data in raw_files.items()}
    failures: list[str] = []
    for module_path in CRITICAL_MODULES:
        coverage_data = _lookup_module(coverage_by_path, module_path)
        if coverage_data is None:
            failures.append(f"{module_path}: missing from coverage JSON")
            continue
        percent = _percent_covered(coverage_data)
        if percent < CRITICAL_COVERAGE_FLOOR:
            failures.append(f"{module_path}: {percent:.2f}% < {CRITICAL_COVERAGE_FLOOR:.2f}%")

    if failures:
        print("Critical coverage gate failed:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1

    print(
        "Critical coverage gate passed: "
        f"{len(CRITICAL_MODULES)} modules >= {CRITICAL_COVERAGE_FLOOR:.0f}%"
    )
    return 0


def _lookup_module(
    coverage_by_path: dict[str, Any],
    module_path: str,
) -> dict[str, Any] | None:
    normalized_module = _normalize_path(module_path)
    if isinstance(coverage_by_path.get(normalized_module), dict):
        return coverage_by_path[normalized_module]
    suffix = normalized_module.removeprefix("backend/")
    for path, data in coverage_by_path.items():
        if path == suffix or path.endswith(f"/{suffix}") or path.endswith(f"/{normalized_module}"):
            return data if isinstance(data, dict) else None
    return None


def _percent_covered(coverage_data: dict[str, Any]) -> float:
    summary = coverage_data.get("summary")
    if isinstance(summary, dict):
        percent = summary.get("percent_covered")
        if isinstance(percent, int | float):
            return float(percent)

    executed = coverage_data.get("executed_lines")
    missing = coverage_data.get("missing_lines")
    executed_count = len(executed) if isinstance(executed, list) else 0
    missing_count = len(missing) if isinstance(missing, list) else 0
    denominator = executed_count + missing_count
    if denominator == 0:
        return 100.0
    return executed_count / denominator * 100


def _normalize_path(path: str) -> str:
    return path.replace("\\", "/").lstrip("./")


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

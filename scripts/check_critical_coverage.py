"""Enforce independent line and branch floors for critical Workbench code."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

CRITICAL_COVERAGE_FLOOR = 90.0
CRITICAL_BRANCH_FLOOR = 80.0
CRITICAL_MODULES = (
    "backend/app/decision_core/producer.py",
    "backend/app/decision_core/evaluation.py",
    "backend/app/domain/engine/scoring.py",
    "backend/app/domain/engine/scoring_operational.py",
    "backend/app/domain/engine/services/waivers.py",
    "backend/app/services/report_bundle_archive_verification.py",
    "backend/app/services/report_sarif_validation.py",
    "backend/app/domain/engine/services/analysis_pipeline.py",
)


def main(argv: list[str]) -> int:
    """Reject missing or malformed measurements as well as inadequate coverage."""
    coverage_path = Path(argv[1]) if len(argv) > 1 else Path("build/coverage-current.json")
    try:
        payload = json.loads(coverage_path.read_text(encoding="utf-8"))
        if (
            not isinstance(payload, dict)
            or payload.get("meta", {}).get("branch_coverage") is not True
        ):
            raise ValueError("branch coverage must be enabled")
        raw_files = payload.get("files")
        if not isinstance(raw_files, dict):
            raise ValueError("missing files object")
        coverage_by_path = {_normalize_path(path): data for path, data in raw_files.items()}
    except (OSError, ValueError, TypeError, AttributeError) as exc:
        print(f"Invalid coverage report {coverage_path}: {exc}", file=sys.stderr)
        return 2
    failures: list[str] = []
    for module_path in CRITICAL_MODULES:
        try:
            data = _lookup_module(coverage_by_path, module_path)
            if data is None:
                raise ValueError("missing or ambiguous module")
            for label, covered, total, floor in (
                ("lines", "covered_lines", "num_statements", CRITICAL_COVERAGE_FLOOR),
                ("branches", "covered_branches", "num_branches", CRITICAL_BRANCH_FLOOR),
            ):
                percent = _coverage_percent(data, covered, total)
                if percent < floor:
                    failures.append(f"{module_path}: {label} {percent:.2f}% < {floor:.2f}%")
        except ValueError as exc:
            failures.append(f"{module_path}: {exc}")
    if failures:
        print("Critical coverage gate failed:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1
    print(
        f"Critical coverage passed: {len(CRITICAL_MODULES)} modules, "
        f"lines >= {CRITICAL_COVERAGE_FLOOR:.0f}%, branches >= {CRITICAL_BRANCH_FLOOR:.0f}%"
    )
    return 0


def _lookup_module(coverage_by_path: dict[str, Any], module_path: str) -> dict[str, Any] | None:
    suffix = module_path.removeprefix("backend/")
    candidates = [
        data
        for path, data in coverage_by_path.items()
        if path in {module_path, suffix}
        or path.endswith(f"/{module_path}")
        or path.endswith(f"/{suffix}")
    ]
    return candidates[0] if len(candidates) == 1 and isinstance(candidates[0], dict) else None


def _coverage_percent(data: dict[str, Any], covered_key: str, total_key: str) -> float:
    summary = data.get("summary")
    if not isinstance(summary, dict):
        raise ValueError("missing summary")
    covered, total = summary.get(covered_key), summary.get(total_key)
    # These selected modules all contain executable lines and branches. A zero
    # denominator is missing measurement, not evidence of complete coverage.
    if (
        type(covered) is not int
        or type(total) is not int
        or not 0 <= covered <= total
        or total <= 0
    ):
        raise ValueError(f"invalid {covered_key}/{total_key} measurement")
    return 100 * covered / total


def _normalize_path(path: str) -> str:
    return path.replace("\\", "/").lstrip("./")


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

#!/usr/bin/env python3
"""Fail focused mutation gates when selected mutants survive."""

from __future__ import annotations

import fnmatch
import json
import sys
from collections import Counter
from pathlib import Path

KILLED_EXIT_CODE = 1
STATUS_BY_EXIT_CODE = {
    None: "not checked",
    0: "survived",
    1: "killed",
    2: "timeout",
    3: "suspicious",
    33: "skipped",
}


def _load_exit_codes(mutants_dir: Path) -> dict[str, int | None]:
    exit_codes: dict[str, int | None] = {}
    for meta_path in mutants_dir.glob("**/*.py.meta"):
        payload = json.loads(meta_path.read_text(encoding="utf-8"))
        for mutant_name, exit_code in payload.get("exit_code_by_key", {}).items():
            exit_codes[mutant_name] = exit_code
    return exit_codes


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        print(
            "Usage: check_mutmut_results.py <mutants-dir> <mutant-pattern> [<mutant-pattern> ...]",
            file=sys.stderr,
        )
        return 2

    mutants_dir = Path(argv[1])
    patterns = argv[2:]
    exit_codes = _load_exit_codes(mutants_dir)
    if not exit_codes:
        print(f"No mutmut metadata found under {mutants_dir}", file=sys.stderr)
        return 1

    selected = {
        name: exit_code
        for name, exit_code in exit_codes.items()
        if any(fnmatch.fnmatch(name, pattern) for pattern in patterns)
    }
    if not selected:
        print("No mutants matched the configured mutation-check patterns.", file=sys.stderr)
        return 1

    counts = Counter(STATUS_BY_EXIT_CODE.get(code, f"exit {code}") for code in selected.values())
    failures = {
        name: exit_code for name, exit_code in selected.items() if exit_code != KILLED_EXIT_CODE
    }
    summary = ", ".join(f"{status}={count}" for status, count in sorted(counts.items()))
    print(f"Focused mutation results: {len(selected)} mutants ({summary})")

    if failures:
        print("Mutation gate failed for selected mutants:", file=sys.stderr)
        for name, exit_code in sorted(failures.items()):
            status = STATUS_BY_EXIT_CODE.get(exit_code, f"exit {exit_code}")
            print(f"  {name}: {status}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

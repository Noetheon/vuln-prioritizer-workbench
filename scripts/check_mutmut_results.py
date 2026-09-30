#!/usr/bin/env python3
"""Fail focused mutation gates when selected mutants survive."""

from __future__ import annotations

import argparse
import ast
import fnmatch
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path

STATUS_BY_EXIT_CODE = {
    None: "not checked",
    0: "survived",
    1: "killed",
    2: "timeout",
    3: "suspicious",
    33: "skipped",
}


def _mutant_status(exit_code: int | None) -> str:
    if isinstance(exit_code, int) and exit_code < 0:
        return f"infrastructure signal {-exit_code}"
    return STATUS_BY_EXIT_CODE.get(exit_code, f"exit {exit_code}")


def _is_killed(exit_code: int | None) -> bool:
    return exit_code == 1


def _load_exit_codes(mutants_dir: Path) -> dict[str, int | None]:
    exit_codes: dict[str, int | None] = {}
    for meta_path in mutants_dir.glob("**/*.py.meta"):
        payload = json.loads(meta_path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError(f"Invalid metadata object: {meta_path}")
        codes = payload.get("exit_code_by_key")
        if not isinstance(codes, dict):
            raise ValueError(f"Missing exit code mapping: {meta_path}")
        for mutant_name, exit_code in codes.items():
            if mutant_name in exit_codes or (exit_code is not None and type(exit_code) is not int):
                raise ValueError(f"Invalid or duplicate mutant result: {mutant_name}")
            exit_codes[mutant_name] = exit_code
    return exit_codes


def reviewed_equivalents(
    path: Path, mutants: Path, patterns: list[str], selected: dict
) -> dict[str, str]:
    """Allow only a surviving exact mutation with unchanged supporting source."""
    policy = json.loads(path.read_text())
    if policy.get("schema") != "vpw.mutation-equivalents.v1":
        raise ValueError("Unknown equivalent-mutant policy schema")
    approved = {}
    for item in policy["mutants"]:
        name = item["name"]
        if not any(fnmatch.fnmatchcase(name, pattern) for pattern in patterns):
            continue
        if name in approved or name not in selected or selected[name] != 0:
            raise ValueError(f"Stale/duplicate equivalent-mutant entry: {name}")
        if not item.get("reason", "").strip() or not item.get("context_sha256"):
            raise ValueError(f"Equivalent mutant requires source context and reasoning: {name}")
        for source, expected in item["context_sha256"].items():
            actual = hashlib.sha256((mutants.parent / source).read_bytes()).hexdigest()
            if actual != expected:
                raise ValueError(
                    f"Re-review equivalent mutant after source change: {name}: {source}"
                )
        module, function = name.rsplit(".", 1)
        text = (mutants / (module.replace(".", "/") + ".py")).read_text()
        node = next(
            (
                n
                for n in ast.parse(text).body
                if isinstance(n, ast.FunctionDef) and n.name == function
            ),
            None,
        )
        if (
            node is None
            or hashlib.sha256(ast.get_source_segment(text, node).encode()).hexdigest()
            != item["mutant_sha256"]
        ):
            raise ValueError(f"Re-review changed equivalent mutation: {name}")
        approved[name] = item["reason"]
    return approved


def main(argv: list[str]) -> int:
    """Validate that all selected mutmut mutants were killed."""
    if len(argv) < 3:
        print(
            "Usage: check_mutmut_results.py <mutants-dir> <mutant-pattern> [<mutant-pattern> ...]",
            file=sys.stderr,
        )
        return 2

    parser = argparse.ArgumentParser()
    parser.add_argument("mutants_dir", type=Path)
    parser.add_argument("patterns", nargs="+")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--equivalents", type=Path)
    args = parser.parse_args(argv[1:])
    mutants_dir = args.mutants_dir
    patterns = args.patterns
    try:
        exit_codes = _load_exit_codes(mutants_dir)
    except (OSError, ValueError, TypeError) as error:
        print(f"Invalid mutation metadata: {error}", file=sys.stderr)
        return 1
    if not exit_codes:
        print(f"No mutmut metadata found under {mutants_dir}", file=sys.stderr)
        return 1

    unmatched_patterns = [
        pattern
        for pattern in patterns
        if not any(fnmatch.fnmatchcase(name, pattern) for name in exit_codes)
    ]
    if unmatched_patterns:
        print("Mutation gate has no results for configured patterns:", file=sys.stderr)
        for pattern in unmatched_patterns:
            print(f"  {pattern}", file=sys.stderr)
        return 1

    selected = {
        name: exit_code
        for name, exit_code in exit_codes.items()
        if any(fnmatch.fnmatchcase(name, pattern) for pattern in patterns)
    }

    approved = {}
    if args.equivalents:
        try:
            approved = reviewed_equivalents(args.equivalents, mutants_dir, patterns, selected)
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
            print(f"Invalid equivalent-mutant review: {error}", file=sys.stderr)
            return 1
    statuses = {
        name: "equivalent (reviewed)" if name in approved else _mutant_status(code)
        for name, code in selected.items()
    }
    counts = Counter(statuses.values())
    failures = {
        name: exit_code
        for name, exit_code in selected.items()
        if not _is_killed(exit_code) and name not in approved
    }
    summary = ", ".join(f"{status}={count}" for status, count in sorted(counts.items()))
    print(f"Focused mutation results: {len(selected)} mutants ({summary})")
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(
            json.dumps(
                {
                    "schema": "vpw.mutation-results.v1",
                    "patterns": patterns,
                    "selected_count": len(selected),
                    "counts": dict(sorted(counts.items())),
                    "mutants": dict(sorted(statuses.items())),
                    "equivalents": approved,
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

    if failures:
        print("Mutation gate failed for selected mutants:", file=sys.stderr)
        for name, exit_code in sorted(failures.items()):
            print(f"  {name}: {_mutant_status(exit_code)}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

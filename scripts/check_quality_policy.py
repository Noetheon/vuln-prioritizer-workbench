"""Require source-bound reasoning for quality-policy changes and reduced test scope."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import subprocess
from pathlib import Path

PROTECTED = (
    ".github/workflows/",
    ".github/CODEOWNERS",
    "quality/",
    "scripts/quality_",
    "scripts/check_quality_",
    "scripts/check_critical_coverage.py",
    "scripts/check_mutmut_results.py",
    "scripts/select_quality_gates.py",
    "scripts/run_mutation_checks.py",
    "scripts/run_grype_integration.py",
    "scripts/grype-checksums.json",
    "backend/mutation-",
    "Makefile",
    "backend/pyproject.toml",
    "pyproject.toml",
    "backend/tests/performance/",
    "backend/tests/utils/property_profiles.py",
)
CRITICAL = ("backend/app/decision_core/", "backend/app/domain/engine/")


def git(root: Path, *args: str) -> bytes:
    """Read Git data without executing repository-provided hooks or shell text."""
    return subprocess.check_output(["git", *args], cwd=root, timeout=30)


def test_names(source: bytes) -> set[str]:
    """Identify removed regression cases without comparing assertion counts."""
    tree = ast.parse(source)
    names = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith(
            "test_"
        ):
            names.add(node.name)
        if isinstance(node, ast.ClassDef):
            names.update(
                f"{node.name}.{child.name}"
                for child in node.body
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
                and child.name.startswith("test_")
            )
    return names


def changed_paths(root: Path, base: str) -> list[str]:
    """Use the PR merge base, including deletions and renames as separate paths."""
    return [
        name.decode()
        for name in git(root, "diff", "--no-renames", "--name-only", "-z", base, "--").split(b"\0")
        if name
    ]


def public_names(source: bytes) -> set[str]:
    """Surface newly introduced decision entry points for explicit scope review."""
    return {
        node.name
        for node in ast.parse(source).body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
        and not node.name.startswith("_")
    }


def previous_source(root: Path, base: str, name: str) -> bytes:
    """Read the base blob, distinguishing a new path from an existing source."""
    if (
        subprocess.run(
            ["git", "cat-file", "-e", f"{base}:{name}"],
            cwd=root,
            capture_output=True,
            timeout=30,
        ).returncode
        == 0
    ):
        return git(root, "show", f"{base}:{name}")
    return b""


def obligations(root: Path, base: str, paths: list[str]) -> dict[str, dict]:
    """Flag policy changes, new critical modules, removed tests and new skips."""
    required = {}
    for name in paths:
        if name.startswith("quality/reviews/"):
            continue
        old = previous_source(root, base, name)
        path = root / name
        new = path.read_bytes() if path.is_file() else b""
        reasons = []
        if name.startswith(PROTECTED):
            reasons.append("quality policy or execution boundary")
        if name.startswith(CRITICAL) and name.endswith(".py") and not old:
            reasons.append("new critical module: explain example/property/mutation coverage")
        elif name.startswith(CRITICAL) and name.endswith(".py"):
            if added := public_names(new) - public_names(old):
                reasons.append("new critical entry points: " + ", ".join(sorted(added)))
        if name.startswith("backend/tests/") and name.endswith(".py"):
            removed = test_names(old) - test_names(new)
            if removed:
                reasons.append("removed test cases: " + ", ".join(sorted(removed)))
            for marker in (b"pytest.skip(", b"pytest.mark.skip", b"pytest.mark.xfail"):
                if new.count(marker) > old.count(marker):
                    reasons.append("new skip/xfail: explain scope, owner and repair deadline")
        if reasons:
            required[name] = {
                "sha256": hashlib.sha256(new).hexdigest() if path.is_file() else "deleted",
                "reasons": reasons,
            }
    return required


def check_records(root: Path, required: dict, paths: list[str]) -> list[str]:
    """Require changed records with concrete reasoning bound to affected bytes."""
    covered = {}
    errors = []
    for name in paths:
        if not name.startswith("quality/reviews/") or not name.endswith(".json"):
            continue
        path = root / name
        if not path.is_file():
            continue
        try:
            record = json.loads(path.read_text())
            if record.get("schema") != "vpw.quality-change.v1":
                raise ValueError("unknown record schema")
            for field in ("owner", "reason", "risk", "validation", "coverage_impact"):
                value = record.get(field)
                if not isinstance(value, str) or len(value.strip()) < 8 or "TODO" in value:
                    raise ValueError(f"missing concrete {field}")
            for affected, sha in record["paths"].items():
                if affected in required and sha != required[affected]["sha256"]:
                    raise ValueError(f"stale source hash: {affected}")
                if affected in required:
                    covered[affected] = name
        except (OSError, ValueError, TypeError, KeyError) as error:
            errors.append(f"{name}: {error}")
    for name, item in required.items():
        if name not in covered:
            errors.append(f"{name}: add a quality change record ({'; '.join(item['reasons'])})")
    return errors


def main() -> int:
    """Check a PR's policy diff, or emit its required source hashes for authors."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--describe", action="store_true")
    args = parser.parse_args()
    if not args.base:
        print("No PR policy comparison; the exact-source runtime gates still apply.")
        return 0
    try:
        base = git(args.root, "merge-base", args.base, "HEAD").decode().strip()
        paths = changed_paths(args.root, base)
        required = obligations(args.root, base, paths)
        if args.describe:
            print(json.dumps(required, indent=2))
            return 0
        errors = check_records(args.root, required, paths)
        for error in errors:
            print(error)
        if errors:
            return 1
        print(f"Quality policy: {len(required)} affected paths have source-bound reasoning.")
        return 0
    except (OSError, ValueError, SyntaxError, subprocess.SubprocessError) as error:
        print(f"Quality policy could not be verified: {error}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

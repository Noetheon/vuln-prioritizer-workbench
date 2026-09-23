"""Reject stale, hand-edited, or differently generated Python lock exports."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[1]
UV_VERSION = "0.11.31"
EXPORTS: tuple[tuple[str, tuple[str, ...], str], ...] = (
    ("backend/requirements.lock.txt", ("--all-packages", "--all-extras"), "3.11"),
    (
        "backend/requirements.runtime.lock.txt",
        ("--package", "vuln-prioritizer-workbench", "--no-dev"),
        "3.14",
    ),
)


def _first_different_line(actual: bytes, expected: bytes) -> int:
    """Give an actionable location without printing potentially huge exports."""
    actual_lines = actual.splitlines(keepends=True)
    expected_lines = expected.splitlines(keepends=True)
    for number, (actual_line, expected_line) in enumerate(
        zip(actual_lines, expected_lines), start=1
    ):
        if actual_line != expected_line:
            return number
    return min(len(actual_lines), len(expected_lines)) + 1


def _run_uv(uv: str, args: list[str], workspace: Path) -> str | None:
    # Inherited UV_* flags can silently change the export profile. Use only the
    # explicit, documented flags and forbid interpreter downloads.
    environment = {key: value for key, value in os.environ.items() if not key.startswith("UV_")}
    environment["UV_PYTHON_DOWNLOADS"] = "never"
    try:
        result = subprocess.run(
            [uv, *args],
            cwd=workspace,
            env=environment,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return f"uv {' '.join(args)} could not run: {error}"
    if result.returncode:
        detail = result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}"
        return f"uv {' '.join(args)} failed: {detail}"
    return None


def check_python_lock_exports(root: Path = ROOT, uv: str = "uv") -> list[str]:
    """Compare each committed file with an offline export from the same lock."""
    try:
        version = subprocess.run(
            [uv, "--version"], capture_output=True, text=True, timeout=10, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return [f"uv {UV_VERSION} is required for python-lock-check: {error}"]
    match = re.match(r"^uv (\d+\.\d+\.\d+)(?:\s|$)", version.stdout.strip())
    if version.returncode or match is None or match.group(1) != UV_VERSION:
        return [
            f"python-lock-check requires uv {UV_VERSION}, found "
            f"{version.stdout.strip() or version.stderr.strip()!r}."
        ]

    required = ("pyproject.toml", "backend/pyproject.toml", "uv.lock")
    missing = [name for name in required if not (root / name).is_file()]
    if missing:
        return [f"Cannot verify Python lock exports; missing: {', '.join(missing)}."]

    with TemporaryDirectory(prefix="vpw-lock-exports-") as temporary:
        workspace = Path(temporary)
        (workspace / "backend").mkdir()
        for name in required:
            shutil.copyfile(root / name, workspace / name)

        error = _run_uv(
            uv, ["lock", "--check", "--offline", "--python", "3.14", "--no-progress"], workspace
        )
        if error:
            return [f"uv.lock is stale or cannot be checked offline: {error}"]

        failures: list[str] = []
        for name, scope, python_version in EXPORTS:
            args = [
                "export",
                "--offline",
                "--format",
                "requirements.txt",
                *scope,
                "--no-emit-project",
                "--no-emit-workspace",
                "--locked",
                "--python",
                python_version,
                "--output-file",
                name,
                "--no-progress",
            ]
            error = _run_uv(uv, args, workspace)
            if error:
                failures.append(f"Cannot verify {name}: {error}")
                continue
            generated = workspace / name
            if not generated.is_file():
                failures.append(f"Cannot verify {name}: uv export produced no output file.")
                continue
            committed = root / name
            if not committed.is_file():
                failures.append(f"{name} is missing; regenerate it with the documented uv export.")
                continue
            actual = committed.read_bytes()
            expected = generated.read_bytes()
            if actual != expected:
                failures.append(
                    f"{name} differs from uv.lock export at line "
                    f"{_first_different_line(actual, expected)}; regenerate it with: "
                    f"uv {' '.join(args)}"
                )
        return failures


def main() -> int:
    """Run the pinned offline comparison as a Makefile/CI gate."""
    failures = check_python_lock_exports()
    if failures:
        for failure in failures:
            print(failure, file=sys.stderr)
        return 1
    print(f"Python lock exports match uv.lock (uv {UV_VERSION}): OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

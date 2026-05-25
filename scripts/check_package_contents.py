"""Validate backend source distribution and wheel package boundaries."""

from __future__ import annotations

import json
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

REQUIRED_WHEEL_SUFFIXES = (
    "app/main.py",
    "app/api/main.py",
    "app/alembic/env.py",
)
REQUIRED_SDIST_SUFFIXES = (
    "app/main.py",
    "app/api/main.py",
    "app/alembic/env.py",
    "pyproject.toml",
)
FORBIDDEN_WHEEL_PREFIXES = (
    "vuln_prioritizer/api/",
    "vuln_prioritizer/cli_support/",
    "vuln_prioritizer/commands/",
    "vuln_prioritizer/db/",
    "vuln_prioritizer/reporting_",
    "vuln_prioritizer/web/",
)
FORBIDDEN_WHEEL_FILES = (
    "vuln_prioritizer/cli.py",
    "vuln_prioritizer/cli_options.py",
    "vuln_prioritizer/parser.py",
    "vuln_prioritizer/reporter.py",
    "vuln_prioritizer/runtime_config.py",
    "vuln_prioritizer/sarif_validation.py",
    "vuln_prioritizer/security_tokens.py",
    "vuln_prioritizer/state_store.py",
)
FORBIDDEN_SDIST_PARTS = (
    "/src/vuln_prioritizer/api/",
    "/src/vuln_prioritizer/cli_support/",
    "/src/vuln_prioritizer/commands/",
    "/src/vuln_prioritizer/db/",
    "/src/vuln_prioritizer/reporting_",
    "/src/vuln_prioritizer/web/",
)
FORBIDDEN_SDIST_FILES = tuple(f"/src/{path}" for path in FORBIDDEN_WHEEL_FILES)


def _single(path: Path, pattern: str) -> Path:
    matches = sorted(path.glob(pattern))
    if len(matches) != 1:
        raise SystemExit(f"Expected exactly one {pattern} in {path}, found {len(matches)}.")
    return matches[0]


def _wheel_entries(path: Path) -> list[str]:
    with zipfile.ZipFile(path) as archive:
        return sorted(info.filename for info in archive.infolist())


def _sdist_entries(path: Path) -> list[str]:
    with tarfile.open(path, "r:gz") as archive:
        return sorted(member.name for member in archive.getmembers() if member.isfile())


def _assert_suffixes(entries: list[str], required_suffixes: tuple[str, ...], artifact: str) -> None:
    missing = [
        suffix
        for suffix in required_suffixes
        if not any(entry.endswith(suffix) for entry in entries)
    ]
    if missing:
        raise SystemExit(f"{artifact} is missing required package entries: {', '.join(missing)}")


def _assert_no_tests(entries: list[str], artifact: str) -> None:
    test_entries = [
        entry
        for entry in entries
        if "/tests/" in entry or entry.startswith("tests/") or entry.endswith("/tests")
    ]
    if test_entries:
        raise SystemExit(f"{artifact} unexpectedly includes tests: {test_entries[:10]}")


def _assert_no_legacy_workbench_modules(entries: list[str], artifact: str) -> None:
    if artifact.endswith(".whl"):
        legacy_entries = [
            entry
            for entry in entries
            if entry in FORBIDDEN_WHEEL_FILES
            or any(entry.startswith(prefix) for prefix in FORBIDDEN_WHEEL_PREFIXES)
        ]
    else:
        legacy_entries = [
            entry
            for entry in entries
            if any(entry.endswith(file_path) for file_path in FORBIDDEN_SDIST_FILES)
            or any(part in entry for part in FORBIDDEN_SDIST_PARTS)
        ]
    if legacy_entries:
        raise SystemExit(
            f"{artifact} unexpectedly includes removed legacy Workbench modules: "
            f"{legacy_entries[:10]}"
        )


def _tracked_alembic_migration_suffixes() -> tuple[str, ...]:
    migration_dir = ROOT / "backend" / "app" / "alembic" / "versions"
    try:
        result = subprocess.run(
            [
                "git",
                "ls-files",
                "--cached",
                "--others",
                "--exclude-standard",
                "--",
                "backend/app/alembic/versions/*.py",
            ],
            check=True,
            cwd=ROOT,
            stderr=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            text=True,
        )
        paths = [ROOT / Path(line) for line in result.stdout.splitlines()]
    except (FileNotFoundError, subprocess.CalledProcessError):
        paths = sorted(migration_dir.glob("*.py"))

    suffixes = []
    for path in paths:
        if not path.is_file():
            continue
        if path.name == "__init__.py":
            continue
        suffixes.append(Path("app/alembic/versions", path.name).as_posix())
    if not suffixes:
        raise SystemExit("No tracked Workbench Alembic migrations found.")
    return tuple(sorted(suffixes))


def main() -> None:
    """Validate the built wheel and source distribution in the dist directory."""
    dist_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("dist")
    wheel = _single(dist_dir, "*.whl")
    sdist = _single(dist_dir, "*.tar.gz")
    required_migration_suffixes = _tracked_alembic_migration_suffixes()

    wheel_entries = _wheel_entries(wheel)
    sdist_entries = _sdist_entries(sdist)

    _assert_suffixes(wheel_entries, REQUIRED_WHEEL_SUFFIXES, wheel.name)
    _assert_suffixes(sdist_entries, REQUIRED_SDIST_SUFFIXES, sdist.name)
    _assert_suffixes(wheel_entries, required_migration_suffixes, wheel.name)
    _assert_suffixes(sdist_entries, required_migration_suffixes, sdist.name)
    _assert_no_tests(wheel_entries, wheel.name)
    _assert_no_tests(sdist_entries, sdist.name)
    _assert_no_legacy_workbench_modules(wheel_entries, wheel.name)
    _assert_no_legacy_workbench_modules(sdist_entries, sdist.name)

    report = {
        "boundary": (
            "The backend distribution intentionally ships both the shared domain "
            "package and the active Workbench FastAPI app package. It does not "
            "publish the legacy CLI as a console entrypoint."
        ),
        "wheel": {
            "path": wheel.as_posix(),
            "entry_count": len(wheel_entries),
            "forbidden_legacy_prefixes": list(FORBIDDEN_WHEEL_PREFIXES),
            "forbidden_legacy_files": list(FORBIDDEN_WHEEL_FILES),
            "required_alembic_migrations": list(required_migration_suffixes),
            "required_suffixes": list(REQUIRED_WHEEL_SUFFIXES),
        },
        "sdist": {
            "path": sdist.as_posix(),
            "entry_count": len(sdist_entries),
            "forbidden_legacy_parts": list(FORBIDDEN_SDIST_PARTS),
            "forbidden_legacy_files": list(FORBIDDEN_SDIST_FILES),
            "required_alembic_migrations": list(required_migration_suffixes),
            "required_suffixes": list(REQUIRED_SDIST_SUFFIXES),
        },
    }
    output_path = Path("build/package-contents.json")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"{output_path}: OK")


if __name__ == "__main__":
    main()

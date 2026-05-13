from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path

import pytest
from paths import REPO_ROOT


def _load_package_contents_module() -> object:
    script_path = REPO_ROOT / "scripts" / "check_package_contents.py"
    spec = importlib.util.spec_from_file_location("check_package_contents", script_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_package_contents_requires_every_tracked_alembic_migration() -> None:
    module = _load_package_contents_module()
    expected = {
        Path("app/alembic/versions", path.name).as_posix()
        for path in (REPO_ROOT / "backend" / "app" / "alembic" / "versions").glob("*.py")
        if path.name != "__init__.py"
    }

    assert set(module._tracked_alembic_migration_suffixes()) == expected


def test_package_contents_falls_back_to_filesystem_without_git(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_package_contents_module()
    expected = {
        Path("app/alembic/versions", path.name).as_posix()
        for path in (REPO_ROOT / "backend" / "app" / "alembic" / "versions").glob("*.py")
        if path.name != "__init__.py"
    }

    def fail_git(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        raise subprocess.CalledProcessError(128, ["git", "ls-files"])

    monkeypatch.setattr(module.subprocess, "run", fail_git)

    assert set(module._tracked_alembic_migration_suffixes()) == expected


def test_package_contents_fails_when_a_tracked_migration_is_absent() -> None:
    module = _load_package_contents_module()
    required = module._tracked_alembic_migration_suffixes()
    entries = [suffix for suffix in required if suffix != required[-1]]

    with pytest.raises(SystemExit, match="missing required package entries"):
        module._assert_suffixes(entries, required, "vuln_prioritizer-0.0.0-py3-none-any.whl")


def test_package_contents_rejects_removed_cli_and_report_modules_from_wheel() -> None:
    module = _load_package_contents_module()

    with pytest.raises(SystemExit, match="removed legacy Workbench modules"):
        module._assert_no_legacy_workbench_modules(
            [
                "app/main.py",
                "vuln_prioritizer/cli.py",
                "vuln_prioritizer/reporting_payloads.py",
            ],
            "vuln_prioritizer-0.0.0-py3-none-any.whl",
        )


def test_package_contents_rejects_removed_cli_and_report_modules_from_sdist() -> None:
    module = _load_package_contents_module()

    with pytest.raises(SystemExit, match="removed legacy Workbench modules"):
        module._assert_no_legacy_workbench_modules(
            [
                "vuln_prioritizer-0.0.0/app/main.py",
                "vuln_prioritizer-0.0.0/src/vuln_prioritizer/commands/report.py",
                "vuln_prioritizer-0.0.0/src/vuln_prioritizer/reporting_html.py",
            ],
            "vuln_prioritizer-0.0.0.tar.gz",
        )

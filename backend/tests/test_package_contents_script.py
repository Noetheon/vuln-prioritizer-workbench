from __future__ import annotations

import importlib.util
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


def test_package_contents_fails_when_a_tracked_migration_is_absent() -> None:
    module = _load_package_contents_module()
    required = module._tracked_alembic_migration_suffixes()
    entries = [suffix for suffix in required if suffix != required[-1]]

    with pytest.raises(SystemExit, match="missing required package entries"):
        module._assert_suffixes(entries, required, "vuln_prioritizer-0.0.0-py3-none-any.whl")

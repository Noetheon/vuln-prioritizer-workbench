"""Keep every place that shows the Workbench version on one number."""

from __future__ import annotations

import json
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_package_versions_match_across_python_and_frontend() -> None:
    root_version = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"][
        "version"
    ]
    backend_version = tomllib.loads(
        (ROOT / "backend" / "pyproject.toml").read_text(encoding="utf-8")
    )["project"]["version"]
    package = json.loads((ROOT / "frontend" / "package.json").read_text(encoding="utf-8"))
    lock = json.loads((ROOT / "frontend" / "package-lock.json").read_text(encoding="utf-8"))

    assert backend_version == root_version
    # The Settings page shows the frontend version next to the backend one.
    assert package["version"] == root_version
    assert lock["version"] == root_version
    assert lock["packages"][""]["version"] == root_version


def test_status_api_reports_the_installed_package_version() -> None:
    from app.api.routes import workbench
    from app.core.version import package_version
    from app.domain.engine import __version__

    assert __version__ == package_version()
    assert "__version__" not in vars(workbench)

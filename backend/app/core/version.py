"""Single source for the installed Workbench version."""

from __future__ import annotations

from importlib import metadata

PACKAGE_NAME = "vuln-prioritizer-workbench"


def package_version() -> str:
    """Return the installed package version, as used by CLI, API, and backups."""
    try:
        return metadata.version(PACKAGE_NAME)
    except metadata.PackageNotFoundError:
        return "0.0.0+local"

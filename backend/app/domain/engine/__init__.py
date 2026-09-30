"""Workbench engine domain package."""

from app.core.version import package_version

__all__ = ["__version__"]

# The engine ships inside the Workbench package and shares its version.
__version__ = package_version()

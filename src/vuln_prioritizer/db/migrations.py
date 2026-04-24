"""Alembic-compatible migration metadata entry points.

Future Alembic ``env.py`` files can import ``target_metadata`` from this module
without importing API, CLI, or legacy state-store code.
"""

from __future__ import annotations

from collections.abc import Sequence

from sqlalchemy import MetaData

from vuln_prioritizer.db.base import target_metadata

INITIAL_REVISION = "0001_workbench_mvp"
WORKBENCH_TABLES: Sequence[str] = (
    "projects",
    "provider_snapshots",
    "analysis_runs",
    "assets",
    "components",
    "vulnerabilities",
    "findings",
    "finding_occurrences",
    "reports",
    "evidence_bundles",
)


def get_target_metadata() -> MetaData:
    """Return metadata for Alembic autogenerate."""
    return target_metadata

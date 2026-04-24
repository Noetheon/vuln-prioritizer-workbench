"""Alembic migration entry points for Workbench persistence."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from alembic import command
from alembic.config import Config
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


def alembic_config(database_url: str) -> Config:
    """Build an Alembic config that works from source trees and installed wheels."""
    config = Config()
    config.set_main_option("script_location", str(Path(__file__).parent / "alembic"))
    config.set_main_option("sqlalchemy.url", database_url)
    return config


def upgrade_database(database_url: str, revision: str = "head") -> None:
    """Run Workbench database migrations up to the requested revision."""
    command.upgrade(alembic_config(database_url), revision)

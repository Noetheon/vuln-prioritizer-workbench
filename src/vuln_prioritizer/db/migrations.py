"""Alembic migration entry points for Workbench persistence."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import MetaData, create_engine, inspect, text
from sqlalchemy.engine import Engine

from vuln_prioritizer.db.base import target_metadata

INITIAL_REVISION = "0001_workbench_mvp"
CURRENT_REVISION = "0005_workbench_integrations"
LEGACY_REVISION_IDS = {
    "0003_workbench_governance_context": "0003_workbench_governance",
    "0005_workbench_governance_detection_integrations": "0005_workbench_integrations",
}
WORKBENCH_MVP_TABLES: Sequence[str] = (
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
WORKBENCH_TABLES: Sequence[str] = (
    "projects",
    "provider_snapshots",
    "analysis_runs",
    "assets",
    "components",
    "vulnerabilities",
    "findings",
    "finding_occurrences",
    "attack_mappings",
    "finding_attack_contexts",
    "reports",
    "evidence_bundles",
    "waivers",
    "detection_controls",
    "api_tokens",
    "provider_update_jobs",
    "project_config_snapshots",
    "github_issue_exports",
)
WORKBENCH_GOVERNANCE_COLUMNS: Sequence[str] = (
    "under_investigation",
    "waiver_status",
    "waiver_reason",
    "waiver_owner",
    "waiver_expires_on",
    "waiver_review_on",
    "waiver_days_remaining",
    "waiver_scope",
    "waiver_id",
    "waiver_matched_scope",
    "waiver_approval_ref",
    "waiver_ticket_url",
)
WORKBENCH_ATTACK_PROVENANCE_COLUMNS: Sequence[str] = (
    "source_hash",
    "source_path",
    "metadata_hash",
    "metadata_path",
)
WORKBENCH_V04_TABLES: Sequence[str] = tuple(
    table for table in WORKBENCH_TABLES if table != "github_issue_exports"
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


def ensure_database_current(database_url: str) -> None:
    """Upgrade the Workbench database, stamping legacy create_all databases first."""
    config = alembic_config(database_url)
    engine = create_engine(database_url)
    inspector = inspect(engine)
    tables = set(inspector.get_table_names())
    if "alembic_version" in tables:
        _normalize_legacy_revision_ids(engine)
    if WORKBENCH_MVP_TABLES[0] in tables and "alembic_version" not in tables:
        target_revision = INITIAL_REVISION
        if set(WORKBENCH_V04_TABLES).issubset(tables):
            finding_columns = {column["name"] for column in inspector.get_columns("findings")}
            target_revision = (
                "0003_workbench_governance"
                if set(WORKBENCH_GOVERNANCE_COLUMNS).issubset(finding_columns)
                else "0002_workbench_attack_core"
            )
            if target_revision == "0003_workbench_governance":
                attack_columns = {
                    column["name"] for column in inspector.get_columns("attack_mappings")
                }
                if set(WORKBENCH_ATTACK_PROVENANCE_COLUMNS).issubset(attack_columns):
                    target_revision = (
                        CURRENT_REVISION
                        if "github_issue_exports" in tables
                        else "0004_workbench_attack_provenance"
                    )
        command.stamp(config, target_revision)
    command.upgrade(config, "head")


def _normalize_legacy_revision_ids(engine: Engine) -> None:
    """Rewrite pre-Postgres smoke revision ids that exceed Alembic's 32-char column."""
    with engine.begin() as connection:
        for legacy_revision, current_revision in LEGACY_REVISION_IDS.items():
            connection.execute(
                text(
                    "update alembic_version set version_num = :current_revision "
                    "where version_num = :legacy_revision"
                ),
                {
                    "current_revision": current_revision,
                    "legacy_revision": legacy_revision,
                },
            )

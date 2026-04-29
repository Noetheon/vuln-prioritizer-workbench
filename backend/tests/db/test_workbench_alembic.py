from __future__ import annotations

from pathlib import Path

from sqlalchemy import create_engine, inspect, text

from vuln_prioritizer.db.migrations import (
    CURRENT_REVISION,
    LEGACY_REVISION_IDS,
    WORKBENCH_TABLES,
    ensure_database_current,
    upgrade_database,
)


def test_alembic_upgrade_creates_initial_workbench_schema(tmp_path: Path) -> None:
    db_path = tmp_path / "workbench.db"
    database_url = f"sqlite:///{db_path}"

    upgrade_database(database_url)

    engine = create_engine(database_url)
    inspector = inspect(engine)
    tables = set(inspector.get_table_names())
    assert set(WORKBENCH_TABLES) <= tables
    assert "alembic_version" in tables

    with engine.connect() as connection:
        revision = connection.execute(text("select version_num from alembic_version")).scalar_one()
    assert revision == CURRENT_REVISION


def test_alembic_revision_ids_fit_default_version_column() -> None:
    assert len(CURRENT_REVISION) <= 32
    assert all(len(revision) <= 32 for revision in LEGACY_REVISION_IDS.values())


def test_ensure_database_current_normalizes_legacy_revision_ids(tmp_path: Path) -> None:
    db_path = tmp_path / "legacy.db"
    database_url = f"sqlite:///{db_path}"
    upgrade_database(database_url)
    engine = create_engine(database_url)
    with engine.begin() as connection:
        connection.execute(
            text("update alembic_version set version_num = :revision"),
            {"revision": "0005_workbench_governance_detection_integrations"},
        )

    ensure_database_current(database_url)

    with engine.connect() as connection:
        revision = connection.execute(text("select version_num from alembic_version")).scalar_one()
    assert revision == CURRENT_REVISION

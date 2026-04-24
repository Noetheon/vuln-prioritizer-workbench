from __future__ import annotations

from pathlib import Path

from sqlalchemy import create_engine, inspect, text

from vuln_prioritizer.db.migrations import WORKBENCH_TABLES, upgrade_database


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
    assert revision == "0001_workbench_mvp"

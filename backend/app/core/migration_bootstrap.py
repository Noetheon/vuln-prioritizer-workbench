"""Alembic bootstrap helpers for legacy local Workbench databases."""

from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect
from sqlalchemy.engine import Inspector

from app.core.config import settings

ALEMBIC_HEAD = "20260508_0013"
ALEMBIC_INI = Path(__file__).resolve().parents[2] / "alembic.ini"


def stamp_legacy_create_all_database(
    *,
    database_url: str | None = None,
    config_path: Path | None = None,
) -> str | None:
    """Stamp DBs previously created via SQLModel.create_all so Alembic can upgrade them."""
    active_database_url = database_url or settings.SQLALCHEMY_DATABASE_URI
    engine = create_engine(
        active_database_url,
        connect_args=_connect_args(active_database_url),
        pool_pre_ping=True,
    )
    try:
        inspector = inspect(engine)
        table_names = set(inspector.get_table_names())
        if not table_names or "alembic_version" in table_names:
            return None
        revision = _legacy_revision_for_tables(inspector, table_names)
    finally:
        engine.dispose()

    if revision is None:
        return None

    config = Config(str(config_path or ALEMBIC_INI))
    config.set_main_option("sqlalchemy.url", active_database_url)
    command.stamp(config, revision)
    return revision


def _legacy_revision_for_tables(
    inspector: Inspector,
    table_names: set[str],
) -> str | None:
    if "api_token" in table_names:
        api_token_columns = {column["name"] for column in inspector.get_columns("api_token")}
        if "github_issue_export" in table_names:
            if "project_id" not in api_token_columns:
                return "20260430_0009"
            if {"auth_session", "audit_event"}.issubset(table_names):
                if "expires_at" in api_token_columns:
                    return ALEMBIC_HEAD if "rate_limit_bucket" in table_names else "20260508_0012"
                return "20260506_0011"
            return "20260505_0010"
        return "20260430_0008" if "project_id" not in api_token_columns else None
    if "attack_stix_snapshot" in table_names:
        return "20260430_0007"
    if "waiver" in table_names:
        return "20260430_0006"
    if "finding_attack_context" in table_names:
        return "20260429_0005"
    if "report" in table_names:
        return "20260429_0004"
    if "analysis_run" in table_names:
        return "20260428_0003"
    if "finding" in table_names:
        return "20260428_0002"
    if {"project", "user"}.issubset(table_names):
        return "20260428_0001"
    return None


def _connect_args(database_url: str) -> dict[str, bool]:
    if database_url.startswith("sqlite"):
        return {"check_same_thread": False}
    return {}


def main() -> None:
    stamp_legacy_create_all_database()


if __name__ == "__main__":
    main()

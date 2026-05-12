from __future__ import annotations

import json
import os
import sys
from importlib import resources
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text


def main() -> None:
    output_path = (
        Path(sys.argv[1]) if len(sys.argv) > 1 else Path("build/workbench-wheel-smoke.json")
    )
    database_path = output_path.with_suffix(".db").resolve()
    database_url = f"sqlite:///{database_path}"
    database_path.unlink(missing_ok=True)

    os.environ.update(
        {
            "SQLALCHEMY_DATABASE_URI": database_url,
            "SECRET_KEY": "wheel-smoke-secret-key-0123456789abcdef",
            "ALLOWED_HOSTS": "localhost,127.0.0.1,testserver",
            "RATE_LIMIT_ENABLED": "false",
        }
    )

    from app.core.migration_bootstrap import ALEMBIC_HEAD
    from app.main import create_app

    script_location = resources.files("app.alembic")
    config = Config()
    config.set_main_option("script_location", str(script_location))
    config.set_main_option("sqlalchemy.url", database_url)
    command.upgrade(config, "head")

    app = create_app()
    engine = create_engine(database_url, connect_args={"check_same_thread": False})
    try:
        inspector = inspect(engine)
        tables = set(inspector.get_table_names())
        with engine.connect() as connection:
            revision = connection.execute(
                text("SELECT version_num FROM alembic_version")
            ).scalar_one()
    finally:
        engine.dispose()

    if revision != ALEMBIC_HEAD:
        raise SystemExit(f"Expected Alembic head {ALEMBIC_HEAD}, got {revision}.")
    required_tables = {"audit_event", "project"}
    missing = sorted(required_tables - tables)
    if missing:
        raise SystemExit(f"Installed Workbench migration is missing tables: {missing}")
    removed_tables = {"api_token", "auth_session", "user"}
    still_present = sorted(removed_tables & tables)
    if still_present:
        raise SystemExit(f"Installed Workbench migration kept removed tables: {still_present}")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(
            {
                "alembic_head": ALEMBIC_HEAD,
                "api_route_count": len(app.routes),
                "database_url": database_url,
                "status": "ok",
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"{output_path}: OK")


if __name__ == "__main__":
    main()

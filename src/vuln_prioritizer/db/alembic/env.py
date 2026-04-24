"""Alembic environment for the Workbench database."""

from __future__ import annotations

from logging.config import fileConfig
from typing import Any

from alembic import context
from sqlalchemy import engine_from_config, pool

# Import models so Alembic metadata is populated for autogenerate and migrations.
from vuln_prioritizer.db import models as _models  # noqa: F401
from vuln_prioritizer.db.base import target_metadata

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)


def run_migrations_offline() -> None:
    """Run migrations without an active DB connection."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations with an active DB connection."""
    section = config.get_section(config.config_ini_section, {})
    connectable = engine_from_config(
        section,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


def run_migrations() -> None:
    """Dispatch to the online or offline Alembic mode."""
    is_offline = context.is_offline_mode()
    runner: Any = run_migrations_offline if is_offline else run_migrations_online
    runner()


run_migrations()

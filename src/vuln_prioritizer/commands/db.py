"""Workbench database command registrations."""

from __future__ import annotations

import typer

from vuln_prioritizer.cli_support.common import console
from vuln_prioritizer.db.migrations import upgrade_database
from vuln_prioritizer.workbench_config import (
    ensure_workbench_directories,
    load_workbench_settings,
    sqlite_path_from_url,
)


def db_init() -> None:
    """Initialize the Workbench SQLite database."""
    settings = load_workbench_settings()
    ensure_workbench_directories(settings)
    sqlite_path = sqlite_path_from_url(settings.database_url)
    if sqlite_path is not None:
        sqlite_path.parent.mkdir(parents=True, exist_ok=True)
    upgrade_database(settings.database_url)
    console.print(f"[green]Initialized Workbench database at {settings.database_url}[/green]")


def register(db_app: typer.Typer) -> None:
    db_app.command("init")(db_init)

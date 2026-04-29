"""Workbench database command registrations."""

from __future__ import annotations

import typer

from vuln_prioritizer.cli_support.common import console
from vuln_prioritizer.db.migrations import upgrade_database
from vuln_prioritizer.db.session import create_db_engine, create_session_factory
from vuln_prioritizer.services.workbench_artifacts import cleanup_project_artifacts
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


def db_cleanup_artifacts(
    project_id: str | None = typer.Option(None, "--project-id"),
    delete: bool = typer.Option(False, "--delete", help="Delete expired and orphaned files."),
) -> None:
    """Inspect or clean report/evidence artifacts under the Workbench report root."""
    settings = load_workbench_settings()
    ensure_workbench_directories(settings)
    engine = create_db_engine(settings.database_url)
    session_factory = create_session_factory(engine)
    with session_factory() as session:
        result = cleanup_project_artifacts(
            session=session,
            settings=settings,
            project_id=project_id,
            dry_run=not delete,
        )
        session.commit()
    mode = "deleted" if delete else "would delete"
    console.print(
        f"[green]Artifact cleanup {mode} {len(result.deleted_files)} file(s), "
        f"{result.bytes_removed} byte(s).[/green]"
    )
    if result.orphan_files:
        console.print(f"Orphan files: {len(result.orphan_files)}")


def register(db_app: typer.Typer) -> None:
    db_app.command("init")(db_init)
    db_app.command("cleanup-artifacts")(db_cleanup_artifacts)

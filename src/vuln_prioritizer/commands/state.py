"""State command registrations."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import typer

from vuln_prioritizer.cli_support.common import (
    TABLE_AND_JSON_OUTPUT_FORMATS,
    StatePriorityScope,
    StateWaiverStatusFilter,
    TableJsonOutputFormat,
    console,
    exit_input_validation,
    output_format_option,
    validate_command_formats,
    validate_output_mode,
)
from vuln_prioritizer.cli_support.snapshot_rollup import load_snapshot_payload
from vuln_prioritizer.cli_support.state import state_store_or_exit
from vuln_prioritizer.models import (
    StateHistoryEntry,
    StateHistoryMetadata,
    StateHistoryReport,
    StateImportMetadata,
    StateImportReport,
    StateImportSummary,
    StateInitMetadata,
    StateInitReport,
    StateInitSummary,
    StateTopServiceEntry,
    StateTopServicesMetadata,
    StateTopServicesReport,
    StateWaiverEntry,
    StateWaiverMetadata,
    StateWaiverReport,
)
from vuln_prioritizer.reporter import (
    generate_state_history_json,
    generate_state_import_json,
    generate_state_init_json,
    generate_state_top_services_json,
    generate_state_waivers_json,
    render_state_history_table,
    render_state_import_panel,
    render_state_init_panel,
    render_state_top_services_table,
    render_state_waivers_table,
    write_output,
)
from vuln_prioritizer.utils import iso_utc_now, normalize_cve_id


def state_init(
    db: Path = typer.Option(..., "--db", dir_okay=False),
    output: Path | None = typer.Option(None, "--output", dir_okay=False),
    format: TableJsonOutputFormat = output_format_option(
        TableJsonOutputFormat.table, TABLE_AND_JSON_OUTPUT_FORMATS
    ),
) -> None:
    """Initialize an optional local SQLite state store."""
    validate_output_mode(format, output)
    validate_command_formats(
        command_name="state init",
        format=format,
        allowed_formats=set(TABLE_AND_JSON_OUTPUT_FORMATS),
    )

    store = state_store_or_exit(db, expect_existing=False)
    try:
        store.initialize()
        report = StateInitReport(
            metadata=StateInitMetadata(
                generated_at=iso_utc_now(),
                db_path=str(db),
            ),
            summary=StateInitSummary(
                initialized=True,
                snapshot_count=store.snapshot_count(),
            ),
        )
    except (OSError, sqlite3.Error, ValueError) as exc:
        exit_input_validation(str(exc))

    console.print(render_state_init_panel(report))
    if output is not None:
        write_output(output, generate_state_init_json(report))
        console.print(f"[green]Wrote json output to {output}[/green]")


def state_import_snapshot(
    db: Path = typer.Option(..., "--db", dir_okay=False),
    input: Path = typer.Option(..., "--input", exists=True, dir_okay=False, readable=True),
    output: Path | None = typer.Option(None, "--output", dir_okay=False),
    format: TableJsonOutputFormat = output_format_option(
        TableJsonOutputFormat.table, TABLE_AND_JSON_OUTPUT_FORMATS
    ),
) -> None:
    """Import a saved snapshot JSON artifact into the local state store."""
    validate_output_mode(format, output)
    validate_command_formats(
        command_name="state import-snapshot",
        format=format,
        allowed_formats=set(TABLE_AND_JSON_OUTPUT_FORMATS),
    )

    payload = load_snapshot_payload(input)
    store = state_store_or_exit(db, expect_existing=False)
    try:
        summary = store.import_snapshot(snapshot_path=input, payload=payload)
        report = StateImportReport(
            metadata=StateImportMetadata(
                generated_at=iso_utc_now(),
                db_path=str(db),
                input_path=str(input),
            ),
            summary=StateImportSummary(
                imported=bool(summary["imported"]),
                snapshot_id=int(summary["snapshot_id"]),
                snapshot_generated_at=str(summary["snapshot_generated_at"]),
                finding_count=int(summary["finding_count"]),
                snapshot_count=store.snapshot_count(),
            ),
        )
    except (OSError, sqlite3.Error, ValueError) as exc:
        exit_input_validation(str(exc))

    console.print(render_state_import_panel(report))
    if output is not None:
        write_output(output, generate_state_import_json(report))
        console.print(f"[green]Wrote json output to {output}[/green]")


def state_history(
    db: Path = typer.Option(..., "--db", exists=False, dir_okay=False),
    cve: str = typer.Option(..., "--cve"),
    output: Path | None = typer.Option(None, "--output", dir_okay=False),
    format: TableJsonOutputFormat = output_format_option(
        TableJsonOutputFormat.table, TABLE_AND_JSON_OUTPUT_FORMATS
    ),
) -> None:
    """Show persisted per-CVE history across imported snapshots."""
    validate_output_mode(format, output)
    validate_command_formats(
        command_name="state history",
        format=format,
        allowed_formats=set(TABLE_AND_JSON_OUTPUT_FORMATS),
    )

    normalized_cve = normalize_cve_id(cve)
    if normalized_cve is None:
        exit_input_validation(f"{cve!r} is not a valid CVE identifier.")
        raise AssertionError("unreachable")

    store = state_store_or_exit(db, expect_existing=True)
    try:
        items = [
            StateHistoryEntry.model_validate(item)
            for item in store.cve_history(cve_id=normalized_cve)
        ]
    except (OSError, sqlite3.Error, ValueError) as exc:
        exit_input_validation(str(exc))

    report = StateHistoryReport(
        metadata=StateHistoryMetadata(
            generated_at=iso_utc_now(),
            db_path=str(db),
            cve_id=normalized_cve,
            entry_count=len(items),
        ),
        items=items,
    )

    if not items:
        console.print(f"[yellow]No persisted history found for {normalized_cve}.[/yellow]")
    console.print(render_state_history_table(items, report.metadata))
    if output is not None:
        write_output(output, generate_state_history_json(report))
        console.print(f"[green]Wrote json output to {output}[/green]")


def state_waivers(
    db: Path = typer.Option(..., "--db", exists=False, dir_okay=False),
    status: StateWaiverStatusFilter = typer.Option(StateWaiverStatusFilter.all, "--status"),
    latest_only: bool = typer.Option(True, "--latest-only/--all-snapshots"),
    output: Path | None = typer.Option(None, "--output", dir_okay=False),
    format: TableJsonOutputFormat = output_format_option(
        TableJsonOutputFormat.table, TABLE_AND_JSON_OUTPUT_FORMATS
    ),
) -> None:
    """Show waiver lifecycle entries from imported snapshot history."""
    validate_output_mode(format, output)
    validate_command_formats(
        command_name="state waivers",
        format=format,
        allowed_formats=set(TABLE_AND_JSON_OUTPUT_FORMATS),
    )

    store = state_store_or_exit(db, expect_existing=True)
    try:
        items = [
            StateWaiverEntry.model_validate(item)
            for item in store.waiver_entries(
                status_filter=status.value,
                latest_only=latest_only,
            )
        ]
    except (OSError, sqlite3.Error, ValueError) as exc:
        exit_input_validation(str(exc))

    report = StateWaiverReport(
        metadata=StateWaiverMetadata(
            generated_at=iso_utc_now(),
            db_path=str(db),
            status_filter=status.value,
            latest_only=latest_only,
            entry_count=len(items),
        ),
        items=items,
    )

    if not items:
        console.print("[yellow]No persisted waiver entries matched the requested filter.[/yellow]")
    console.print(render_state_waivers_table(items, report.metadata))
    if output is not None:
        write_output(output, generate_state_waivers_json(report))
        console.print(f"[green]Wrote json output to {output}[/green]")


def state_top_services(
    db: Path = typer.Option(..., "--db", exists=False, dir_okay=False),
    days: int = typer.Option(30, "--days", min=1),
    priority: StatePriorityScope = typer.Option(StatePriorityScope.all, "--priority"),
    limit: int = typer.Option(10, "--limit", min=1),
    output: Path | None = typer.Option(None, "--output", dir_okay=False),
    format: TableJsonOutputFormat = output_format_option(
        TableJsonOutputFormat.table, TABLE_AND_JSON_OUTPUT_FORMATS
    ),
) -> None:
    """Show repeated recent services across imported snapshot history."""
    validate_output_mode(format, output)
    validate_command_formats(
        command_name="state top-services",
        format=format,
        allowed_formats=set(TABLE_AND_JSON_OUTPUT_FORMATS),
    )

    store = state_store_or_exit(db, expect_existing=True)
    try:
        items = [
            StateTopServiceEntry.model_validate(item)
            for item in store.top_services(
                days=days,
                priority_filter=priority.value,
                limit=limit,
            )
        ]
    except (OSError, sqlite3.Error, ValueError) as exc:
        exit_input_validation(str(exc))

    report = StateTopServicesReport(
        metadata=StateTopServicesMetadata(
            generated_at=iso_utc_now(),
            db_path=str(db),
            days=days,
            priority_filter=priority.value,
            limit=limit,
            entry_count=len(items),
        ),
        items=items,
    )

    if not items:
        console.print("[yellow]No persisted service entries matched the requested window.[/yellow]")
    console.print(render_state_top_services_table(items, report.metadata))
    if output is not None:
        write_output(output, generate_state_top_services_json(report))
        console.print(f"[green]Wrote json output to {output}[/green]")


def register(state_app: typer.Typer) -> None:
    state_app.command("init")(state_init)
    state_app.command("import-snapshot")(state_import_snapshot)
    state_app.command("history")(state_history)
    state_app.command("waivers")(state_waivers)
    state_app.command("top-services")(state_top_services)

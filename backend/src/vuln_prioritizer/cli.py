"""Typer-based command line interface composition root."""

from __future__ import annotations

from pathlib import Path

import typer

from vuln_prioritizer.cli_support.analysis import (
    build_attack_summary_from_findings as _build_attack_summary_from_findings,
)
from vuln_prioritizer.cli_support.common import (
    console,
    load_runtime_config_for_session,
    merge_default_maps,
    version_callback,
)
from vuln_prioritizer.commands.analysis import register as register_analysis_commands
from vuln_prioritizer.commands.attack import register as register_attack_commands
from vuln_prioritizer.commands.data import register as register_data_commands
from vuln_prioritizer.commands.input import register as register_input_commands
from vuln_prioritizer.commands.report import register as register_report_commands
from vuln_prioritizer.commands.snapshot import register as register_snapshot_commands
from vuln_prioritizer.commands.state import register as register_state_commands
from vuln_prioritizer.runtime_config import build_cli_default_map

app = typer.Typer(help="Prioritize known CVEs with NVD, EPSS, KEV, and ATT&CK context.")
attack_app = typer.Typer(help="Validate and summarize local ATT&CK mapping files.")
data_app = typer.Typer(help="Inspect cache state and local data-source metadata.")
input_app = typer.Typer(help="Validate local input, asset context, and VEX files.")
report_app = typer.Typer(help="Render secondary report formats from exported analysis JSON.")
snapshot_app = typer.Typer(help="Create and compare prioritized snapshots.")
state_app = typer.Typer(help="Persist snapshot history in an optional local SQLite store.")

app.add_typer(attack_app, name="attack")
app.add_typer(data_app, name="data")
app.add_typer(input_app, name="input")
app.add_typer(report_app, name="report")
app.add_typer(snapshot_app, name="snapshot")
app.add_typer(state_app, name="state")


@app.callback()
def callback(
    ctx: typer.Context,
    version: bool = typer.Option(
        False,
        "--version",
        callback=version_callback,
        is_eager=True,
        help="Show the application version and exit.",
    ),
    config: Path | None = typer.Option(None, "--config", dir_okay=False, readable=True),
    no_config: bool = typer.Option(False, "--no-config"),
) -> None:
    """CLI entrypoint."""
    if config is not None and no_config:
        console.print(
            "[red]Input validation failed:[/red] --config and --no-config cannot be combined."
        )
        raise typer.Exit(code=2)

    loaded = load_runtime_config_for_session(config=config, no_config=no_config)
    ctx.obj = {"runtime_config": loaded}
    if loaded is not None:
        ctx.default_map = merge_default_maps(ctx.default_map, build_cli_default_map(loaded))


register_analysis_commands(app)
register_snapshot_commands(app, snapshot_app)
register_state_commands(state_app)
register_attack_commands(attack_app)
register_data_commands(data_app)
register_input_commands(input_app)
register_report_commands(report_app)


def main() -> None:
    """Entrypoint used by the console script."""
    app()


__all__ = ["app", "main", "_build_attack_summary_from_findings"]


if __name__ == "__main__":
    main()

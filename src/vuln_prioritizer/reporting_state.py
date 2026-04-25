"""State-command terminal renderers."""

from __future__ import annotations

from rich.panel import Panel
from rich.table import Table

from vuln_prioritizer.models import (
    StateHistoryEntry,
    StateHistoryMetadata,
    StateImportReport,
    StateInitReport,
    StateServiceHistoryEntry,
    StateServiceHistoryMetadata,
    StateTopServiceEntry,
    StateTopServicesMetadata,
    StateTrendEntry,
    StateTrendsMetadata,
    StateWaiverEntry,
    StateWaiverMetadata,
)
from vuln_prioritizer.reporting_format import _format_state_waiver_status


def render_state_init_panel(report: StateInitReport) -> Panel:
    """Render the terminal summary for state init."""
    return Panel(
        "\n".join(
            [
                f"Schema version: {report.metadata.schema_version}",
                f"Database path: {report.metadata.db_path}",
                f"Snapshots imported: {report.summary.snapshot_count}",
            ]
        ),
        title="State Store Initialized",
    )


def render_state_import_panel(report: StateImportReport) -> Panel:
    """Render the terminal summary for state import."""
    lines = [
        f"Database path: {report.metadata.db_path}",
        f"Input snapshot: {report.metadata.input_path}",
        f"Imported: {'yes' if report.summary.imported else 'no (duplicate)'}",
        "Snapshot id: "
        + (str(report.summary.snapshot_id) if report.summary.snapshot_id is not None else "N.A."),
        f"Snapshot generated at: {report.summary.snapshot_generated_at or 'N.A.'}",
        f"Findings imported: {report.summary.finding_count}",
        f"Snapshots in store: {report.summary.snapshot_count}",
    ]
    return Panel("\n".join(lines), title="State Snapshot Import")


def render_state_history_table(
    items: list[StateHistoryEntry],
    metadata: StateHistoryMetadata,
) -> Table:
    """Build the Rich table shown for persisted CVE history."""
    table = Table(title=f"State History: {metadata.cve_id}", show_lines=False)
    table.add_column("Snapshot", style="bold")
    table.add_column("Priority")
    table.add_column("KEV")
    table.add_column("Waiver")
    table.add_column("Owner")
    table.add_column("Services", overflow="fold")
    table.add_column("Asset IDs", overflow="fold")
    for item in items:
        table.add_row(
            item.snapshot_generated_at,
            item.priority_label,
            "Yes" if item.in_kev else "No",
            _format_state_waiver_status(item.waived, item.waiver_status),
            item.waiver_owner or "N.A.",
            ", ".join(item.services) or "N.A.",
            ", ".join(item.asset_ids) or "N.A.",
        )
    table.caption = f"Entries: {metadata.entry_count}"
    return table


def render_state_waivers_table(
    items: list[StateWaiverEntry],
    metadata: StateWaiverMetadata,
) -> Table:
    """Build the Rich table shown for persisted waiver views."""
    table = Table(title="Persisted Waiver View", show_lines=False)
    table.add_column("Snapshot", style="bold")
    table.add_column("CVE")
    table.add_column("Priority")
    table.add_column("Status")
    table.add_column("Owner")
    table.add_column("Review On")
    table.add_column("Expires On")
    for item in items:
        table.add_row(
            item.snapshot_generated_at,
            item.cve_id,
            item.priority_label,
            item.waiver_status,
            item.waiver_owner or "N.A.",
            item.waiver_review_on or "N.A.",
            item.waiver_expires_on or "N.A.",
        )
    scope_label = "latest snapshot only" if metadata.latest_only else "all snapshots"
    table.caption = (
        f"Entries: {metadata.entry_count} | Filter: {metadata.status_filter} | Scope: {scope_label}"
    )
    return table


def render_state_top_services_table(
    items: list[StateTopServiceEntry],
    metadata: StateTopServicesMetadata,
) -> Table:
    """Build the Rich table shown for persisted top-service views."""
    table = Table(title="Persisted Top Services", show_lines=False)
    table.add_column("Service", style="bold")
    table.add_column("Occurrences")
    table.add_column("Distinct CVEs")
    table.add_column("Snapshots")
    table.add_column("KEV")
    table.add_column("Latest Seen")
    for item in items:
        table.add_row(
            item.service,
            str(item.occurrence_count),
            str(item.distinct_cves),
            str(item.snapshot_count),
            str(item.kev_count),
            item.latest_seen or "N.A.",
        )
    table.caption = (
        f"Entries: {metadata.entry_count} | Days: {metadata.days} | "
        f"Priority: {metadata.priority_filter} | Limit: {metadata.limit}"
    )
    return table


def render_state_trends_table(
    items: list[StateTrendEntry],
    metadata: StateTrendsMetadata,
) -> Table:
    """Build the Rich table shown for persisted snapshot trends."""
    table = Table(title="Persisted Snapshot Trends", show_lines=False)
    table.add_column("Snapshot", style="bold")
    table.add_column("Findings")
    table.add_column("Critical")
    table.add_column("High")
    table.add_column("KEV")
    table.add_column("Attack")
    table.add_column("Waived")
    for item in items:
        table.add_row(
            item.snapshot_generated_at,
            str(item.findings_count),
            str(item.critical_count),
            str(item.high_count),
            str(item.kev_count),
            str(item.attack_mapped_count),
            str(item.waived_count),
        )
    table.caption = (
        f"Entries: {metadata.entry_count} | Days: {metadata.days} | "
        f"Priority: {metadata.priority_filter}"
    )
    return table


def render_state_service_history_table(
    items: list[StateServiceHistoryEntry],
    metadata: StateServiceHistoryMetadata,
) -> Table:
    """Build the Rich table shown for persisted service history."""
    table = Table(title=f"Service History: {metadata.service}", show_lines=False)
    table.add_column("Snapshot", style="bold")
    table.add_column("Occurrences")
    table.add_column("Distinct CVEs")
    table.add_column("Critical")
    table.add_column("High")
    table.add_column("KEV")
    table.add_column("CVEs", overflow="fold")
    for item in items:
        table.add_row(
            item.snapshot_generated_at,
            str(item.occurrence_count),
            str(item.distinct_cves),
            str(item.critical_count),
            str(item.high_count),
            str(item.kev_count),
            ", ".join(item.cve_ids) or "N.A.",
        )
    table.caption = (
        f"Entries: {metadata.entry_count} | Days: {metadata.days} | "
        f"Priority: {metadata.priority_filter}"
    )
    return table

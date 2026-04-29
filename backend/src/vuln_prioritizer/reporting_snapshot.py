"""Snapshot diff and rollup renderers."""

from __future__ import annotations

from rich.table import Table

from vuln_prioritizer.models import (
    RollupBucket,
    RollupMetadata,
    SnapshotDiffItem,
    SnapshotDiffMetadata,
    SnapshotDiffSummary,
)
from vuln_prioritizer.reporting_format import (
    _format_rollup_candidates,
    _format_rollup_reason,
    escape_pipes,
)


def render_snapshot_diff_table(
    items: list[SnapshotDiffItem],
    summary: SnapshotDiffSummary,
    metadata: SnapshotDiffMetadata,
) -> Table:
    """Build the Rich diff table shown in the terminal."""
    table = Table(title="Snapshot Diff", show_lines=False)
    table.add_column("CVE", style="bold")
    table.add_column("Category")
    table.add_column("Before")
    table.add_column("After")
    table.add_column("Context Changes", overflow="fold")
    for item in items:
        table.add_row(
            item.cve_id,
            item.category,
            item.before_priority or "N.A.",
            item.after_priority or "N.A.",
            ", ".join(item.context_change_fields) or "N.A.",
        )
    table.caption = (
        "Added: "
        f"{summary.added} | Removed: {summary.removed} | Up: {summary.priority_up} | "
        f"Down: {summary.priority_down} | Context changed: {summary.context_changed} | "
        f"Unchanged: {summary.unchanged}"
    )
    return table


def generate_snapshot_diff_markdown(
    items: list[SnapshotDiffItem],
    summary: SnapshotDiffSummary,
    metadata: SnapshotDiffMetadata,
) -> str:
    """Render a Markdown snapshot diff report."""
    lines = [
        "# Snapshot Diff",
        "",
        f"- Generated at: `{metadata.generated_at}`",
        f"- Before: `{metadata.before_path}`",
        f"- After: `{metadata.after_path}`",
        f"- Include unchanged: `{'yes' if metadata.include_unchanged else 'no'}`",
        f"- Added: {summary.added}",
        f"- Removed: {summary.removed}",
        f"- Priority up: {summary.priority_up}",
        f"- Priority down: {summary.priority_down}",
        f"- Context changed: {summary.context_changed}",
        f"- Unchanged: {summary.unchanged}",
        "",
        "## Items",
        "",
        "| CVE ID | Category | Before | After | Context Changes |",
        "| --- | --- | --- | --- | --- |",
    ]
    for item in items:
        lines.append(
            "| "
            + " | ".join(
                [
                    item.cve_id,
                    escape_pipes(item.category),
                    escape_pipes(item.before_priority or "N.A."),
                    escape_pipes(item.after_priority or "N.A."),
                    escape_pipes(", ".join(item.context_change_fields) or "N.A."),
                ]
            )
            + " |"
        )
    return "\n".join(lines) + "\n"


def render_rollup_table(
    buckets: list[RollupBucket],
    metadata: RollupMetadata,
) -> Table:
    """Build the Rich rollup table shown in the terminal."""
    table = Table(title=f"{metadata.dimension.title()} Rollup", show_lines=False)
    table.add_column("Rank")
    table.add_column(metadata.dimension.title(), style="bold")
    table.add_column("Priority")
    table.add_column("Actionable/Total")
    table.add_column("Critical")
    table.add_column("KEV")
    table.add_column("Waived")
    table.add_column("Owners", overflow="fold")
    table.add_column("Patch First", overflow="fold")
    table.add_column("Why First", overflow="fold")
    table.add_column("Next Actions", overflow="fold")
    for bucket in buckets:
        table.add_row(
            str(bucket.remediation_rank),
            bucket.bucket,
            bucket.highest_priority,
            f"{bucket.actionable_count}/{bucket.finding_count}",
            str(bucket.critical_count),
            str(bucket.kev_count),
            str(bucket.waived_count),
            ", ".join(bucket.owners) or "N.A.",
            _format_rollup_candidates(bucket.top_candidates),
            _format_rollup_reason(bucket),
            ", ".join(bucket.recommended_actions) or "N.A.",
        )
    return table


def generate_rollup_markdown(
    buckets: list[RollupBucket],
    metadata: RollupMetadata,
) -> str:
    """Render a Markdown rollup report."""
    buckets_header = (
        "| Rank | Bucket | Priority | Actionable/Total | Critical | KEV | Waived | Owners | "
        + "Patch First | Why First | Next Actions |"
    )
    lines = [
        f"# {metadata.dimension.title()} Rollup",
        "",
        f"- Generated at: `{metadata.generated_at}`",
        f"- Input path: `{metadata.input_path}`",
        f"- Input kind: `{metadata.input_kind}`",
        f"- Dimension: `{metadata.dimension}`",
        f"- Buckets: {metadata.bucket_count}",
        f"- Top remediation candidates per bucket: {metadata.top}",
        "",
        "## Buckets",
        "",
        buckets_header,
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for bucket in buckets:
        lines.append(
            "| "
            + " | ".join(
                [
                    str(bucket.remediation_rank),
                    escape_pipes(bucket.bucket),
                    bucket.highest_priority,
                    f"{bucket.actionable_count}/{bucket.finding_count}",
                    str(bucket.critical_count),
                    str(bucket.kev_count),
                    str(bucket.waived_count),
                    escape_pipes(", ".join(bucket.owners) or "N.A."),
                    escape_pipes(_format_rollup_candidates(bucket.top_candidates)),
                    escape_pipes(_format_rollup_reason(bucket)),
                    escape_pipes(", ".join(bucket.recommended_actions) or "N.A."),
                ]
            )
            + " |"
        )
    return "\n".join(lines) + "\n"

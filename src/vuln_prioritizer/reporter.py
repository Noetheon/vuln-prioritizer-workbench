"""Report generation facade and terminal rendering."""

from __future__ import annotations

from html import escape
from pathlib import Path

from rich.console import Group
from rich.panel import Panel
from rich.table import Table

from vuln_prioritizer.models import (
    AnalysisContext,
    AttackData,
    ComparisonFinding,
    EpssData,
    EvidenceBundleVerificationItem,
    EvidenceBundleVerificationSummary,
    KevData,
    NvdData,
    PrioritizedFinding,
    RollupBucket,
    RollupMetadata,
    SnapshotDiffItem,
    SnapshotDiffMetadata,
    SnapshotDiffSummary,
    StateHistoryEntry,
    StateHistoryMetadata,
    StateImportReport,
    StateInitReport,
    StateTopServiceEntry,
    StateTopServicesMetadata,
    StateWaiverEntry,
    StateWaiverMetadata,
)
from vuln_prioritizer.reporting_format import (
    _attack_methodology_lines,
    _attack_summary_lines,
    _capability_groups,
    _format_attack_indicator,
    _format_distribution,
    _format_exploit_status,
    _format_priority_indicator,
    _format_rollup_candidates,
    _format_rollup_reason,
    _format_state_waiver_status,
    _format_vex_statuses,
    _format_waiver_status,
    _mapping_types,
    _priority_display_label,
    _run_metadata_lines,
    _summary_lines,
    _warning_lines,
    comma_or_na,
    escape_pipes,
    format_change,
    format_score,
    normalize_whitespace,
    truncate_text,
)
from vuln_prioritizer.reporting_payloads import (
    build_analysis_report_payload,
    build_snapshot_report_payload,
    generate_compare_json,
    generate_doctor_json,
    generate_evidence_bundle_manifest_json,
    generate_evidence_bundle_verification_json,
    generate_explain_json,
    generate_json_report,
    generate_rollup_json,
    generate_sarif_report,
    generate_snapshot_diff_json,
    generate_state_history_json,
    generate_state_import_json,
    generate_state_init_json,
    generate_state_top_services_json,
    generate_state_waivers_json,
    generate_summary_markdown,
)

__all__ = [
    "build_analysis_report_payload",
    "build_snapshot_report_payload",
    "generate_compare_json",
    "generate_compare_markdown",
    "generate_doctor_json",
    "generate_evidence_bundle_manifest_json",
    "generate_evidence_bundle_verification_json",
    "generate_explain_json",
    "generate_explain_markdown",
    "generate_html_report",
    "generate_json_report",
    "generate_markdown_report",
    "generate_rollup_json",
    "generate_rollup_markdown",
    "generate_sarif_report",
    "generate_snapshot_diff_json",
    "generate_snapshot_diff_markdown",
    "generate_state_history_json",
    "generate_state_import_json",
    "generate_state_init_json",
    "generate_state_top_services_json",
    "generate_state_waivers_json",
    "generate_summary_markdown",
    "render_compare_table",
    "render_evidence_bundle_verification_table",
    "render_explain_view",
    "render_findings_table",
    "render_rollup_table",
    "render_snapshot_diff_table",
    "render_state_history_table",
    "render_state_import_panel",
    "render_state_init_panel",
    "render_state_top_services_table",
    "render_state_waivers_table",
    "render_summary_panel",
    "write_output",
]


def render_findings_table(findings: list[PrioritizedFinding]) -> Table:
    """Build the Rich table shown in the terminal."""
    table = Table(title="Vulnerability Prioritization", show_lines=False)
    table.add_column("CVE", style="bold")
    table.add_column("Priority")
    table.add_column("CVSS")
    table.add_column("EPSS")
    table.add_column("KEV")
    table.add_column("ATT&CK")
    table.add_column("Attack Relevance")
    table.add_column("Source")
    table.add_column("Description", overflow="fold")
    table.add_column("Recommended Action", overflow="fold")

    for finding in findings:
        table.add_row(
            finding.cve_id,
            _format_priority_indicator(
                finding.priority_label,
                finding.suppressed_by_vex,
                in_kev=finding.in_kev,
                waived=finding.waived,
                waiver_status=finding.waiver_status,
            ),
            format_score(finding.cvss_base_score, digits=1),
            format_score(finding.epss, digits=3),
            "Yes" if finding.in_kev else "No",
            _format_attack_indicator(finding.attack_mapped, len(finding.attack_technique_details)),
            finding.attack_relevance,
            ", ".join(finding.provenance.source_formats) or "N.A.",
            truncate_text(finding.description or "N.A.", 90),
            truncate_text(finding.recommended_action, 120),
        )

    return table


def render_compare_table(comparisons: list[ComparisonFinding]) -> Table:
    """Build the Rich comparison table shown in the terminal."""
    table = Table(title="CVSS-only vs Enriched Prioritization", show_lines=False)
    table.add_column("CVE", style="bold")
    table.add_column("CVSS-only")
    table.add_column("Enriched")
    table.add_column("VEX")
    table.add_column("ATT&CK")
    table.add_column("Relevance")
    table.add_column("CVSS")
    table.add_column("EPSS")
    table.add_column("KEV")
    table.add_column("Reason", overflow="fold")

    for row in comparisons:
        table.add_row(
            row.cve_id,
            row.cvss_only_label,
            _format_priority_indicator(
                row.enriched_label,
                row.suppressed_by_vex,
                in_kev=row.in_kev,
                waived=row.waived,
                waiver_status=row.waiver_status,
            ),
            "Under investigation" if row.under_investigation else "N.A.",
            _format_attack_indicator(row.attack_mapped, row.mapped_technique_count),
            row.attack_relevance,
            format_score(row.cvss_base_score, digits=1),
            format_score(row.epss, digits=3),
            "Yes" if row.in_kev else "No",
            truncate_text(row.change_reason, 100),
        )

    return table


def render_summary_panel(
    context: AnalysisContext,
    *,
    mode: str = "analyze",
    changed_count: int | None = None,
) -> Panel:
    """Render the shared terminal summary panel."""
    lines = [
        f"Schema version: {context.schema_version}",
        f"Total input rows: {context.total_input}",
        f"Valid unique CVEs: {context.valid_input}",
        f"Occurrences: {context.occurrences_count}",
        f"Input format: {context.input_format}",
        f"Merged inputs: {context.merged_input_count}",
        f"Findings shown: {context.findings_count}",
        f"Filtered out: {context.filtered_out_count}",
        f"Locked provider data: {'yes' if context.locked_provider_data else 'no'}",
        f"NVD hits: {context.nvd_hits}/{context.valid_input}",
        f"EPSS hits: {context.epss_hits}/{context.valid_input}",
        f"KEV hits: {context.kev_hits}/{context.valid_input}",
    ]
    if context.attack_enabled:
        lines.extend(
            [
                f"ATT&CK source: {context.attack_source}",
                f"ATT&CK hits: {context.attack_hits}/{context.valid_input}",
                f"Mapped CVEs shown: {context.attack_summary.mapped_cves}",
                f"Unmapped CVEs shown: {context.attack_summary.unmapped_cves}",
            ]
        )
        if context.mapping_framework_version:
            lines.append(f"Mapping version: {context.mapping_framework_version}")
        if context.attack_version:
            lines.append(f"ATT&CK version: {context.attack_version}")
    if context.source_stats:
        lines.append("Source stats: " + _format_distribution(context.source_stats))
    if context.input_sources:
        lines.extend(
            [
                "Input sources: "
                + "; ".join(
                    f"{Path(source.input_path).name} ({source.input_format}, "
                    f"rows={source.total_rows}, unique_cves={source.unique_cves})"
                    for source in context.input_sources
                )
            ]
        )
    if context.duplicate_cve_count:
        lines.append(f"Duplicate CVEs collapsed: {context.duplicate_cve_count}")
    if context.provider_snapshot_file:
        lines.append(f"Provider snapshot: {context.provider_snapshot_file}")
    if context.provider_snapshot_sources:
        lines.append("Provider snapshot sources: " + ", ".join(context.provider_snapshot_sources))
    if context.nvd_diagnostics.requested:
        diagnostics = context.nvd_diagnostics
        lines.append(
            "NVD diagnostics: "
            + f"requested={diagnostics.requested}, "
            + f"cache_hits={diagnostics.cache_hits}, "
            + f"network_fetches={diagnostics.network_fetches}, "
            + f"failures={diagnostics.failures}, "
            + f"content_hits={diagnostics.content_hits}"
        )
    if context.suppressed_by_vex:
        lines.append(f"Suppressed by VEX: {context.suppressed_by_vex}")
    if context.under_investigation_count:
        lines.append(f"Under investigation: {context.under_investigation_count}")
    if context.asset_match_conflict_count:
        lines.append(f"Asset-context conflicts resolved: {context.asset_match_conflict_count}")
    if context.vex_conflict_count:
        lines.append(f"VEX conflicts resolved: {context.vex_conflict_count}")
    if context.waived_count:
        lines.append(f"Waived: {context.waived_count}")
    if context.waiver_review_due_count:
        lines.append(f"Waiver review due: {context.waiver_review_due_count}")
    if context.expired_waiver_count:
        lines.append(f"Expired waivers: {context.expired_waiver_count}")

    if mode == "compare" and changed_count is not None:
        unchanged_count = max(context.findings_count - changed_count, 0)
        lines.extend(
            [
                f"Changed rows: {changed_count}",
                f"Unchanged rows: {unchanged_count}",
            ]
        )

    for label in ("Critical", "High", "Medium", "Low"):
        lines.append(f"{label}: {context.counts_by_priority.get(label, 0)}")

    if context.active_filters:
        lines.append("Active filters: " + ", ".join(context.active_filters))
    if context.policy_overrides:
        lines.append("Policy overrides: " + ", ".join(context.policy_overrides))

    return Panel("\n".join(lines), title="Summary")


def generate_markdown_report(
    findings: list[PrioritizedFinding],
    context: AnalysisContext,
) -> str:
    """Render the Markdown report."""
    findings_header = (
        "| CVE ID | Description | CVSS | Severity | CVSS Version | EPSS | EPSS Percentile | "
        + "KEV | ATT&CK | Attack Relevance | Sources | Asset Criticality | VEX | Waiver | "
        + "Priority | Rationale | Recommended Action | Context Recommendation |"
    )
    findings_divider = (
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | "
        + "--- | --- | --- | --- | --- |"
    )
    attack_header = (
        "| CVE ID | Mapping Types | Techniques | Tactics | Capability Groups | ATT&CK Note |"
    )
    lines = [
        "# Vulnerability Prioritization Report",
        "",
        "## Run Metadata",
    ]
    lines.extend(_run_metadata_lines(context))
    lines.extend(["", "## Data Sources"])
    lines.extend(f"- {source}" for source in context.data_sources)
    lines.extend(["", "## Methodology"])
    lines.extend(f"- {line}" for line in context.priority_policy.methodology_lines())
    lines.extend(_attack_methodology_lines(context))
    lines.extend(["", "## Summary"])
    lines.extend(_summary_lines(context))
    lines.extend(["", "## ATT&CK Context Summary"])
    lines.extend(_attack_summary_lines(context.attack_summary, context.attack_enabled))
    lines.extend(["", "## Warnings"])
    lines.extend(_warning_lines(context.warnings))
    lines.extend(
        [
            "",
            "## Findings",
            "",
            findings_header,
            findings_divider,
        ]
    )

    for finding in findings:
        lines.append(
            "| "
            + " | ".join(
                [
                    finding.cve_id,
                    escape_pipes(finding.description or "N.A."),
                    format_score(finding.cvss_base_score, digits=1),
                    escape_pipes(finding.cvss_severity or "N.A."),
                    escape_pipes(finding.cvss_version or "N.A."),
                    format_score(finding.epss, digits=3),
                    format_score(finding.epss_percentile, digits=3),
                    "Yes" if finding.in_kev else "No",
                    escape_pipes(
                        _format_attack_indicator(
                            finding.attack_mapped,
                            len(finding.attack_technique_details),
                        )
                    ),
                    escape_pipes(finding.attack_relevance),
                    escape_pipes(", ".join(finding.provenance.source_formats) or "N.A."),
                    escape_pipes(finding.highest_asset_criticality or "N.A."),
                    escape_pipes(_format_vex_statuses(finding.provenance.vex_statuses)),
                    escape_pipes(_format_waiver_status(finding)),
                    finding.priority_label,
                    escape_pipes(finding.rationale),
                    escape_pipes(finding.recommended_action),
                    escape_pipes(finding.context_recommendation or "N.A."),
                ]
            )
            + " |"
        )

    lines.extend(["", "## ATT&CK-mapped CVEs", ""])
    if any(finding.attack_mapped for finding in findings):
        lines.extend(
            [
                attack_header,
                "| --- | --- | --- | --- | --- | --- |",
            ]
        )
        for finding in findings:
            if not finding.attack_mapped:
                continue
            lines.append(
                "| "
                + " | ".join(
                    [
                        finding.cve_id,
                        escape_pipes(", ".join(_mapping_types(finding.attack_mappings)) or "N.A."),
                        escape_pipes(", ".join(finding.attack_techniques) or "N.A."),
                        escape_pipes(", ".join(finding.attack_tactics) or "N.A."),
                        escape_pipes(
                            ", ".join(_capability_groups(finding.attack_mappings)) or "N.A."
                        ),
                        escape_pipes(finding.attack_note or "N.A."),
                    ]
                )
                + " |"
            )
    else:
        lines.append("No mapped CVEs were included in this export.")

    lines.extend(["", "## Finding Provenance", ""])
    if findings:
        lines.extend(
            [
                "| CVE ID | Sources | Components | Paths | Fix Versions | Targets | VEX Statuses |",
                "| --- | --- | --- | --- | --- | --- | --- |",
            ]
        )
        for finding in findings:
            lines.append(
                "| "
                + " | ".join(
                    [
                        finding.cve_id,
                        escape_pipes(", ".join(finding.provenance.source_formats) or "N.A."),
                        escape_pipes(", ".join(finding.provenance.components) or "N.A."),
                        escape_pipes(", ".join(finding.provenance.affected_paths) or "N.A."),
                        escape_pipes(", ".join(finding.provenance.fix_versions) or "N.A."),
                        escape_pipes(", ".join(finding.provenance.targets) or "N.A."),
                        escape_pipes(_format_vex_statuses(finding.provenance.vex_statuses)),
                    ]
                )
                + " |"
            )

    return "\n".join(lines) + "\n"


def generate_compare_markdown(
    comparisons: list[ComparisonFinding],
    context: AnalysisContext,
) -> str:
    """Render the Markdown comparison report."""
    comparison_header = (
        "| CVE ID | Description | CVSS-only | Enriched | VEX | ATT&CK | Attack Relevance | "
        + "Delta | Changed | CVSS | EPSS | KEV | Waiver | Reason |"
    )
    changed_count = sum(1 for row in comparisons if row.changed)
    lines = [
        "# Vulnerability Priority Comparison Report",
        "",
        "## Run Metadata",
    ]
    lines.extend(_run_metadata_lines(context))
    lines.extend(
        [
            "",
            "## Baselines",
            "- CVSS-only: Critical >= 9.0, High >= 7.0, Medium >= 4.0, Low otherwise",
            "- Enriched thresholds:",
        ]
    )
    lines.extend(f"- {line}" for line in context.priority_policy.methodology_lines())
    lines.extend(_attack_methodology_lines(context))
    lines.extend(["", "## Data Sources"])
    lines.extend(f"- {source}" for source in context.data_sources)
    lines.extend(["", "## Summary"])
    lines.extend(_summary_lines(context))
    lines.append(f"- Changed rows: {changed_count}")
    lines.append(f"- Unchanged rows: {max(context.findings_count - changed_count, 0)}")
    lines.extend(["", "## ATT&CK Context Summary"])
    lines.extend(_attack_summary_lines(context.attack_summary, context.attack_enabled))
    lines.extend(["", "## Warnings"])
    lines.extend(_warning_lines(context.warnings))
    lines.extend(
        [
            "",
            "## Comparison",
            "",
            comparison_header,
            "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
        ]
    )

    for row in comparisons:
        lines.append(
            "| "
            + " | ".join(
                [
                    row.cve_id,
                    escape_pipes(row.description or "N.A."),
                    row.cvss_only_label,
                    escape_pipes(
                        _priority_display_label(
                            row.enriched_label,
                            row.in_kev,
                            row.waived,
                            row.waiver_status,
                        )
                    ),
                    "under_investigation" if row.under_investigation else "N.A.",
                    escape_pipes(
                        _format_attack_indicator(
                            row.attack_mapped,
                            row.mapped_technique_count,
                        )
                    ),
                    escape_pipes(row.attack_relevance),
                    escape_pipes(format_change(row.delta_rank)),
                    "Yes" if row.changed else "No",
                    format_score(row.cvss_base_score, digits=1),
                    format_score(row.epss, digits=3),
                    "Yes" if row.in_kev else "No",
                    (
                        f"owner={row.waiver_owner or 'N.A.'}, "
                        f"expires={row.waiver_expires_on or 'N.A.'}"
                        if row.waived
                        else "N.A."
                    ),
                    escape_pipes(row.change_reason),
                ]
            )
            + " |"
        )

    return "\n".join(lines) + "\n"


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


def render_evidence_bundle_verification_table(
    items: list[EvidenceBundleVerificationItem],
    summary: EvidenceBundleVerificationSummary,
) -> Table:
    """Build the Rich table shown for evidence bundle verification."""
    table = Table(title="Evidence Bundle Verification", show_lines=False)
    table.add_column("Path", style="bold")
    table.add_column("Status")
    table.add_column("Detail", overflow="fold")
    for item in items:
        table.add_row(item.path, item.status.upper(), item.detail)
    if not items and summary.ok:
        table.add_row("manifest.json", "OK", "No bundle integrity issues were detected.")
    return table


def write_output(path: Path, content: str) -> None:
    """Write report content to disk."""
    path.parent.mkdir(parents=True, exist_ok=True)
    normalized_content = content if content.endswith("\n") else content + "\n"
    normalized_lines = [line.rstrip() for line in normalized_content.splitlines()]
    path.write_text("\n".join(normalized_lines) + "\n", encoding="utf-8")


def render_explain_view(
    finding: PrioritizedFinding,
    nvd: NvdData,
    epss: EpssData,
    kev: KevData,
    attack: AttackData,
    comparison: ComparisonFinding | None = None,
) -> Group:
    """Build a detailed terminal view for one CVE."""
    signal_table = Table(title=f"Explanation for {finding.cve_id}", show_header=False)
    signal_table.add_column("Field", style="bold cyan")
    signal_table.add_column("Value")
    signal_table.add_row("Priority", finding.priority_label)
    signal_table.add_row("CVSS", format_score(finding.cvss_base_score, digits=1))
    signal_table.add_row("CVSS Severity", finding.cvss_severity or "N.A.")
    signal_table.add_row("CVSS Version", finding.cvss_version or "N.A.")
    signal_table.add_row("EPSS", format_score(finding.epss, digits=3))
    signal_table.add_row("EPSS Percentile", format_score(finding.epss_percentile, digits=3))
    signal_table.add_row("In KEV", "Yes" if finding.in_kev else "No")
    signal_table.add_row("Exploit Status", _format_exploit_status(finding.in_kev))
    signal_table.add_row("Published", nvd.published or "N.A.")
    signal_table.add_row("Last Modified", nvd.last_modified or "N.A.")
    signal_table.add_row("CWEs", comma_or_na(nvd.cwes))
    signal_table.add_row("ATT&CK Source", attack.source)
    signal_table.add_row("ATT&CK Relevance", attack.attack_relevance)
    signal_table.add_row("ATT&CK Techniques", comma_or_na(attack.attack_techniques))
    signal_table.add_row("ATT&CK Tactics", comma_or_na(attack.attack_tactics))
    signal_table.add_row("ATT&CK Note", attack.attack_note or "N.A.")
    signal_table.add_row("Input Sources", comma_or_na(finding.provenance.source_formats))
    signal_table.add_row("Components", comma_or_na(finding.provenance.components))
    signal_table.add_row("Targets", comma_or_na(finding.provenance.targets))
    signal_table.add_row("Asset Criticality", finding.highest_asset_criticality or "N.A.")
    signal_table.add_row("Asset Count", str(finding.asset_count))
    signal_table.add_row("VEX Statuses", _format_vex_statuses(finding.provenance.vex_statuses))
    signal_table.add_row("Remediation Strategy", finding.remediation.strategy)
    signal_table.add_row("Remediation Ecosystem", finding.remediation.ecosystem or "N.A.")
    signal_table.add_row("Waiver", _format_waiver_status(finding))
    signal_table.add_row("KEV Vendor", kev.vendor_project or "N.A.")
    signal_table.add_row("KEV Product", kev.product or "N.A.")
    signal_table.add_row("KEV Required Action", kev.required_action or "N.A.")
    signal_table.add_row("KEV Due Date", kev.due_date or "N.A.")
    if comparison is not None:
        signal_table.add_row("CVSS-only Baseline", comparison.cvss_only_label)
        signal_table.add_row("Delta vs Baseline", format_change(comparison.delta_rank))

    mappings_table = Table(title="ATT&CK Mappings")
    mappings_table.add_column("Type")
    mappings_table.add_column("Technique")
    mappings_table.add_column("Tactics")
    mappings_table.add_column("Capability Group")

    if attack.mappings:
        tactics_by_id = {
            technique.attack_object_id: comma_or_na(technique.tactics)
            for technique in attack.techniques
        }
        for mapping in attack.mappings:
            mappings_table.add_row(
                mapping.mapping_type or "N.A.",
                f"{mapping.attack_object_id} {mapping.attack_object_name or ''}".strip(),
                tactics_by_id.get(mapping.attack_object_id, "N.A."),
                mapping.capability_group or "N.A.",
            )
    else:
        mappings_table.add_row("N.A.", "No CTID mapping", "N.A.", "N.A.")

    description_panel = Panel(
        normalize_whitespace(nvd.description or "N.A."),
        title="Description",
    )
    rationale_panel = Panel(normalize_whitespace(finding.rationale), title="Rationale")
    attack_panel = Panel(
        normalize_whitespace(attack.attack_rationale or "No ATT&CK rationale available."),
        title="ATT&CK Context",
    )
    comparison_panel = Panel(
        normalize_whitespace(comparison.change_reason if comparison is not None else "N.A."),
        title="Comparison",
    )
    action_panel = Panel(
        normalize_whitespace(finding.recommended_action), title="Recommended Action"
    )
    context_panel = Panel(
        normalize_whitespace(finding.context_recommendation or "No context recommendation."),
        title="Context Recommendation",
    )
    applicability_table = Table(title="Applicability")
    applicability_table.add_column("Component")
    applicability_table.add_column("Target")
    applicability_table.add_column("VEX Status")
    applicability_table.add_column("Justification")
    applicability_table.add_column("Action")
    if finding.provenance.occurrences:
        for occurrence in finding.provenance.occurrences:
            applicability_table.add_row(
                " ".join(
                    part
                    for part in [occurrence.component_name, occurrence.component_version]
                    if part
                ).strip()
                or "N.A.",
                (
                    f"{occurrence.target_kind}:{occurrence.target_ref}"
                    if occurrence.target_ref
                    else "N.A."
                ),
                occurrence.vex_status or "N.A.",
                occurrence.vex_justification or "N.A.",
                occurrence.vex_action_statement or "N.A.",
            )
    else:
        applicability_table.add_row("N.A.", "N.A.", "N.A.", "N.A.", "N.A.")

    remediation_table = Table(title="Remediation Components")
    remediation_table.add_column("Component")
    remediation_table.add_column("Path")
    remediation_table.add_column("Fixed Versions")
    remediation_table.add_column("Package Type")
    remediation_table.add_column("PURL", overflow="fold")
    if finding.remediation.components:
        for component in finding.remediation.components:
            remediation_table.add_row(
                " ".join(
                    part for part in [component.name, component.current_version] if part
                ).strip()
                or "N.A.",
                component.path or "N.A.",
                comma_or_na(component.fixed_versions),
                component.package_type or "N.A.",
                component.purl or "N.A.",
            )
    else:
        remediation_table.add_row("N.A.", "N.A.", "N.A.", "N.A.", "N.A.")

    references = nvd.references[:10]
    references_panel = Panel(
        "\n".join(f"- {reference}" for reference in references) if references else "N.A.",
        title="References (first 10)",
    )

    return Group(
        signal_table,
        mappings_table,
        description_panel,
        rationale_panel,
        attack_panel,
        comparison_panel,
        action_panel,
        context_panel,
        applicability_table,
        remediation_table,
        references_panel,
    )


def generate_explain_markdown(
    finding: PrioritizedFinding,
    nvd: NvdData,
    epss: EpssData,
    kev: KevData,
    attack: AttackData,
    context: AnalysisContext,
    comparison: ComparisonFinding | None = None,
) -> str:
    """Render a single-CVE detailed Markdown explanation."""
    lines = [
        f"# CVE Explanation: {finding.cve_id}",
        "",
        "## Run Metadata",
    ]
    lines.extend(_run_metadata_lines(context))
    lines.extend(
        [
            "",
            "## Signals",
            f"- Priority: `{finding.priority_label}`",
            f"- CVSS: `{format_score(finding.cvss_base_score, 1)}`",
            f"- CVSS Severity: `{finding.cvss_severity or 'N.A.'}`",
            f"- CVSS Version: `{finding.cvss_version or 'N.A.'}`",
            f"- EPSS: `{format_score(finding.epss, 3)}`",
            f"- EPSS Percentile: `{format_score(finding.epss_percentile, 3)}`",
            f"- In KEV: `{'yes' if finding.in_kev else 'no'}`",
            f"- Published: `{nvd.published or 'N.A.'}`",
            f"- Last Modified: `{nvd.last_modified or 'N.A.'}`",
            f"- CWEs: {comma_or_na(nvd.cwes)}",
            f"- ATT&CK Source: `{attack.source}`",
            f"- ATT&CK Relevance: `{attack.attack_relevance}`",
            f"- ATT&CK Techniques: {comma_or_na(attack.attack_techniques)}",
            f"- ATT&CK Tactics: {comma_or_na(attack.attack_tactics)}",
            f"- ATT&CK Note: {attack.attack_note or 'N.A.'}",
            f"- Sources: {comma_or_na(finding.provenance.source_formats)}",
            f"- Components: {comma_or_na(finding.provenance.components)}",
            f"- Targets: {comma_or_na(finding.provenance.targets)}",
            f"- Highest Asset Criticality: `{finding.highest_asset_criticality or 'N.A.'}`",
            f"- VEX Statuses: {_format_vex_statuses(finding.provenance.vex_statuses)}",
            f"- Remediation Strategy: `{finding.remediation.strategy}`",
            f"- Remediation Ecosystem: `{finding.remediation.ecosystem or 'N.A.'}`",
            f"- Waiver: {_format_waiver_status(finding)}",
            "",
            "## Description",
            normalize_whitespace(nvd.description or "N.A."),
            "",
            "## Rationale",
            normalize_whitespace(finding.rationale),
            "",
            "## ATT&CK Context",
            normalize_whitespace(attack.attack_rationale or "No ATT&CK rationale available."),
            "",
            "| Mapping Type | Technique | Tactics | Capability Group | Comments |",
            "| --- | --- | --- | --- | --- |",
        ]
    )
    if attack.mappings:
        tactics_by_id = {
            technique.attack_object_id: comma_or_na(technique.tactics)
            for technique in attack.techniques
        }
        for mapping in attack.mappings:
            lines.append(
                "| "
                + " | ".join(
                    [
                        escape_pipes(mapping.mapping_type or "N.A."),
                        escape_pipes(
                            f"{mapping.attack_object_id} {mapping.attack_object_name or ''}".strip()
                        ),
                        escape_pipes(tactics_by_id.get(mapping.attack_object_id, "N.A.")),
                        escape_pipes(mapping.capability_group or "N.A."),
                        escape_pipes(mapping.comments or "N.A."),
                    ]
                )
                + " |"
            )
    else:
        lines.append("| N.A. | No CTID mapping | N.A. | N.A. | N.A. |")

    lines.extend(
        [
            "",
            "## Comparison",
            f"- CVSS-only Baseline: `{comparison.cvss_only_label if comparison else 'N.A.'}`",
            "- Enriched Priority: `"
            f"{comparison.enriched_label if comparison else finding.priority_label}`",
            "- Delta vs Baseline: `"
            f"{format_change(comparison.delta_rank) if comparison else 'N.A.'}`",
            normalize_whitespace(comparison.change_reason if comparison is not None else "N.A."),
            "",
            "## Recommended Action",
            normalize_whitespace(finding.recommended_action),
            "",
            "## Context Recommendation",
            normalize_whitespace(finding.context_recommendation or "No context recommendation."),
            "",
            "## Applicability",
            "",
            "| Component | Target | VEX Status | Justification | Action |",
            "| --- | --- | --- | --- | --- |",
        ]
    )
    if finding.provenance.occurrences:
        for occurrence in finding.provenance.occurrences:
            component_label = (
                " ".join(
                    part
                    for part in [
                        occurrence.component_name,
                        occurrence.component_version,
                    ]
                    if part
                ).strip()
                or "N.A."
            )
            target_label = (
                f"{occurrence.target_kind}:{occurrence.target_ref}"
                if occurrence.target_ref
                else "N.A."
            )
            lines.append(
                "| "
                + " | ".join(
                    [
                        escape_pipes(component_label),
                        escape_pipes(target_label),
                        escape_pipes(occurrence.vex_status or "N.A."),
                        escape_pipes(occurrence.vex_justification or "N.A."),
                        escape_pipes(occurrence.vex_action_statement or "N.A."),
                    ]
                )
                + " |"
            )
    else:
        lines.append("| N.A. | N.A. | N.A. | N.A. | N.A. |")

    lines.extend(
        [
            "",
            "## Remediation Components",
            "",
            "| Component | Path | Fixed Versions | Package Type | PURL |",
            "| --- | --- | --- | --- | --- |",
        ]
    )
    if finding.remediation.components:
        for component in finding.remediation.components:
            lines.append(
                "| "
                + " | ".join(
                    [
                        escape_pipes(
                            " ".join(
                                part for part in [component.name, component.current_version] if part
                            ).strip()
                            or "N.A."
                        ),
                        escape_pipes(component.path or "N.A."),
                        escape_pipes(", ".join(component.fixed_versions) or "N.A."),
                        escape_pipes(component.package_type or "N.A."),
                        escape_pipes(component.purl or "N.A."),
                    ]
                )
                + " |"
            )
    else:
        lines.append("| N.A. | N.A. | N.A. | N.A. | N.A. |")

    lines.extend(
        [
            "",
            "## KEV Metadata",
            f"- Vendor/Project: `{kev.vendor_project or 'N.A.'}`",
            f"- Product: `{kev.product or 'N.A.'}`",
            f"- Date Added: `{kev.date_added or 'N.A.'}`",
            f"- Required Action: `{kev.required_action or 'N.A.'}`",
            f"- Due Date: `{kev.due_date or 'N.A.'}`",
            "",
            "## References",
        ]
    )
    if nvd.references:
        lines.extend(f"- {reference}" for reference in nvd.references[:20])
    else:
        lines.append("- N.A.")
    return "\n".join(lines) + "\n"


def generate_html_report(report_payload: dict) -> str:
    """Render a static HTML report from a JSON analysis payload."""
    metadata = report_payload.get("metadata", {})
    findings = report_payload.get("findings", [])
    attack_summary = report_payload.get("attack_summary", {})
    kev_hits = sum(1 for finding in findings if finding.get("in_kev"))
    critical_count = sum(1 for finding in findings if finding.get("priority_label") == "Critical")
    rows = []
    for finding in findings:
        source_formats = finding.get("provenance", {}).get("source_formats", [])
        source_label = ", ".join(source_formats) or "N.A."
        urgency_label = _priority_display_label(
            str(finding.get("priority_label", "N.A.")),
            bool(finding.get("in_kev")),
            bool(finding.get("waived")),
            str(finding.get("waiver_status")) if finding.get("waiver_status") else None,
        )
        exploit_status = _format_exploit_status(bool(finding.get("in_kev")))
        rationale = escape(finding.get("rationale") or "N.A.")
        description = escape(finding.get("description") or "N.A.")
        recommended_action = escape(finding.get("recommended_action") or "N.A.")
        rows.append(
            "<tr>"
            f"<td><strong>{escape(finding.get('cve_id', 'N.A.'))}</strong>"
            f'<div class="subtle">{description}</div></td>'
            f'<td><span class="badge urgency">{escape(urgency_label)}</span></td>'
            f"<td>{escape(str(finding.get('cvss_base_score', 'N.A.')))}</td>"
            f"<td>{escape(str(finding.get('epss', 'N.A.')))}</td>"
            f'<td><span class="badge kev">{escape(exploit_status)}</span></td>'
            f"<td>{escape(source_label)}</td>"
            f"<td>{rationale}</td>"
            f"<td>{recommended_action}</td>"
            f"<td>{escape(finding.get('context_recommendation') or 'N.A.')}</td>"
            "</tr>"
        )
    findings_count = escape(str(metadata.get("findings_count", 0)))
    suppressed_count = escape(str(metadata.get("suppressed_by_vex", 0)))
    waived_count = escape(str(metadata.get("waived_count", 0)))
    review_due_count = escape(str(metadata.get("waiver_review_due_count", 0)))
    expired_waiver_count = escape(str(metadata.get("expired_waiver_count", 0)))
    mapped_cves = escape(str(attack_summary.get("mapped_cves", 0)))
    kev_count = escape(str(kev_hits))
    critical_total = escape(str(critical_count))
    findings_header = "<th>CVE</th><th>Urgency</th><th>CVSS</th><th>EPSS</th>"
    findings_header += "<th>Exploit Status</th><th>Sources</th><th>Rationale</th>"
    findings_header += "<th>Recommended Action</th>"
    findings_header += "<th>Context Recommendation</th>"
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>vuln-prioritizer report</title>
  <style>
    :root {{
      color-scheme: light;
      --ink: #17212b;
      --muted: #5a6775;
      --line: #d4dbe2;
      --canvas: #f5f1e8;
      --panel: #fffdf8;
      --panel-alt: #f3efe5;
      --accent: #0f5c4d;
      --accent-soft: #dcebe7;
      --danger: #8a2432;
      --danger-soft: #f7dde1;
      --warning: #8a5a12;
      --warning-soft: #f6ead6;
    }}
    body {{
      font-family: Georgia, "Times New Roman", serif;
      margin: 0;
      color: var(--ink);
      background:
        radial-gradient(circle at top right, rgba(15, 92, 77, 0.08), transparent 30%),
        linear-gradient(180deg, #f8f4eb 0%, var(--canvas) 100%);
    }}
    main {{ max-width: 1280px; margin: 0 auto; padding: 2.5rem 2rem 3rem; }}
    h1, h2 {{ margin-bottom: 0.5rem; }}
    p {{ line-height: 1.5; }}
    .eyebrow {{
      text-transform: uppercase;
      letter-spacing: 0.12em;
      color: var(--accent);
      font-size: 0.78rem;
      margin-bottom: 0.4rem;
    }}
    .hero {{ margin-bottom: 2rem; }}
    .hero p {{ max-width: 70ch; color: var(--muted); }}
    .meta {{
      background: rgba(255, 253, 248, 0.9);
      border: 1px solid var(--line);
      padding: 1rem 1.2rem;
      border-radius: 14px;
      box-shadow: 0 10px 30px rgba(30, 40, 48, 0.06);
    }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 1rem; background: var(--panel); }}
    th, td {{
      border: 1px solid var(--line);
      padding: 0.75rem;
      text-align: left;
      vertical-align: top;
    }}
    th {{ background: var(--panel-alt); }}
    .summary {{ display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 1rem; }}
    .summary.secondary {{ margin-top: 1rem; grid-template-columns: repeat(2, minmax(0, 1fr)); }}
    .card {{
      background: rgba(255, 253, 248, 0.94);
      border: 1px solid var(--line);
      border-radius: 14px;
      padding: 1rem;
      box-shadow: 0 10px 24px rgba(23, 33, 43, 0.05);
    }}
    .card strong {{
      display: block;
      font-size: 0.85rem;
      color: var(--muted);
      margin-bottom: 0.35rem;
      text-transform: uppercase;
      letter-spacing: 0.08em;
    }}
    .metric {{
      font-size: 2rem;
      line-height: 1;
    }}
    .subtle {{ margin-top: 0.35rem; color: var(--muted); font-size: 0.92rem; }}
    .badge {{
      display: inline-block;
      padding: 0.2rem 0.55rem;
      border-radius: 999px;
      font-size: 0.82rem;
      font-weight: 700;
      white-space: nowrap;
    }}
    .badge.urgency {{ background: var(--warning-soft); color: var(--warning); }}
    .badge.kev {{ background: var(--danger-soft); color: var(--danger); }}
    .section {{ margin-top: 2rem; }}
    @media (max-width: 900px) {{
      main {{ padding: 1.4rem 1rem 2rem; }}
      .summary, .summary.secondary {{ grid-template-columns: 1fr; }}
      table {{ display: block; overflow-x: auto; }}
    }}
  </style>
</head>
<body>
  <main>
    <section class="hero">
      <div class="eyebrow">Executive Vulnerability Brief</div>
      <h1>vuln-prioritizer Executive Report</h1>
      <p>
        Deterministic prioritization based on NVD, FIRST EPSS, CISA KEV, and optional
        local ATT&amp;CK context. KEV-listed findings are surfaced as known exploited risk.
      </p>
      <div class="meta">
        <p><strong>Generated at:</strong> {escape(str(metadata.get("generated_at", "N.A.")))}</p>
        <p><strong>Input:</strong> {escape(str(metadata.get("input_path", "N.A.")))}</p>
        <p><strong>Input format:</strong> {escape(str(metadata.get("input_format", "N.A.")))}</p>
        <p><strong>Merged inputs:</strong> {escape(str(metadata.get("merged_input_count", 1)))}</p>
        <p>
          <strong>Policy profile:</strong>
          {escape(str(metadata.get("policy_profile", "default")))}
        </p>
      </div>
    </section>
    <section class="section">
      <h2>Input Sources</h2>
      <ul>
        {
        "".join(
            "<li>"
            + escape(str(source.get("input_path", "N.A.")))
            + " ("
            + escape(str(source.get("input_format", "N.A.")))
            + f", rows={int(source.get('total_rows', 0))}, "
            + f"occurrences={int(source.get('occurrence_count', 0))}, "
            + f"unique_cves={int(source.get('unique_cves', 0))})"
            + "</li>"
            for source in metadata.get("input_sources", [])
        )
        or "<li>N.A.</li>"
    }
      </ul>
      <p><strong>Duplicate CVEs collapsed:</strong> {
        escape(str(metadata.get("duplicate_cve_count", 0)))
    }</p>
    </section>
    <section class="section">
      <h2>Executive Summary</h2>
      <div class="summary">
        <div class="card">
          <strong>Findings shown</strong><span class="metric">{findings_count}</span>
        </div>
        <div class="card">
          <strong>Known exploited</strong><span class="metric">{kev_count}</span>
        </div>
        <div class="card">
          <strong>Critical</strong><span class="metric">{critical_total}</span>
        </div>
      </div>
      <div class="summary secondary">
        <div class="card">
          <strong>Suppressed by VEX</strong><span class="metric">{suppressed_count}</span>
        </div>
        <div class="card">
          <strong>ATT&amp;CK mapped CVEs</strong><span class="metric">{mapped_cves}</span>
        </div>
        <div class="card">
          <strong>Waived</strong><span class="metric">{waived_count}</span>
        </div>
        <div class="card">
          <strong>Waiver Review Due</strong><span class="metric">{review_due_count}</span>
        </div>
        <div class="card">
          <strong>Expired Waivers</strong><span class="metric">{expired_waiver_count}</span>
        </div>
      </div>
    </section>
    <section class="section">
      <h2>Top Risks</h2>
      <table>
        <thead>
          <tr>{findings_header}</tr>
        </thead>
        <tbody>
          {"".join(rows)}
        </tbody>
      </table>
    </section>
  </main>
</body>
</html>
"""

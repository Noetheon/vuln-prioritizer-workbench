"""Report generation facade and terminal rendering."""

from __future__ import annotations

from collections import Counter
from html import escape
from pathlib import Path

from rich.console import Group
from rich.panel import Panel
from rich.table import Table

from vuln_prioritizer.cli_support.snapshot_rollup import build_rollup_buckets
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
from vuln_prioritizer.scoring import build_comparison_reason, determine_cvss_only_priority

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


def _html_text(value: object, *, default: str = "N.A.") -> str:
    if value is None:
        return escape(default)
    text = normalize_whitespace(str(value)).strip()
    if not text:
        return escape(default)
    return escape(text)


def _html_score(value: object, *, digits: int) -> str:
    if isinstance(value, bool):
        return escape("N.A.")
    if isinstance(value, int | float):
        return escape(format_score(float(value), digits=digits))
    return escape("N.A.")


def _html_rate(hits: object, total: object) -> str:
    try:
        hit_count = int(hits)
        total_count = int(total)
    except (TypeError, ValueError):
        return "N.A."
    if total_count <= 0:
        return "N.A."
    percent = round((hit_count / total_count) * 100)
    return f"{hit_count}/{total_count} ({percent}%)"


def _html_slug(value: object) -> str:
    raw = normalize_whitespace(str(value or "")).lower()
    slug_chars = [char if char.isalnum() else "-" for char in raw]
    slug = "".join(slug_chars).strip("-")
    while "--" in slug:
        slug = slug.replace("--", "-")
    return slug or "item"


def _html_unique_strings(values: list[object]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value is None:
            continue
        text = normalize_whitespace(str(value)).strip()
        if text and text not in seen:
            seen.add(text)
            result.append(text)
    return result


def _html_counter_items(counter: Counter[str], *, limit: int = 6) -> list[tuple[str, int]]:
    return sorted(counter.items(), key=lambda item: (-item[1], item[0]))[:limit]


def _html_priority_tone(priority_label: str) -> str:
    mapping = {
        "Critical": "critical",
        "High": "high",
        "Medium": "medium",
        "Low": "neutral",
    }
    return mapping.get(priority_label, "neutral")


def _html_chip(label: str, *, tone: str = "neutral") -> str:
    return f'<span class="chip" data-tone="{escape(tone)}">{escape(label)}</span>'


def _html_chip_list(
    values: list[str],
    *,
    tone: str = "neutral",
    empty_text: str = "N.A.",
) -> str:
    if not values:
        return f'<p class="empty-copy">{escape(empty_text)}</p>'
    return "".join(_html_chip(value, tone=tone) for value in values)


def _html_counter_chip_list(counter: Counter[str], *, empty_text: str) -> str:
    items = _html_counter_items(counter)
    if not items:
        return f'<p class="empty-copy">{escape(empty_text)}</p>'
    return "".join(
        '<span class="chip chip-with-count" data-tone="neutral">'
        f'<span class="chip-label">{escape(label)}</span>'
        f'<span class="chip-count">{count}</span>'
        "</span>"
        for label, count in items
    )


def _html_metric_card(label: str, value: object, *, detail: str | None = None, tone: str) -> str:
    detail_html = f'<p class="metric-detail">{escape(detail)}</p>' if detail else ""
    return (
        f'<article class="metric-card" data-tone="{escape(tone)}">'
        f'<p class="metric-label">{escape(label)}</p>'
        f'<p class="metric-value">{escape(str(value))}</p>'
        f"{detail_html}"
        "</article>"
    )


def _html_meta_row(label: str, value: object) -> str:
    return f"<dt>{escape(label)}</dt><dd>{_html_text(value)}</dd>"


def _html_occurrence_component(occurrence: dict) -> str:
    component_name = normalize_whitespace(str(occurrence.get("component_name") or "")).strip()
    component_version = normalize_whitespace(str(occurrence.get("component_version") or "")).strip()
    if component_name and component_version:
        return f"{component_name} {component_version}"
    if component_name:
        return component_name
    if component_version:
        return component_version
    return "N.A."


def _html_occurrence_target(occurrence: dict) -> str:
    target_kind = normalize_whitespace(str(occurrence.get("target_kind") or "")).strip()
    target_ref = normalize_whitespace(str(occurrence.get("target_ref") or "")).strip()
    if target_kind and target_ref:
        return f"{target_kind}:{target_ref}"
    if target_ref:
        return target_ref
    if target_kind:
        return target_kind
    return "N.A."


def _html_occurrence_summary(findings: list[dict]) -> dict[str, object]:
    services: Counter[str] = Counter()
    owners: Counter[str] = Counter()
    exposures: Counter[str] = Counter()
    environments: Counter[str] = Counter()
    criticalities: Counter[str] = Counter()
    asset_ids: set[str] = set()
    targets: set[str] = set()
    components: set[str] = set()
    has_vex_evidence = False
    occurrence_total = 0

    for finding in findings:
        provenance = finding.get("provenance", {})
        if not isinstance(provenance, dict):
            continue
        for component in provenance.get("components", []):
            text = normalize_whitespace(str(component or "")).strip()
            if text:
                components.add(text)
        for target in provenance.get("targets", []):
            text = normalize_whitespace(str(target or "")).strip()
            if text:
                targets.add(text)
        for asset_id in provenance.get("asset_ids", []):
            text = normalize_whitespace(str(asset_id or "")).strip()
            if text:
                asset_ids.add(text)
        vex_statuses = provenance.get("vex_statuses", {})
        if isinstance(vex_statuses, dict) and vex_statuses:
            has_vex_evidence = True
        occurrences = provenance.get("occurrences", [])
        if not isinstance(occurrences, list):
            continue
        occurrence_total += len(occurrences)
        for occurrence in occurrences:
            if not isinstance(occurrence, dict):
                continue
            for key, counter in (
                ("asset_business_service", services),
                ("asset_owner", owners),
                ("asset_exposure", exposures),
                ("asset_environment", environments),
                ("asset_criticality", criticalities),
            ):
                text = normalize_whitespace(str(occurrence.get(key) or "")).strip()
                if text:
                    counter[text] += 1

    return {
        "services": services,
        "owners": owners,
        "exposures": exposures,
        "environments": environments,
        "criticalities": criticalities,
        "asset_count": len(asset_ids),
        "target_count": len(targets),
        "component_count": len(components),
        "occurrence_total": occurrence_total,
        "has_asset_context": bool(
            services or owners or exposures or environments or criticalities or asset_ids
        ),
        "has_vex_evidence": has_vex_evidence,
        "has_component_evidence": bool(components or targets),
    }


def _html_baseline_delta(finding: dict) -> dict[str, object]:
    try:
        validated_finding = PrioritizedFinding.model_validate(finding)
    except Exception:
        priority_label = (
            normalize_whitespace(str(finding.get("priority_label") or "")).strip() or "N.A."
        )
        return {
            "cvss_only_label": "N.A.",
            "cvss_only_rank": None,
            "delta_rank": 0,
            "delta_label": "No change",
            "changed": False,
            "reason": (
                "The report could not reconstruct a strict CVSS-only baseline because the finding payload "
                f"is incomplete. Published enriched priority: {priority_label}."
            ),
        }
    cvss_only_label, cvss_only_rank = determine_cvss_only_priority(
        validated_finding.cvss_base_score
    )
    delta_rank = cvss_only_rank - validated_finding.priority_rank
    if delta_rank > 0:
        delta_label = f"Raised by {delta_rank}"
    elif delta_rank < 0:
        delta_label = f"Lowered by {abs(delta_rank)}"
    else:
        delta_label = "No change"
    return {
        "cvss_only_label": cvss_only_label,
        "cvss_only_rank": cvss_only_rank,
        "delta_rank": delta_rank,
        "delta_label": delta_label,
        "changed": delta_rank != 0,
        "reason": build_comparison_reason(
            validated_finding,
            cvss_only_label=cvss_only_label,
            cvss_only_rank=cvss_only_rank,
        ),
    }


def _html_reference_links(urls: list[object], *, limit: int = 4) -> str:
    values = _html_unique_strings(urls)[:limit]
    if not values:
        return '<p class="empty-copy">No provider references were preserved.</p>'
    items: list[str] = []
    for value in values:
        escaped_value = escape(value)
        if value.startswith(("http://", "https://")):
            items.append(
                '<li><a class="inline-link" href="'
                + escaped_value
                + '">'
                + escaped_value
                + "</a></li>"
            )
        else:
            items.append(f"<li>{escaped_value}</li>")
    return '<ul class="bullet-list compact-list">' + "".join(items) + "</ul>"


def _html_attack_mapping_field_values(raw_mappings: object, field: str) -> list[str]:
    values: list[str] = []
    if not isinstance(raw_mappings, list):
        return values
    for mapping in raw_mappings:
        if not isinstance(mapping, dict):
            continue
        text = normalize_whitespace(str(mapping.get(field) or "")).strip()
        if text and text not in values:
            values.append(text)
    return values


def _html_attack_reference_urls(raw_mappings: object) -> list[str]:
    values: list[str] = []
    if not isinstance(raw_mappings, list):
        return values
    for mapping in raw_mappings:
        if not isinstance(mapping, dict):
            continue
        references = mapping.get("references", [])
        if not isinstance(references, list):
            continue
        for reference in references:
            text = normalize_whitespace(str(reference or "")).strip()
            if text and text not in values:
                values.append(text)
    return values


def _html_attack_technique_cards(technique_details: object, fallback_labels: list[str]) -> str:
    cards: list[str] = []
    if isinstance(technique_details, list):
        for technique in technique_details:
            if not isinstance(technique, dict):
                continue
            attack_object_id = normalize_whitespace(
                str(technique.get("attack_object_id") or "")
            ).strip()
            name = normalize_whitespace(str(technique.get("name") or "")).strip() or "Technique"
            url = normalize_whitespace(str(technique.get("url") or "")).strip()
            tactics = _html_unique_strings(technique.get("tactics", []))
            labels = []
            if technique.get("deprecated"):
                labels.append(_html_chip("Deprecated", tone="warning"))
            if technique.get("revoked"):
                labels.append(_html_chip("Revoked", tone="warning"))
            title_html = (
                f'<a class="attack-technique-link" href="{escape(url)}">{escape(attack_object_id or name)}</a>'
                if url.startswith(("http://", "https://"))
                else f'<span class="attack-technique-link">{escape(attack_object_id or name)}</span>'
            )
            primary_tactic = tactics[0] if tactics else "No tactic metadata"
            reference_html = (
                f'<a class="attack-technique-ref" href="{escape(url)}">MITRE reference</a>'
                if url.startswith(("http://", "https://"))
                else '<span class="attack-technique-ref">Local CTID mapping</span>'
            )
            cards.append(
                '<article class="attack-technique-card">'
                '<p class="attack-technique-kicker">MITRE technique</p>'
                '<div class="attack-technique-head">'
                f'<div><div class="attack-technique-id">{title_html}</div>'
                f'<p class="attack-technique-name">{escape(name)}</p></div>'
                f'<div class="chip-row">{"".join(labels)}</div>'
                "</div>"
                '<div class="attack-technique-body">'
                '<div class="attack-technique-meta-row">'
                "<span>Primary tactic</span>"
                f"<strong>{_html_text(primary_tactic)}</strong>"
                "</div>"
                '<div class="attack-technique-chip-row">'
                f"{_html_chip_list(tactics, tone='neutral', empty_text='No tactic metadata.')}"
                "</div>"
                "</div>"
                '<div class="attack-technique-footer">'
                "<span>Mapped in local CTID data</span>"
                f"{reference_html}"
                "</div>"
                "</article>"
            )
    if not cards:
        for label in fallback_labels:
            cards.append(
                '<article class="attack-technique-card">'
                '<p class="attack-technique-kicker">ATT&amp;CK signal</p>'
                f'<div class="attack-technique-id">{escape(label)}</div>'
                '<div class="attack-technique-footer"><span>Technique metadata not preserved in payload</span></div>'
                "</article>"
            )
    return (
        '<div class="attack-technique-grid">' + "".join(cards) + "</div>"
        if cards
        else '<p class="empty-copy">No ATT&amp;CK technique metadata captured.</p>'
    )


def _html_attack_preview_block(finding: dict, *, attack_enabled: bool) -> str:
    if not attack_enabled:
        return ""

    attack_relevance = normalize_whitespace(str(finding.get("attack_relevance") or "")).strip()
    technique_details = finding.get("attack_technique_details", [])
    technique_labels: list[str] = []
    preview_cards: list[str] = []

    if isinstance(technique_details, list):
        for technique in technique_details:
            if not isinstance(technique, dict):
                continue
            attack_object_id = normalize_whitespace(
                str(technique.get("attack_object_id") or "")
            ).strip()
            name = normalize_whitespace(str(technique.get("name") or "")).strip() or "Technique"
            url = normalize_whitespace(str(technique.get("url") or "")).strip()
            tactics = _html_unique_strings(technique.get("tactics", []))
            label = " · ".join(part for part in (attack_object_id, name) if part)
            if label and label not in technique_labels:
                technique_labels.append(label)
            if len(preview_cards) >= 4:
                continue
            title_html = (
                f'<a class="attack-technique-link" href="{escape(url)}">{escape(attack_object_id or name)}</a>'
                if url.startswith(("http://", "https://"))
                else f'<span class="attack-technique-link">{escape(attack_object_id or name)}</span>'
            )
            preview_cards.append(
                '<article class="attack-mini-card">'
                f'<div class="attack-mini-id">{title_html}</div>'
                f'<p class="attack-mini-name">{escape(name)}</p>'
                f'<p class="attack-mini-meta">{_html_text(", ".join(tactics), default="No tactic metadata.")}</p>'
                "</article>"
            )

    if not technique_labels:
        technique_labels = _html_unique_strings(finding.get("attack_techniques", []))
    if not preview_cards:
        for label in technique_labels[:4]:
            preview_cards.append(
                '<article class="attack-mini-card">'
                f'<div class="attack-mini-id">{escape(label)}</div>'
                "</article>"
            )

    tactics = _html_unique_strings(finding.get("attack_tactics", []))
    mapping_types = _html_attack_mapping_field_values(
        finding.get("attack_mappings", []), "mapping_type"
    )
    top_tactic = tactics[0] if tactics else ""
    attack_copy = normalize_whitespace(
        str(finding.get("attack_note") or finding.get("attack_rationale") or "")
    ).strip()

    if not finding.get("attack_mapped"):
        return (
            '<section class="attack-preview attack-preview-empty">'
            '<div class="attack-preview-head">'
            "<div>"
            '<p class="label">Threat behavior snapshot</p>'
            "<h3>No mapped ATT&amp;CK behavior</h3>"
            "</div>"
            f'<div class="chip-row">{_html_chip("Unmapped in local dataset", tone="warning")}</div>'
            "</div>"
            f'<p class="attack-preview-copy">{_html_text(attack_copy, default="This CVE is not mapped in the supplied ATT&amp;CK dataset, so only the base prioritization model is available here.")}</p>'
            "</section>"
        )

    preview_badges = [
        _html_chip(f"ATT&CK {attack_relevance or 'Mapped'}", tone="accent"),
        _html_chip(f"{len(technique_labels)} TTPs", tone="info"),
        _html_chip(f"{len(tactics)} tactics", tone="neutral"),
    ]
    if top_tactic:
        preview_badges.append(_html_chip(top_tactic, tone="neutral"))

    return (
        '<section class="attack-preview">'
        '<div class="attack-preview-head">'
        "<div>"
        '<p class="label">Threat behavior snapshot</p>'
        "<h3>ATT&amp;CK view</h3>"
        "</div>"
        f'<div class="chip-row">{"".join(preview_badges)}</div>'
        "</div>"
        + (
            f'<p class="attack-preview-copy">{_html_text(truncate_text(attack_copy, 260))}</p>'
            if attack_copy
            else ""
        )
        + (
            '<div class="attack-preview-taxonomy">'
            '<div class="attack-mini-stack">'
            '<p class="label">Top tactics</p>'
            f"{_html_chip_list(tactics[:4], tone='neutral', empty_text='No tactics captured.')}"
            "</div>"
            '<div class="attack-mini-stack">'
            '<p class="label">Mapping types</p>'
            f"{_html_chip_list(mapping_types[:4], tone='accent', empty_text='No mapping types captured.')}"
            "</div>"
            "</div>"
        )
        + '<div class="attack-mini-grid">'
        + "".join(preview_cards)
        + "</div>"
        + "</section>"
    )


def _html_provider_evidence_block(finding: dict) -> str:
    provider_evidence = finding.get("provider_evidence", {})
    if not isinstance(provider_evidence, dict):
        provider_evidence = {}
    nvd = provider_evidence.get("nvd", {})
    epss = provider_evidence.get("epss", {})
    kev = provider_evidence.get("kev", {})
    if not isinstance(nvd, dict):
        nvd = {}
    if not isinstance(epss, dict):
        epss = {}
    if not isinstance(kev, dict):
        kev = {}

    return (
        '<div class="evidence-groups">'
        '<div class="evidence-group">'
        "<h5>NVD evidence</h5>"
        '<ul class="bullet-list compact-list">'
        f"<li><strong>Published:</strong> {_html_text(nvd.get('published'), default='Not available.')}</li>"
        f"<li><strong>Last modified:</strong> {_html_text(nvd.get('last_modified'), default='Not available.')}</li>"
        f"<li><strong>CVSS version:</strong> {_html_text(nvd.get('cvss_version'), default='Not available.')}</li>"
        f"<li><strong>CWEs:</strong> {_html_text(comma_or_na(_html_unique_strings(nvd.get('cwes', []))))}</li>"
        "</ul>"
        '<div class="provider-links">'
        '<p class="label">References</p>'
        f"{_html_reference_links(nvd.get('references', []))}"
        "</div>"
        "</div>"
        '<div class="evidence-group">'
        "<h5>FIRST EPSS evidence</h5>"
        '<ul class="bullet-list compact-list">'
        f"<li><strong>Score:</strong> {_html_score(epss.get('epss'), digits=3)}</li>"
        f"<li><strong>Percentile:</strong> {_html_score(epss.get('percentile'), digits=3)}</li>"
        f"<li><strong>Score date:</strong> {_html_text(epss.get('date'), default='Not available.')}</li>"
        "</ul>"
        '<p class="empty-copy" style="margin-top:0.5rem;font-size:0.8rem;">EPSS is a probability signal. It explains urgency, but KEV and the base threshold model still decide the priority label.</p>'
        "</div>"
        '<div class="evidence-group">'
        "<h5>CISA KEV evidence</h5>"
        '<ul class="bullet-list compact-list">'
        f"<li><strong>In KEV:</strong> {_html_text('Yes' if kev.get('in_kev') else 'No')}</li>"
        f"<li><strong>Vendor / product:</strong> {_html_text(' / '.join(part for part in (_html_unique_strings([kev.get('vendor_project'), kev.get('product')]))), default='Not available.')}</li>"
        f"<li><strong>Date added:</strong> {_html_text(kev.get('date_added'), default='Not available.')}</li>"
        f"<li><strong>Due date:</strong> {_html_text(kev.get('due_date'), default='Not available.')}</li>"
        f"<li><strong>Required action:</strong> {_html_text(kev.get('required_action'), default='No KEV action text captured.')}</li>"
        "</ul>"
        "</div>"
        "</div>"
    )


def _html_top_decision_cards(findings: list[dict]) -> str:
    if not findings:
        return '<div class="empty-state"><p>No visible findings are available for executive decision cards.</p></div>'
    cards: list[str] = []
    for finding in findings[:3]:
        cve_id = normalize_whitespace(str(finding.get("cve_id") or "")).strip() or "N.A."
        provenance = finding.get("provenance", {})
        provenance = provenance if isinstance(provenance, dict) else {}
        top_service = _html_counter_items(
            Counter(
                normalize_whitespace(str(occurrence.get("asset_business_service") or "")).strip()
                for occurrence in provenance.get("occurrences", [])
                if isinstance(occurrence, dict)
                and normalize_whitespace(
                    str(occurrence.get("asset_business_service") or "")
                ).strip()
            ),
            limit=1,
        )
        top_owner = _html_counter_items(
            Counter(
                normalize_whitespace(str(occurrence.get("asset_owner") or "")).strip()
                for occurrence in provenance.get("occurrences", [])
                if isinstance(occurrence, dict)
                and normalize_whitespace(str(occurrence.get("asset_owner") or "")).strip()
            ),
            limit=1,
        )
        baseline = _html_baseline_delta(finding)
        top_service_name = top_service[0][0] if top_service else "Unmapped"
        top_owner_name = top_owner[0][0] if top_owner else "Unassigned"
        baseline_delta = str(baseline["delta_label"])
        cards.append(
            f'<div class="decision-card" data-priority="{escape(str(finding.get("priority_label", "Low")))}">'
            '<div class="decision-topline">'
            f"<h4>{escape(cve_id)}</h4>"
            f"{_html_chip(str(finding.get('priority_label') or 'N.A.'), tone=_html_priority_tone(str(finding.get('priority_label', 'Low'))))}"
            "</div>"
            f'<p class="decision-action-line">{_html_text(truncate_text(finding.get("recommended_action") or "N.A.", 104))}</p>'
            '<div class="decision-chip-row">'
            f"{_html_chip(f'Service {top_service_name}', tone='neutral')}"
            f"{_html_chip(f'Owner {top_owner_name}', tone='neutral')}"
            f"{_html_chip(f'CVSS-only baseline delta {baseline_delta}', tone='accent' if baseline_delta != 'No delta' else 'neutral')}"
            "</div>"
            f'<p class="decision-why"><strong>Why now:</strong> {_html_text(truncate_text(finding.get("rationale") or "N.A.", 128))}</p>'
            "</div>"
        )
    return '<div class="decision-stack">' + "".join(cards) + "</div>"


def _html_rollup_bucket_card(bucket: RollupBucket, *, title_prefix: str) -> str:
    top_candidates = ", ".join(bucket.top_cves[:3]) if bucket.top_cves else "N.A."
    owners = ", ".join(bucket.owners) if bucket.owners else "Unmapped"
    action = (
        bucket.recommended_actions[0] if bucket.recommended_actions else "Review bucket candidates."
    )
    return (
        '<div class="bucket-card">'
        '<div class="bucket-topline">'
        f"<h4>{escape(title_prefix)} {escape(bucket.bucket)}</h4>"
        f"{_html_chip(f'Rank {bucket.remediation_rank}', tone='accent')}"
        "</div>"
        f'<p class="bucket-summary">{escape(bucket.rank_reason or "No rank reason captured.")}</p>'
        '<dl class="bucket-meta">'
        f"<dt>Highest priority</dt><dd>{escape(bucket.highest_priority)}</dd>"
        f"<dt>Owners</dt><dd>{escape(owners)}</dd>"
        f"<dt>Patch first</dt><dd>{escape(top_candidates)}</dd>"
        f"<dt>Suggested action</dt><dd>{escape(action)}</dd>"
        "</dl>"
        "</div>"
    )


def _html_action_plan(report_payload: dict[str, object]) -> str:
    try:
        service_buckets = build_rollup_buckets(report_payload, dimension="service", top=3)
        asset_buckets = build_rollup_buckets(report_payload, dimension="asset", top=2)
    except Exception:
        return '<div class="empty-state"><p>Action-plan rollups could not be derived from this payload.</p></div>'

    meaningful_service_buckets = [
        bucket for bucket in service_buckets if bucket.bucket != "Unmapped"
    ][:3]
    meaningful_asset_buckets = [bucket for bucket in asset_buckets if bucket.bucket != "Unmapped"][
        :2
    ]
    if not meaningful_service_buckets and not meaningful_asset_buckets:
        return '<div class="empty-state"><p>No owner or asset mappings are available yet, so the report cannot build an action-plan queue.</p></div>'

    service_html = (
        "".join(
            _html_rollup_bucket_card(bucket, title_prefix="Service")
            for bucket in meaningful_service_buckets
        )
        if meaningful_service_buckets
        else '<div class="empty-state"><p>No service-level mappings are available for an action-plan view.</p></div>'
    )
    asset_html = (
        "".join(
            _html_rollup_bucket_card(bucket, title_prefix="Asset")
            for bucket in meaningful_asset_buckets
        )
        if meaningful_asset_buckets
        else '<div class="empty-state"><p>No asset-level mappings are available for an action-plan view.</p></div>'
    )
    return (
        '<div class="action-plan-stack">'
        '<div class="action-plan-section"><p class="label">Service queues</p>'
        + service_html
        + "</div>"
        '<div class="action-plan-section"><p class="label">Asset queues</p>' + asset_html + "</div>"
        "</div>"
    )


def _html_provider_transparency(metadata: dict, findings: list[dict]) -> str:
    nvd_diagnostics = metadata.get("nvd_diagnostics", {})
    nvd_diagnostics = nvd_diagnostics if isinstance(nvd_diagnostics, dict) else {}
    latest_epss_dates = sorted(
        {
            normalize_whitespace(
                str(finding.get("provider_evidence", {}).get("epss", {}).get("date") or "")
            ).strip()
            for finding in findings
            if isinstance(finding.get("provider_evidence"), dict)
            and isinstance(finding.get("provider_evidence", {}).get("epss"), dict)
            and normalize_whitespace(
                str(finding.get("provider_evidence", {}).get("epss", {}).get("date") or "")
            ).strip()
        }
    )
    latest_kev_dates = sorted(
        {
            normalize_whitespace(
                str(finding.get("provider_evidence", {}).get("kev", {}).get("date_added") or "")
            ).strip()
            for finding in findings
            if isinstance(finding.get("provider_evidence"), dict)
            and isinstance(finding.get("provider_evidence", {}).get("kev"), dict)
            and normalize_whitespace(
                str(finding.get("provider_evidence", {}).get("kev", {}).get("date_added") or "")
            ).strip()
        }
    )
    return (
        '<div class="two-col">'
        "<div>"
        "<h5>Provider transparency</h5>"
        '<ul class="bullet-list compact-list">'
        f"<li><strong>Cache enabled:</strong> {_html_text('yes' if metadata.get('cache_enabled') else 'no')}</li>"
        f"<li><strong>Provider snapshot file:</strong> {_html_text(metadata.get('provider_snapshot_file'), default='Not used for this run.')}</li>"
        f"<li><strong>Provider snapshot sources:</strong> {_html_text(comma_or_na(_html_unique_strings(metadata.get('provider_snapshot_sources', []))))}</li>"
        f"<li><strong>NVD request diagnostics:</strong> {_html_text('requested=' + str(nvd_diagnostics.get('requested', 0)) + ', cache_hits=' + str(nvd_diagnostics.get('cache_hits', 0)) + ', network_fetches=' + str(nvd_diagnostics.get('network_fetches', 0)) + ', failures=' + str(nvd_diagnostics.get('failures', 0)) + ', content_hits=' + str(nvd_diagnostics.get('content_hits', 0)))}</li>"
        "</ul>"
        "</div>"
        "<div>"
        "<h5>Provider freshness</h5>"
        '<ul class="bullet-list compact-list">'
        f"<li><strong>EPSS dates present:</strong> {_html_text(comma_or_na(latest_epss_dates[-3:]))}</li>"
        f"<li><strong>KEV add dates present:</strong> {_html_text(comma_or_na(latest_kev_dates[-3:]))}</li>"
        f"<li><strong>Warning count:</strong> {_html_text(len(metadata.get('warnings', [])) if isinstance(metadata.get('warnings'), list) else 0)}</li>"
        "</ul>"
        '<p class="empty-copy" style="margin-top:0.5rem;font-size:0.8rem;">Freshness and diagnostics explain how much of the report is live enrichment, cached provider data, or pinned snapshot replay.</p>'
        "</div>"
        "</div>"
    )


def _html_top_distribution_labels(distribution: object, *, limit: int = 6) -> list[str]:
    if not isinstance(distribution, dict):
        return []
    sortable: list[tuple[str, int]] = []
    for key, value in distribution.items():
        label = normalize_whitespace(str(key)).strip()
        try:
            count = int(value)
        except (TypeError, ValueError):
            continue
        if label:
            sortable.append((label, count))
    sortable.sort(key=lambda item: (-item[1], item[0]))
    return [f"{label} ({count})" for label, count in sortable[:limit]]


def _html_brief_summary(
    metadata: dict,
    findings: list[dict],
    attack_summary: dict,
    occurrence_summary: dict[str, object],
) -> str:
    visible_findings = len(findings)
    valid_input = int(metadata.get("valid_input", 0) or 0)
    kev_visible = sum(1 for finding in findings if finding.get("in_kev"))
    attack_enabled = bool(metadata.get("attack_enabled"))
    mapped_cves = int(attack_summary.get("mapped_cves", 0) or 0)
    summary_bits = [f"{visible_findings} visible finding(s) across {valid_input} valid CVE(s)"]
    if kev_visible:
        summary_bits.append(f"{kev_visible} KEV-listed")
    elif visible_findings:
        summary_bits.append("no KEV-listed finding in view")

    if attack_enabled:
        attack_copy = (
            f"ATT&CK context is available for {mapped_cves} visible CVE(s)"
            if mapped_cves
            else "ATT&CK context is enabled but not mapped in the visible queue"
        )
    else:
        attack_copy = "ATT&CK context is disabled for this run"

    if occurrence_summary["has_asset_context"]:
        services = _html_counter_items(occurrence_summary["services"], limit=1)
        service_note = f"; top service signal: {services[0][0]}" if services else ""
        context_copy = f"Asset context is present for {int(occurrence_summary['asset_count'])} mapped asset(s){service_note}"
    else:
        context_copy = "Asset ownership context is limited"

    return (
        ". ".join(
            [
                ", ".join(summary_bits),
                attack_copy,
                context_copy,
            ]
        )
        + "."
    )


def _html_strengthen_report(
    metadata: dict, occurrence_summary: dict[str, object]
) -> list[tuple[str, str, str]]:
    suggestions: list[tuple[str, str, str]] = []
    if not metadata.get("attack_enabled"):
        suggestions.append(
            (
                "Add ATT&CK context",
                "Show mapped versus unmapped adversary behavior, tactics, and management-facing threat context.",
                "vuln-prioritizer analyze --attack-source ctid-json --attack-mapping-file <mappings.json> --attack-technique-metadata-file <techniques.json>",
            )
        )
    if not occurrence_summary["has_asset_context"]:
        suggestions.append(
            (
                "Attach asset context",
                "Populate owner, service, exposure, and environment signals so dossiers can route remediation work more precisely.",
                "vuln-prioritizer analyze --asset-context example_asset_context.csv",
            )
        )
    if not occurrence_summary["has_vex_evidence"]:
        suggestions.append(
            (
                "Bring VEX evidence",
                "Expose suppressed findings, investigations in progress, and applicability decisions in the governance view.",
                "vuln-prioritizer analyze --vex-file openvex_statements.json",
            )
        )
    if not metadata.get("waiver_file"):
        suggestions.append(
            (
                "Track waivers explicitly",
                "Show accepted risk, owners, review dates, and expiry pressure instead of leaving governance debt off-report.",
                "vuln-prioritizer analyze --waiver-file waivers.yml",
            )
        )
    if not occurrence_summary["has_component_evidence"]:
        suggestions.append(
            (
                "Increase package evidence",
                "Scanner or SBOM inputs provide component, path, and fix-version evidence that makes remediation guidance actionable.",
                "vuln-prioritizer analyze --input trivy-results.json --input-format trivy-json",
            )
        )
    return suggestions


def _html_priority_signal(finding: dict) -> str:
    signals: list[str] = []
    if finding.get("in_kev"):
        signals.append("KEV-listed")
    if finding.get("under_investigation"):
        signals.append("VEX under investigation")
    if finding.get("waived"):
        signals.append("Waived")
    if finding.get("attack_mapped"):
        attack_relevance = normalize_whitespace(str(finding.get("attack_relevance") or "")).strip()
        if attack_relevance:
            signals.append(f"ATT&CK {attack_relevance}")
    highest_criticality = normalize_whitespace(
        str(finding.get("highest_asset_criticality") or "")
    ).strip()
    if highest_criticality:
        signals.append(f"Asset {highest_criticality}")
    highest_exposure = normalize_whitespace(
        str(finding.get("provenance", {}).get("highest_asset_exposure") or "")
    ).strip()
    if highest_exposure:
        signals.append(highest_exposure)
    return ", ".join(signals) if signals else "No exceptional routing signal"


def _html_occurrence_rows(occurrences: list[object]) -> str:
    rows: list[str] = []
    for raw_occurrence in occurrences:
        if not isinstance(raw_occurrence, dict):
            continue
        vex_status = (
            normalize_whitespace(str(raw_occurrence.get("vex_status") or "")).strip() or "N.A."
        )
        owner = normalize_whitespace(str(raw_occurrence.get("asset_owner") or "")).strip() or "N.A."
        service = (
            normalize_whitespace(str(raw_occurrence.get("asset_business_service") or "")).strip()
            or "N.A."
        )
        exposure = (
            normalize_whitespace(str(raw_occurrence.get("asset_exposure") or "")).strip() or "N.A."
        )
        environment = (
            normalize_whitespace(str(raw_occurrence.get("asset_environment") or "")).strip()
            or "N.A."
        )
        asset_label = (
            normalize_whitespace(str(raw_occurrence.get("asset_id") or "")).strip() or "N.A."
        )
        rows.append(
            "<tr>"
            f"<td>{_html_text(_html_occurrence_component(raw_occurrence))}</td>"
            f"<td>{_html_text(_html_occurrence_target(raw_occurrence))}</td>"
            f"<td>{_html_text(asset_label)}</td>"
            f"<td>{_html_text(service)}</td>"
            f"<td>{_html_text(owner)}</td>"
            f"<td>{_html_text(exposure)}</td>"
            f"<td>{_html_text(environment)}</td>"
            f"<td>{_html_text(vex_status)}</td>"
            "</tr>"
        )
    if not rows:
        return (
            '<p class="empty-copy">No occurrence-level evidence was preserved in this export.</p>'
        )
    return (
        '<div class="table-wrap"><table class="data-table compact-table"><thead><tr>'
        "<th>Component</th><th>Target</th><th>Asset</th><th>Service</th><th>Owner</th>"
        "<th>Exposure</th><th>Environment</th><th>VEX</th>"
        "</tr></thead><tbody>" + "".join(rows) + "</tbody></table></div>"
    )


def _html_remediation_block(finding: dict) -> str:
    remediation = finding.get("remediation", {})
    components = remediation.get("components", []) if isinstance(remediation, dict) else []
    if not isinstance(components, list) or not components:
        return '<p class="empty-copy">No component-level remediation detail was preserved for this finding.</p>'
    cards: list[str] = []
    for component in components:
        if not isinstance(component, dict):
            continue
        name = normalize_whitespace(str(component.get("name") or "")).strip() or "Component"
        current_version = (
            normalize_whitespace(str(component.get("current_version") or "")).strip() or "N.A."
        )
        fixed_versions = _html_unique_strings(component.get("fixed_versions", []))
        package_type = normalize_whitespace(str(component.get("package_type") or "")).strip()
        path = normalize_whitespace(str(component.get("path") or "")).strip()
        notes = []
        if package_type:
            notes.append(package_type)
        if path:
            notes.append(path)
        cards.append(
            '<div class="remediation-item">'
            f"<h5>{_html_text(name)}</h5>"
            f'<p class="subtle">Current version: <strong>{_html_text(current_version)}</strong></p>'
            f'<p class="subtle">Fixed version(s): <strong>{_html_text(", ".join(fixed_versions), default="N.A.")}</strong></p>'
            f'<p class="subtle">{_html_text(" | ".join(notes), default="No package/path metadata captured.")}</p>'
            "</div>"
        )
    return '<div class="remediation-items">' + "".join(cards) + "</div>"


def _html_attack_block(finding: dict, *, attack_enabled: bool) -> str:
    if not attack_enabled:
        return (
            '<div class="attack-status-card">'
            '<p class="label">Threat data unavailable</p>'
            '<p class="empty-copy">ATT&amp;CK context was disabled for this export. Enable local CTID-backed mappings to show threat behavior alongside the base priority model.</p>'
            '<code class="command-chip">vuln-prioritizer analyze --attack-source ctid-json --attack-mapping-file &lt;mappings.json&gt; --attack-technique-metadata-file &lt;techniques.json&gt;</code>'
            "</div>"
        )
    if not finding.get("attack_mapped"):
        attack_rationale = normalize_whitespace(str(finding.get("attack_rationale") or "")).strip()
        return (
            '<div class="attack-status-card">'
            '<p class="label">Threat behavior unavailable</p>'
            '<p class="empty-copy">This CVE is currently unmapped in the supplied local ATT&amp;CK dataset. The base priority remains valid, but adversary-behavior context is absent.</p>'
            + (
                f'<p class="attack-note">{_html_text(attack_rationale)}</p>'
                if attack_rationale
                else ""
            )
            + "</div>"
        )

    technique_details = finding.get("attack_technique_details", [])
    technique_labels: list[str] = []
    if isinstance(technique_details, list):
        for technique in technique_details:
            if not isinstance(technique, dict):
                continue
            attack_object_id = normalize_whitespace(
                str(technique.get("attack_object_id") or "")
            ).strip()
            name = normalize_whitespace(str(technique.get("name") or "")).strip()
            label = " · ".join(part for part in (attack_object_id, name) if part)
            if label:
                technique_labels.append(label)
    if not technique_labels:
        technique_labels = _html_unique_strings(finding.get("attack_techniques", []))

    tactics = _html_unique_strings(finding.get("attack_tactics", []))
    raw_mappings = finding.get("attack_mappings", [])
    mapping_types = _html_attack_mapping_field_values(raw_mappings, "mapping_type")
    capability_groups = _html_attack_mapping_field_values(raw_mappings, "capability_group")
    references = _html_attack_reference_urls(raw_mappings)
    note = finding.get("attack_note")
    rationale = finding.get("attack_rationale")
    reference_html = _html_reference_links(references, limit=6)
    technique_cards_html = _html_attack_technique_cards(technique_details, technique_labels)
    mapping_count = len(raw_mappings) if isinstance(raw_mappings, list) else 0

    return (
        '<div class="attack-detail-stack">'
        '<div class="attack-overview-grid">'
        + _html_metric_card(
            "ATT&CK relevance",
            f"ATT&CK {finding.get('attack_relevance') or 'Mapped'}",
            detail="Threat-context signal for this CVE",
            tone="accent",
        )
        + _html_metric_card(
            "Techniques",
            len(technique_labels),
            detail="Mapped TTPs for this CVE",
            tone="info",
        )
        + _html_metric_card(
            "Tactics",
            len(tactics),
            detail="Mapped adversary phases",
            tone="default",
        )
        + _html_metric_card(
            "Mappings",
            mapping_count,
            detail="Imported CTID mapping objects",
            tone="default",
        )
        + "</div>"
        '<div class="attack-taxonomy-grid">'
        '<article class="attack-block-card">'
        '<p class="label">Tactics</p>'
        f"{_html_chip_list(tactics, tone='neutral', empty_text='No tactics available.')}"
        "</article>"
        '<article class="attack-block-card">'
        '<p class="label">Mapping types</p>'
        f"{_html_chip_list(mapping_types, tone='info', empty_text='No mapping types available.')}"
        "</article>"
        '<article class="attack-block-card">'
        '<p class="label">Capability groups</p>'
        f"{_html_chip_list(capability_groups, tone='accent', empty_text='No capability groups available.')}"
        "</article>"
        "</div>"
        '<article class="attack-block-card">'
        '<p class="label">Attack narrative</p>'
        f'<p class="attack-note">{_html_text(note, default="No ATT&CK narrative note was attached.")}</p>'
        + (
            f'<p class="empty-copy" style="margin-top:0.55rem;">{_html_text(rationale)}</p>'
            if rationale
            else ""
        )
        + "</article>"
        '<div class="attack-technique-section">'
        '<p class="label">Techniques and TTPs</p>'
        f"{technique_cards_html}"
        "</div>"
        '<article class="attack-block-card">'
        '<p class="label">References</p>'
        f"{reference_html}"
        "</article>"
        "</div>"
    )


def _html_governance_block(finding: dict) -> str:
    provenance = finding.get("provenance", {})
    vex_statuses = provenance.get("vex_statuses", {}) if isinstance(provenance, dict) else {}
    vex_label = _format_vex_statuses(vex_statuses if isinstance(vex_statuses, dict) else {})
    waiver_summary = (
        _format_waiver_status(finding) if isinstance(finding, PrioritizedFinding) else None
    )
    if waiver_summary is None:
        waiver_details = []
        if finding.get("waived") or finding.get("waiver_status"):
            waiver_details = [
                f"status={finding.get('waiver_status') or 'active'}",
                f"owner={finding.get('waiver_owner') or 'N.A.'}",
                f"expires={finding.get('waiver_expires_on') or 'N.A.'}",
            ]
            if finding.get("waiver_review_on"):
                waiver_details.append(f"review_on={finding.get('waiver_review_on')}")
            if finding.get("waiver_scope"):
                waiver_details.append(f"scope={finding.get('waiver_scope')}")
        waiver_summary = ", ".join(waiver_details) if waiver_details else "N.A."
    return (
        '<dl class="governance-dl">'
        '<div class="governance-item"><dt>VEX state</dt>'
        f"<dd>{_html_text(vex_label)}</dd></div>"
        '<div class="governance-item"><dt>Waiver state</dt>'
        f"<dd>{_html_text(waiver_summary)}</dd></div>"
        '<div class="governance-item"><dt>Context summary</dt>'
        f"<dd>{_html_text(finding.get('context_summary'), default='No contextual summary was generated.')}</dd></div>"
        "</dl>"
    )


def _html_findings_empty_state(metadata: dict) -> str:
    filtered_out = int(metadata.get("filtered_out_count", 0) or 0)
    suppressed = int(metadata.get("suppressed_by_vex", 0) or 0)
    valid_input = int(metadata.get("valid_input", 0) or 0)
    return (
        f"No visible findings matched this export. {valid_input} valid CVE(s) were processed, "
        f"{filtered_out} finding(s) were filtered out, and {suppressed} finding(s) were fully suppressed by VEX."
    )


def _html_sort_key(finding: dict) -> tuple[object, ...]:
    try:
        rank = int(finding.get("priority_rank", 999))
    except (TypeError, ValueError):
        rank = 999
    kev_sort = 0 if finding.get("in_kev") else 1
    epss_sort = -float(finding["epss"]) if finding.get("epss") is not None else 1.0
    cvss_sort = (
        -float(finding["cvss_base_score"]) if finding.get("cvss_base_score") is not None else 1.0
    )
    return (
        rank,
        kev_sort,
        epss_sort,
        cvss_sort,
        normalize_whitespace(str(finding.get("cve_id") or "")),
    )


def generate_html_report(report_payload: dict) -> str:
    """Render a static HTML report from a JSON analysis payload."""
    metadata = report_payload.get("metadata", {})
    findings = report_payload.get("findings", [])
    attack_summary = report_payload.get("attack_summary", {})
    if not isinstance(metadata, dict):
        metadata = {}
    if not isinstance(findings, list):
        findings = []
    if not isinstance(attack_summary, dict):
        attack_summary = {}

    sorted_findings = sorted(
        [finding for finding in findings if isinstance(finding, dict)],
        key=_html_sort_key,
    )
    occurrence_summary = _html_occurrence_summary(sorted_findings)

    visible_findings = len(sorted_findings)
    critical_count = sum(
        1 for finding in sorted_findings if finding.get("priority_label") == "Critical"
    )
    kev_visible = sum(1 for finding in sorted_findings if finding.get("in_kev"))
    under_investigation = int(metadata.get("under_investigation_count", 0) or 0)
    suppressed_count = int(metadata.get("suppressed_by_vex", 0) or 0)
    waived_count = int(metadata.get("waived_count", 0) or 0)
    review_due_count = int(metadata.get("waiver_review_due_count", 0) or 0)
    expired_waiver_count = int(metadata.get("expired_waiver_count", 0) or 0)
    mapped_cves = int(attack_summary.get("mapped_cves", 0) or 0)
    warnings = metadata.get("warnings", [])
    warning_count = len(warnings) if isinstance(warnings, list) else 0
    attack_enabled = bool(metadata.get("attack_enabled"))
    top_finding = sorted_findings[0] if sorted_findings else None
    executive_focus_html = (
        '<p class="empty-copy">No visible finding is available for executive triage.</p>'
    )
    if isinstance(top_finding, dict):
        top_cve = normalize_whitespace(str(top_finding.get("cve_id") or "")).strip() or "N.A."
        top_priority = _priority_display_label(
            str(top_finding.get("priority_label", "N.A.")),
            bool(top_finding.get("in_kev")),
            bool(top_finding.get("waived")),
            str(top_finding.get("waiver_status")) if top_finding.get("waiver_status") else None,
        )
        top_provenance = top_finding.get("provenance", {})
        top_provenance = top_provenance if isinstance(top_provenance, dict) else {}
        top_occurrences = (
            top_provenance.get("occurrences", [])
            if isinstance(top_provenance.get("occurrences", []), list)
            else []
        )
        top_services = Counter()
        top_owners = Counter()
        for occurrence in top_occurrences:
            if not isinstance(occurrence, dict):
                continue
            service_text = normalize_whitespace(
                str(occurrence.get("asset_business_service") or "")
            ).strip()
            owner_text = normalize_whitespace(str(occurrence.get("asset_owner") or "")).strip()
            if service_text:
                top_services[service_text] += 1
            if owner_text:
                top_owners[owner_text] += 1
        top_service = (
            _html_counter_items(top_services, limit=1)[0][0] if top_services else "Unmapped service"
        )
        top_owner = (
            _html_counter_items(top_owners, limit=1)[0][0] if top_owners else "Unassigned owner"
        )
        top_exposure = (
            normalize_whitespace(str(top_provenance.get("highest_asset_exposure") or "")).strip()
            or "No exposure signal"
        )
        top_attack = (
            f"ATT&CK {top_finding.get('attack_relevance') or 'Mapped'}"
            if top_finding.get("attack_mapped")
            else "No ATT&CK mapping"
        )
        top_focus_badges = [
            _html_chip(
                top_priority,
                tone=_html_priority_tone(str(top_finding.get("priority_label", "Low"))),
            )
        ]
        if top_finding.get("in_kev"):
            top_focus_badges.append(_html_chip("Known exploited", tone="critical"))
        if top_finding.get("attack_mapped"):
            top_focus_badges.append(
                _html_chip(
                    f"{len(_html_unique_strings(top_finding.get('attack_techniques', [])))} TTPs",
                    tone="info",
                )
            )
        executive_focus_html = (
            '<article class="executive-focus-card">'
            '<div class="executive-focus-head">'
            "<div>"
            '<p class="label">Top of queue</p>'
            f'<h3 class="executive-focus-title">{escape(top_cve)}</h3>'
            "</div>"
            f'<div class="chip-row">{"".join(top_focus_badges)}</div>'
            "</div>"
            f'<p class="executive-focus-copy">{_html_text(truncate_text(top_finding.get("recommended_action") or "N.A.", 220))}</p>'
            '<div class="executive-focus-grid">'
            f'<article class="executive-focus-item"><span>Route</span><strong>{_html_text(top_service)}</strong></article>'
            f'<article class="executive-focus-item"><span>Owner</span><strong>{_html_text(top_owner)}</strong></article>'
            f'<article class="executive-focus-item"><span>Exposure</span><strong>{_html_text(top_exposure)}</strong></article>'
            f'<article class="executive-focus-item"><span>Threat</span><strong>{_html_text(top_attack)}</strong></article>'
            "</div>"
            "</article>"
        )
    definition_cards = [
        (
            "Priority",
            "The primary queue stays deterministic and rule-based from CVSS, EPSS, and KEV.",
        ),
        (
            "KEV",
            "A KEV listing means public evidence of exploitation in the wild and should trigger immediate scrutiny.",
        ),
        (
            "ATT&CK relevance",
            "ATT&CK explains threat behavior and management framing, but it does not silently replace the base score.",
        ),
        (
            "VEX",
            "VEX records applicability. Suppressed findings can disappear, while under-investigation findings stay visible.",
        ),
        (
            "Waiver",
            "Waivers document accepted risk with owners, review dates, and expiry pressure rather than hiding the finding.",
        ),
        (
            "Asset context",
            "Owner, service, exposure, and environment signals turn a generic finding into an operational remediation route.",
        ),
    ]

    provider_cards = [
        _html_metric_card(
            "NVD Coverage",
            _html_rate(metadata.get("nvd_hits", 0), metadata.get("valid_input", 0)),
            detail="Description + CVSS coverage",
            tone="default",
        ),
        _html_metric_card(
            "EPSS Coverage",
            _html_rate(metadata.get("epss_hits", 0), metadata.get("valid_input", 0)),
            detail="Exploit probability coverage",
            tone="default",
        ),
        _html_metric_card(
            "KEV Coverage",
            _html_rate(metadata.get("kev_hits", 0), metadata.get("valid_input", 0)),
            detail="Known exploited catalog coverage",
            tone="critical",
        ),
        _html_metric_card(
            "ATT&CK Coverage",
            _html_rate(metadata.get("attack_hits", 0), metadata.get("valid_input", 0)),
            detail="Mapped adversary behavior coverage",
            tone="accent",
        ),
    ]

    priority_distribution = []
    max_priority_count = max(
        [int(value) for value in metadata.get("counts_by_priority", {}).values()] or [1]
    )
    for label in ("Critical", "High", "Medium", "Low"):
        count = int(metadata.get("counts_by_priority", {}).get(label, 0) or 0)
        width = max(8, round((count / max_priority_count) * 100)) if count else 8
        priority_distribution.append(
            '<div class="distribution-row">'
            f'<span class="distribution-label">{escape(label)}</span>'
            f'<div class="distribution-track"><span class="distribution-fill tone-{_html_priority_tone(label)}" style="width: {width}%"></span></div>'
            f'<span class="distribution-count">{count}</span>'
            "</div>"
        )

    input_sources = metadata.get("input_sources", [])
    input_source_rows: list[str] = []
    input_source_cards: list[str] = []
    if isinstance(input_sources, list):
        for source in input_sources:
            if not isinstance(source, dict):
                continue
            input_source_rows.append(
                "<tr>"
                f"<td>{_html_text(source.get('input_path'))}</td>"
                f"<td>{_html_text(source.get('input_format'))}</td>"
                f"<td>{_html_text(source.get('total_rows'))}</td>"
                f"<td>{_html_text(source.get('occurrence_count'))}</td>"
                f"<td>{_html_text(source.get('unique_cves'))}</td>"
                "</tr>"
            )
            input_source_cards.append(
                '<article class="kv-card">'
                f"<h4>{_html_text(source.get('input_path'))}</h4>"
                '<dl class="compact-meta">'
                f"<dt>Format</dt><dd>{_html_text(source.get('input_format'))}</dd>"
                f"<dt>Rows</dt><dd>{_html_text(source.get('total_rows'))}</dd>"
                f"<dt>Occurrences</dt><dd>{_html_text(source.get('occurrence_count'))}</dd>"
                f"<dt>Unique CVEs</dt><dd>{_html_text(source.get('unique_cves'))}</dd>"
                "</dl>"
                "</article>"
            )
    input_sources_html = (
        '<div class="table-wrap queue-desktop"><table class="data-table compact-table"><thead><tr>'
        "<th>Input</th><th>Format</th><th>Rows</th><th>Occurrences</th><th>Unique CVEs</th>"
        "</tr></thead><tbody>"
        + ("".join(input_source_rows) or '<tr><td colspan="5">N.A.</td></tr>')
        + "</tbody></table></div>"
        + (
            '<div class="kv-card-grid queue-mobile">' + "".join(input_source_cards) + "</div>"
            if input_source_cards
            else '<p class="empty-copy queue-mobile">No input sources were preserved.</p>'
        )
    )

    warnings_html = (
        '<ul class="bullet-list">'
        + "".join(f"<li>{_html_text(warning)}</li>" for warning in warnings)
        + "</ul>"
        if isinstance(warnings, list) and warnings
        else '<p class="empty-copy">No warnings were recorded for this export.</p>'
    )

    improvement_cards = _html_strengthen_report(metadata, occurrence_summary)
    improvement_html = (
        "".join(
            '<div class="bucket-card">'
            f"<h4>{escape(title)}</h4>"
            f'<p style="font-size:0.82rem;color:var(--text-2);margin-bottom:0;">{escape(description)}</p>'
            f'<code class="command-chip">{escape(command)}</code>'
            "</div>"
            for title, description, command in improvement_cards
        )
        if improvement_cards
        else '<p class="empty-copy">Threat, governance, and evidence layers are already represented in this export.</p>'
    )
    decision_cards_html = _html_top_decision_cards(sorted_findings)
    action_plan_html = _html_action_plan(report_payload)
    provider_transparency_html = _html_provider_transparency(metadata, sorted_findings)
    attack_metadata_chips = "".join(
        chip
        for chip in (
            _html_chip(f"Source {metadata.get('attack_source')}", tone="accent")
            if metadata.get("attack_source")
            else "",
            _html_chip(f"ATT&CK v{metadata.get('attack_version')}", tone="info")
            if metadata.get("attack_version")
            else "",
            _html_chip(f"Domain {metadata.get('attack_domain')}", tone="neutral")
            if metadata.get("attack_domain")
            else "",
            _html_chip(f"Framework {metadata.get('mapping_framework')}", tone="neutral")
            if metadata.get("mapping_framework")
            else "",
            _html_chip(
                f"Mapping version {metadata.get('mapping_framework_version')}", tone="neutral"
            )
            if metadata.get("mapping_framework_version")
            else "",
        )
    )
    attack_mapping_type_labels = _html_top_distribution_labels(
        attack_summary.get("mapping_type_distribution")
    )
    top_attack_techniques = _html_top_distribution_labels(
        attack_summary.get("technique_distribution")
    )
    top_attack_tactics = _html_top_distribution_labels(attack_summary.get("tactic_distribution"))
    unique_attack_techniques = len(
        attack_summary.get("technique_distribution", {})
        if isinstance(attack_summary.get("technique_distribution"), dict)
        else {}
    )
    unique_attack_tactics = len(
        attack_summary.get("tactic_distribution", {})
        if isinstance(attack_summary.get("tactic_distribution"), dict)
        else {}
    )

    attack_context_html = ""
    if attack_enabled:
        attack_summary_copy = (
            f"{mapped_cves} mapped visible CVE(s) contribute {unique_attack_techniques} technique(s) across "
            f"{unique_attack_tactics} tactic(s) in this view."
        )
        if top_attack_techniques:
            attack_summary_copy += f" Most common technique signal: {top_attack_techniques[0]}."
        if top_attack_tactics:
            attack_summary_copy += f" Most common tactic signal: {top_attack_tactics[0]}."
        attack_context_html = (
            '<div class="attack-detail-stack">'
            '<article class="attack-snapshot-card">'
            '<div class="attack-snapshot-head">'
            "<div>"
            '<p class="label">Threat behavior in queue</p>'
            "<h3>ATT&amp;CK coverage snapshot</h3>"
            "</div>"
            + f'<div class="chip-row">{attack_metadata_chips or _html_chip("Local ATT&CK context", tone="accent")}</div>'
            + "</div>"
            + f'<p class="attack-note">{_html_text(attack_summary_copy)}</p>'
            + "</article>"
            '<div class="attack-overview-grid">'
            + _html_metric_card(
                "Mapped CVEs", mapped_cves, detail="Visible mapped findings", tone="info"
            )
            + _html_metric_card(
                "Unmapped CVEs",
                int(attack_summary.get("unmapped_cves", 0) or 0),
                detail="Visible findings without ATT&CK mapping",
                tone="neutral",
            )
            + _html_metric_card(
                "Techniques",
                unique_attack_techniques,
                detail="Unique ATT&CK techniques in view",
                tone="accent",
            )
            + _html_metric_card(
                "Tactics",
                unique_attack_tactics,
                detail="Unique ATT&CK tactics in view",
                tone="default",
            )
            + "</div>"
            + '<div class="attack-taxonomy-grid">'
            + '<article class="attack-block-card"><p class="label">Top techniques</p><div class="chip-row">'
            + _html_chip_list(
                top_attack_techniques,
                tone="info",
                empty_text="No ATT&CK techniques were captured.",
            )
            + "</div></article>"
            + '<article class="attack-block-card"><p class="label">Top tactics</p><div class="chip-row">'
            + _html_chip_list(
                top_attack_tactics,
                tone="neutral",
                empty_text="No ATT&CK tactics were captured.",
            )
            + "</div></article>"
            + '<article class="attack-block-card"><p class="label">Mapping types</p><div class="chip-row">'
            + _html_chip_list(
                attack_mapping_type_labels,
                tone="accent",
                empty_text="No ATT&CK mapping types were captured.",
            )
            + "</div></article>"
            + "</div>"
        )
    else:
        attack_context_html = (
            '<div class="attack-status-card">'
            '<p class="label">Threat behavior unavailable</p>'
            '<p class="empty-copy">ATT&amp;CK context was not supplied in the source analysis run. This report cannot distinguish mapped versus unmapped threat behavior, tactics, techniques, or mapping provenance.</p>'
            '<code class="command-chip">vuln-prioritizer analyze --attack-source ctid-json --attack-mapping-file &lt;mappings.json&gt; --attack-technique-metadata-file &lt;techniques.json&gt;</code>'
            "</div>"
        )

    queue_rows: list[str] = []
    queue_cards: list[str] = []
    for index, finding in enumerate(sorted_findings, start=1):
        cve_id = normalize_whitespace(str(finding.get("cve_id") or "")).strip() or "N.A."
        anchor = f"finding-{_html_slug(cve_id)}"
        provenance = finding.get("provenance", {})
        provenance = provenance if isinstance(provenance, dict) else {}
        occurrences = (
            provenance.get("occurrences", [])
            if isinstance(provenance.get("occurrences", []), list)
            else []
        )
        queue_services = Counter()
        queue_owners = Counter()
        for occurrence in occurrences:
            if not isinstance(occurrence, dict):
                continue
            service_text = normalize_whitespace(
                str(occurrence.get("asset_business_service") or "")
            ).strip()
            owner_text = normalize_whitespace(str(occurrence.get("asset_owner") or "")).strip()
            if service_text:
                queue_services[service_text] += 1
            if owner_text:
                queue_owners[owner_text] += 1
        priority_tone = _html_priority_tone(str(finding.get("priority_label", "Low")))
        urgency_label = _priority_display_label(
            str(finding.get("priority_label", "N.A.")),
            bool(finding.get("in_kev")),
            bool(finding.get("waived")),
            str(finding.get("waiver_status")) if finding.get("waiver_status") else None,
        )
        queue_badges = [
            _html_chip(
                urgency_label,
                tone=priority_tone,
            )
        ]
        if finding.get("in_kev"):
            queue_badges.append(_html_chip("KEV", tone="critical"))
        elif finding.get("attack_mapped"):
            queue_badges.append(
                _html_chip(f"ATT&CK {finding.get('attack_relevance') or 'Mapped'}", tone="accent")
            )
        attack_techniques = _html_unique_strings(finding.get("attack_techniques", []))
        attack_tactics = _html_unique_strings(finding.get("attack_tactics", []))
        if finding.get("attack_mapped") and attack_techniques:
            queue_badges.append(_html_chip(f"{len(attack_techniques)} TTPs", tone="info"))
        if finding.get("under_investigation"):
            queue_badges.append(_html_chip("VEX review", tone="warning"))
        queue_badges_html = "".join(queue_badges)
        queue_service = (
            _html_counter_items(queue_services, limit=1)[0][0]
            if queue_services
            else "Unmapped service"
        )
        queue_owner = (
            _html_counter_items(queue_owners, limit=1)[0][0] if queue_owners else "Unassigned owner"
        )
        queue_exposure = (
            normalize_whitespace(str(provenance.get("highest_asset_exposure") or "")).strip()
            or "No exposure signal"
        )
        queue_criticality = (
            normalize_whitespace(str(finding.get("highest_asset_criticality") or "")).strip()
            or "No asset criticality"
        )
        queue_occurrence_count = int(provenance.get("occurrence_count", len(occurrences)) or 0)
        queue_rows.append(
            f'<tr class="queue-row" data-priority="{escape(str(finding.get("priority_label", "Low")))}">'
            f'<td class="queue-num">{index}</td>'
            '<td class="queue-main">'
            f'<a class="queue-cve-id" href="#{anchor}">{escape(cve_id)}</a>'
            f'<div class="chip-row">{queue_badges_html}</div>'
            f'<p class="queue-desc">{_html_text(truncate_text(finding.get("description") or "N.A.", 180))}</p>'
            "</td>"
            f'<td class="queue-action">{_html_text(truncate_text(finding.get("recommended_action") or "N.A.", 150))}</td>'
            f'<td><a href="#{anchor}" style="font-size:0.8rem;color:var(--c-info);">Detail ↗</a></td>'
            "</tr>"
        )
        queue_cards.append(
            f'<article class="queue-mobile-card" data-priority="{escape(str(finding.get("priority_label", "Low")))}">'
            '<div class="queue-mobile-top">'
            f'<div class="queue-mobile-rank">#{index}</div>'
            f'<a class="queue-cve-id" href="#{anchor}">{escape(cve_id)}</a>'
            "</div>"
            f'<div class="chip-row">{queue_badges_html}</div>'
            '<div class="queue-metrics">'
            f"<span><strong>{_html_score(finding.get('cvss_base_score'), digits=1)}</strong> CVSS</span>"
            f"<span><strong>{_html_score(finding.get('epss'), digits=3)}</strong> EPSS</span>"
            f"<span><strong>{queue_occurrence_count}</strong> occurrences</span>"
            "</div>"
            f'<p class="queue-desc">{_html_text(truncate_text(finding.get("description") or "N.A.", 180))}</p>'
            '<div class="queue-mobile-action">'
            '<p class="label">Immediate action</p>'
            f"<p>{_html_text(truncate_text(finding.get('recommended_action') or 'N.A.', 135))}</p>"
            "</div>"
            '<div class="queue-context-grid">'
            f'<div class="queue-context-item"><span>Service</span><strong>{_html_text(queue_service)}</strong></div>'
            f'<div class="queue-context-item"><span>Owner</span><strong>{_html_text(queue_owner)}</strong></div>'
            f'<div class="queue-context-item"><span>Exposure</span><strong>{_html_text(queue_exposure)}</strong></div>'
            f'<div class="queue-context-item"><span>Criticality</span><strong>{_html_text(queue_criticality)}</strong></div>'
            "</div>"
            f'<a class="queue-mobile-link" href="#{anchor}">Open dossier</a>'
            "</article>"
        )
    priority_queue_html = (
        '<div class="table-wrap queue-desktop"><table class="data-table queue-table"><thead><tr>'
        "<th>#</th><th>Finding</th><th>Immediate action</th><th>Dossier</th>"
        "</tr></thead><tbody>"
        + "".join(queue_rows)
        + "</tbody></table></div>"
        + '<div class="queue-mobile-list queue-mobile">'
        + "".join(queue_cards)
        + "</div>"
        if queue_rows
        else f'<div class="empty-state"><p>{escape(_html_findings_empty_state(metadata))}</p></div>'
    )

    dossier_articles: list[str] = []
    for finding in sorted_findings:
        cve_id = normalize_whitespace(str(finding.get("cve_id") or "")).strip() or "N.A."
        anchor = f"finding-{_html_slug(cve_id)}"
        provenance = finding.get("provenance", {})
        provenance = provenance if isinstance(provenance, dict) else {}
        occurrences = (
            provenance.get("occurrences", [])
            if isinstance(provenance.get("occurrences", []), list)
            else []
        )
        services = Counter()
        owners = Counter()
        exposures = Counter()
        environments = Counter()
        for occurrence in occurrences:
            if not isinstance(occurrence, dict):
                continue
            for key, counter in (
                ("asset_business_service", services),
                ("asset_owner", owners),
                ("asset_exposure", exposures),
                ("asset_environment", environments),
            ):
                text = normalize_whitespace(str(occurrence.get(key) or "")).strip()
                if text:
                    counter[text] += 1
        baseline = _html_baseline_delta(finding)
        source_formats = _html_unique_strings(provenance.get("source_formats", []))
        provenance_components = _html_unique_strings(provenance.get("components", []))
        provenance_targets = _html_unique_strings(provenance.get("targets", []))
        top_service_label = _html_counter_items(services, limit=1)
        top_owner_label = _html_counter_items(owners, limit=1)
        top_exposure_label = _html_counter_items(exposures, limit=1)
        top_environment_label = _html_counter_items(environments, limit=1)
        attack_techniques = _html_unique_strings(finding.get("attack_techniques", []))
        attack_tactics = _html_unique_strings(finding.get("attack_tactics", []))

        badge_tokens = [
            _html_chip(
                str(
                    _priority_display_label(
                        str(finding.get("priority_label", "N.A.")),
                        bool(finding.get("in_kev")),
                        bool(finding.get("waived")),
                        str(finding.get("waiver_status")) if finding.get("waiver_status") else None,
                    )
                ),
                tone=_html_priority_tone(str(finding.get("priority_label", "Low"))),
            ),
            _html_chip(
                _format_exploit_status(bool(finding.get("in_kev"))),
                tone="critical" if finding.get("in_kev") else "neutral",
            ),
            _html_chip(
                f"ATT&CK {finding.get('attack_relevance') or 'Unmapped'}",
                tone="accent" if finding.get("attack_mapped") else "neutral",
            ),
        ]
        if finding.get("attack_mapped") and attack_techniques:
            badge_tokens.append(_html_chip(f"{len(attack_techniques)} TTPs", tone="info"))
        if finding.get("under_investigation"):
            badge_tokens.append(_html_chip("Under investigation", tone="warning"))
        if finding.get("waiver_status") == "expired":
            badge_tokens.append(_html_chip("Waiver expired", tone="critical"))
        elif finding.get("waiver_status") == "review_due":
            badge_tokens.append(_html_chip("Waiver review due", tone="warning"))
        elif finding.get("waived"):
            badge_tokens.append(_html_chip("Waived", tone="accent"))

        priority_tone = _html_priority_tone(str(finding.get("priority_label", "Low")))
        attack_insight_html = (
            '<article class="insight-card">'
            '<p class="label">Threat behavior</p>'
            f'<p class="insight-value">{_html_text(finding.get("attack_relevance"), default="Unmapped")}</p>'
            f'<p class="insight-detail">{_html_text(str(len(attack_techniques)) + " technique(s), top tactic " + (attack_tactics[0] if attack_tactics else "N.A."))}</p>'
            "</article>"
            if finding.get("attack_mapped")
            else ""
        )
        insight_blocks = "".join(
            [
                '<div class="insight-grid">',
                '<article class="insight-card">',
                '<p class="label">Priority signal</p>',
                f'<p class="insight-value">{_html_text(_html_priority_signal(finding))}</p>',
                "</article>",
                '<article class="insight-card">',
                '<p class="label">Service and owner</p>',
                f'<p class="insight-value">{_html_text(top_service_label[0][0] if top_service_label else "Unmapped")}</p>',
                f'<p class="insight-detail">{_html_text(top_owner_label[0][0] if top_owner_label else "Unassigned")}</p>',
                "</article>",
                '<article class="insight-card">',
                '<p class="label">Component and target</p>',
                f'<p class="insight-value">{_html_text(provenance_components[0] if provenance_components else "No component evidence")}</p>',
                f'<p class="insight-detail">{_html_text(provenance_targets[0] if provenance_targets else "No target reference")}</p>',
                "</article>",
                '<article class="insight-card">',
                '<p class="label">Exposure and environment</p>',
                f'<p class="insight-value">{_html_text(top_exposure_label[0][0] if top_exposure_label else "No exposure signal")}</p>',
                f'<p class="insight-detail">{_html_text(top_environment_label[0][0] if top_environment_label else "No environment label")}</p>',
                "</article>",
                attack_insight_html,
                "</div>",
            ]
        )
        attack_preview_html = _html_attack_preview_block(finding, attack_enabled=attack_enabled)
        attack_drawer_meta: list[str] = []
        if attack_enabled:
            if finding.get("attack_mapped"):
                if finding.get("attack_relevance"):
                    attack_drawer_meta.append(f"ATT&CK {finding.get('attack_relevance')}")
                if attack_techniques:
                    attack_drawer_meta.append(f"{len(attack_techniques)} TTPs")
                if attack_tactics:
                    attack_drawer_meta.append(attack_tactics[0])
            else:
                attack_drawer_meta.append("Unmapped")
        attack_drawer_summary = (
            "<summary>"
            '<span class="dossier-drawer-title">ATT&amp;CK context</span>'
            + (
                f'<span class="drawer-meta">{escape(" · ".join(attack_drawer_meta))}</span>'
                if attack_drawer_meta
                else ""
            )
            + "</summary>"
        )
        dossier_articles.append(
            f'<article class="dossier" id="{anchor}">'
            + '<div class="dossier-head">'
            + f'<span class="dossier-cve-id">{escape(cve_id)}</span>'
            + f'<div class="chip-row">{"".join(badge_tokens)}</div>'
            + '<div class="dossier-scores">'
            + f'<div class="score-item"><strong>{_html_score(finding.get("cvss_base_score"), digits=1)}</strong> CVSS</div>'
            + f'<div class="score-item"><strong>{_html_score(finding.get("epss"), digits=3)}</strong> EPSS</div>'
            + f'<div class="score-item"><strong>{int(provenance.get("occurrence_count", 0) or 0)}</strong> occurrences</div>'
            + "</div>"
            + "</div>"
            + '<div class="dossier-body">'
            + f'<p class="dossier-desc">{_html_text(finding.get("description"))}</p>'
            + f'<div class="action-callout" data-urgency="{escape(priority_tone)}">'
            + '<div class="action-callout-label">Recommended Action</div>'
            + f'<p class="action-callout-text">{_html_text(finding.get("recommended_action"))}</p>'
            + "</div>"
            + insight_blocks
            + attack_preview_html
            + f'<p class="dossier-summary">{_html_text(truncate_text(finding.get("rationale") or "N.A.", 260))}</p>'
            + (
                f'<p class="dossier-context">{_html_text(finding.get("context_recommendation"))}</p>'
                if finding.get("context_recommendation")
                else ""
            )
            + "</div>"
            + '<div class="dossier-accordion">'
            + '<details class="dossier-drawer">'
            + "<summary>Provider evidence</summary>"
            + f'<div class="dossier-drawer-body">{_html_provider_evidence_block(finding)}</div>'
            + "</details>"
            + '<details class="dossier-drawer">'
            + "<summary>CVSS-only baseline delta</summary>"
            + '<div class="dossier-drawer-body">'
            + '<ul class="bullet-list compact-list">'
            + f"<li><strong>Baseline (CVSS-only):</strong> {_html_text(baseline['cvss_only_label'])}</li>"
            + f"<li><strong>Delta:</strong> {_html_text(baseline['delta_label'])}</li>"
            + "</ul>"
            + f'<p style="margin-top:0.75rem;font-size:0.875rem;color:var(--text-2);">{_html_text(baseline["reason"])}</p>'
            + "</div>"
            + "</details>"
            + f'<details class="dossier-drawer{" open" if finding.get("attack_mapped") else ""}">'
            + attack_drawer_summary
            + f'<div class="dossier-drawer-body">{_html_attack_block(finding, attack_enabled=attack_enabled)}</div>'
            + "</details>"
            + '<details class="dossier-drawer">'
            + "<summary>Remediation detail</summary>"
            + f'<div class="dossier-drawer-body">{_html_remediation_block(finding)}</div>'
            + "</details>"
            + '<details class="dossier-drawer">'
            + "<summary>Decision logic</summary>"
            + f'<div class="dossier-drawer-body"><p class="empty-copy">{_html_text(finding.get("rationale"), default="No rationale text was generated.")}</p></div>'
            + "</details>"
            + '<details class="dossier-drawer">'
            + "<summary>Governance state</summary>"
            + f'<div class="dossier-drawer-body">{_html_governance_block(finding)}</div>'
            + "</details>"
            + '<details class="dossier-drawer">'
            + "<summary>Routing context</summary>"
            + '<div class="dossier-drawer-body">'
            + '<dl class="routing-grid">'
            + f'<div><dt class="label">Services</dt><dd>{_html_counter_chip_list(services, empty_text="No service ownership data captured.")}</dd></div>'
            + f'<div><dt class="label">Owners</dt><dd>{_html_counter_chip_list(owners, empty_text="No owner data captured.")}</dd></div>'
            + f'<div><dt class="label">Exposure</dt><dd>{_html_counter_chip_list(exposures, empty_text="No exposure signals captured.")}</dd></div>'
            + f'<div><dt class="label">Environment</dt><dd>{_html_counter_chip_list(environments, empty_text="No environment labels captured.")}</dd></div>'
            + f'<div><dt class="label">Source formats</dt><dd>{_html_chip_list(source_formats, tone="neutral", empty_text="No source formats recorded.")}</dd></div>'
            + f'<div><dt class="label">Components</dt><dd>{_html_chip_list(provenance_components, tone="neutral", empty_text="No component evidence recorded.")}</dd></div>'
            + f'<div><dt class="label">Targets</dt><dd>{_html_chip_list(provenance_targets, tone="neutral", empty_text="No target references recorded.")}</dd></div>'
            + "</dl>"
            + "</div>"
            + "</details>"
            + '<details class="dossier-drawer">'
            + f"<summary>Occurrence evidence ({len(occurrences)})</summary>"
            + f'<div class="dossier-drawer-body">{_html_occurrence_rows(occurrences)}</div>'
            + "</details>"
            + "</div>"
            + "</article>"
        )

    dossier_html = (
        "".join(dossier_articles)
        if dossier_articles
        else f'<div class="empty-state"><p>{escape(_html_findings_empty_state(metadata))}</p></div>'
    )

    nav_links = [
        ("executive-brief", "Executive Brief"),
        ("priority-queue", "Priority Queue"),
        ("decision-action", "Decision & Action"),
        ("finding-dossiers", "Finding Dossiers"),
        ("coverage-context", "Coverage & Context"),
        ("attack-governance", "ATT&CK & Governance"),
        ("how-to-read", "How to Read"),
    ]
    nav_html = "".join(f'<a href="#{anchor}">{escape(label)}</a>' for anchor, label in nav_links)
    headline_stats = [
        ("", "Visible findings", visible_findings),
        ("is-critical", "Critical", critical_count),
        ("is-high", "KEV", kev_visible),
        ("is-medium", "Under investigation", under_investigation),
        ("", "Suppressed by VEX", suppressed_count),
        ("", "Waiver review due", review_due_count),
    ]
    stats_html = "".join(
        '<div class="stat-cell' + (f" {tone_class}" if tone_class else "") + '">'
        f'<div class="stat-value">{escape(str(value))}</div>'
        f'<div class="stat-label">{escape(label)}</div>'
        "</div>"
        for tone_class, label, value in headline_stats
    )

    styles = """
    :root {
      --bg: #f5f6f8;
      --surface: #ffffff;
      --surface-sunken: #f8f9fb;
      --text-1: #111827;
      --text-2: #4b5563;
      --text-3: #9ca3af;
      --border: #e5e7eb;
      --border-strong: #d1d5db;
      --c-critical: #dc2626; --c-critical-bg: #fef2f2; --c-critical-border: #fecaca;
      --c-high:     #ea580c; --c-high-bg:     #fff7ed; --c-high-border:     #fed7aa;
      --c-medium:   #d97706; --c-medium-bg:   #fffbeb; --c-medium-border:   #fde68a;
      --c-low:      #6b7280; --c-low-bg:      #f9fafb; --c-low-border:      #e5e7eb;
      --c-info:     #2563eb; --c-info-bg:     #eff6ff; --c-info-border:     #bfdbfe;
      --shadow-sm: 0 1px 3px rgba(0,0,0,0.08);
      --shadow-md: 0 4px 12px rgba(0,0,0,0.08);
      --radius: 10px;
      --radius-sm: 6px;
      --radius-chip: 4px;
      --font-sans: "Avenir Next", "Segoe UI", -apple-system, BlinkMacSystemFont, system-ui, sans-serif;
      --font-serif: "Iowan Old Style", "Palatino Linotype", "Book Antiqua", Georgia, serif;
      --font-mono: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
    }
    *, *::before, *::after { box-sizing: border-box; }
    html { scroll-behavior: auto; }
    body {
      margin: 0;
      min-height: 100vh;
      font-family: var(--font-sans);
      font-size: 15px;
      line-height: 1.6;
      color: var(--text-1);
      background:
        radial-gradient(circle at top left, rgba(37, 99, 235, 0.04), transparent 26%),
        linear-gradient(180deg, #f5f3ee 0%, #f6f7fa 42%, #eef2f8 100%);
    }
    main {
      max-width: 1360px;
      margin: 0 auto;
      padding: 1rem 1rem calc(10rem + env(safe-area-inset-bottom, 0px));
    }
    h1, h2, h3, h4, h5, p, dl, ul {
      margin-top: 0;
    }
    h1 {
      font-family: var(--font-serif);
      font-size: clamp(1.65rem, 2.5vw, 2.3rem);
      font-weight: 700;
      line-height: 1.08;
      letter-spacing: -0.02em;
      margin-bottom: 0.35rem;
    }
    h2 {
      font-family: var(--font-serif);
      font-size: 1.4rem;
      font-weight: 700;
      letter-spacing: -0.01em;
      margin-bottom: 0.3rem;
    }
    h3 { font-size: 1.05rem; font-weight: 600; margin-bottom: 0.25rem; }
    h4 { font-size: 0.9rem; font-weight: 600; margin-bottom: 0.25rem; color: var(--text-2); }
    h5 { font-size: 0.8rem; font-weight: 600; margin-bottom: 0.2rem; text-transform: uppercase; letter-spacing: 0.04em; color: var(--text-3); }
    p {
      line-height: 1.65;
    }
    a {
      color: var(--c-info);
      text-decoration: none;
    }
    a:hover { text-decoration: underline; }

    /* ── Topbar ─────────────────────────────────────────── */
    .topbar {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 0.5rem 1.5rem;
      padding: 0.9rem 1.25rem;
      background: linear-gradient(135deg, #101827 0%, #16233b 100%);
      color: #f9fafb;
      border-radius: var(--radius) var(--radius) 0 0;
    }
    .topbar-brand {
      font-size: 0.85rem;
      font-weight: 700;
      letter-spacing: 0.03em;
      color: #f9fafb;
    }
    .topbar-copy {
      display: grid;
      gap: 0.1rem;
    }
    .topbar-meta {
      font-size: 0.78rem;
      color: #9ca3af;
      overflow-wrap: anywhere;
    }
    .topbar-chips {
      display: flex;
      flex-wrap: wrap;
      gap: 0.35rem;
      margin-left: auto;
    }

    /* ── Page nav ───────────────────────────────────────── */
    .page-nav {
      position: sticky;
      top: 0;
      z-index: 10;
      display: flex;
      flex-wrap: wrap;
      gap: 0;
      background: var(--surface);
      border-bottom: 1px solid var(--border);
      box-shadow: var(--shadow-sm);
    }
    .page-nav a {
      flex: 0 0 auto;
      padding: 0.65rem 1.1rem;
      font-size: 0.8rem;
      font-weight: 500;
      color: var(--text-2);
      text-decoration: none;
      border-bottom: 2px solid transparent;
      transition: color 120ms, border-color 120ms;
      white-space: nowrap;
    }
    .page-nav a:hover {
      color: var(--text-1);
      border-bottom-color: var(--border-strong);
      text-decoration: none;
    }

    /* ── Stats row ──────────────────────────────────────── */
    .stats-row {
      display: flex;
      flex-wrap: wrap;
      gap: 0;
      background: var(--surface);
      border: 1px solid var(--border);
      border-top: 0;
      border-radius: 0 0 var(--radius) var(--radius);
      margin-bottom: 1.25rem;
      overflow: hidden;
    }
    .stat-cell {
      flex: 1 1 100px;
      padding: 1rem 1.25rem;
      border-right: 1px solid var(--border);
      text-align: center;
    }
    .stat-cell:last-child { border-right: 0; }
    .stat-value {
      font-size: 1.9rem;
      font-weight: 700;
      line-height: 1;
      margin-bottom: 0.2rem;
      color: var(--text-1);
    }
    .stat-label {
      font-size: 0.73rem;
      font-weight: 500;
      color: var(--text-3);
      text-transform: uppercase;
      letter-spacing: 0.04em;
    }
    .stat-cell.is-critical .stat-value { color: var(--c-critical); }
    .stat-cell.is-high     .stat-value { color: var(--c-high); }
    .stat-cell.is-medium   .stat-value { color: var(--c-medium); }

    /* ── Sections ───────────────────────────────────────── */
    .section {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      margin-top: 1.1rem;
      overflow: hidden;
      box-shadow: var(--shadow-sm);
    }
    .section-header {
      padding: 1.1rem 1.35rem 0.85rem;
      border-bottom: 1px solid var(--border);
      background: linear-gradient(180deg, rgba(255,255,255,0.98), rgba(248,250,253,0.95));
    }
    .section-header h2 {
      margin-bottom: 0.15rem;
      font-size: 1.45rem;
    }
    .section-subtitle {
      font-size: 0.82rem;
      color: var(--text-2);
      margin-bottom: 0;
      max-width: 72rem;
    }
    .section-inner {
      padding: 1.25rem 1.35rem;
    }
    .section-inner + .section-inner {
      border-top: 1px solid var(--border);
      padding-top: 1rem;
    }
    .stack {
      display: grid;
      gap: 0.85rem;
    }
    .panel-card {
      padding: 1rem;
      border: 1px solid var(--border);
      border-radius: var(--radius-sm);
      background: linear-gradient(180deg, #ffffff 0%, #f8f9fc 100%);
      min-width: 0;
      box-shadow: var(--shadow-sm);
      height: 100%;
    }
    .executive-hero-card {
      background:
        radial-gradient(circle at top right, rgba(234, 88, 12, 0.06), transparent 28%),
        linear-gradient(180deg, #fffdfa 0%, #f9fbff 100%);
    }
    .executive-hero-head {
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 0.9rem;
      flex-wrap: wrap;
    }
    .hero-lead {
      margin-bottom: 0;
      font-size: 0.95rem;
      color: var(--text-1);
      line-height: 1.55;
      max-width: 42rem;
    }
    .executive-focus-card {
      padding: 1rem 1.05rem;
      border: 1px solid var(--border);
      border-radius: var(--radius-sm);
      background: linear-gradient(180deg, rgba(255,255,255,0.92), rgba(246,248,252,0.92));
      display: grid;
      gap: 0.85rem;
      box-shadow: var(--shadow-sm);
    }
    .executive-focus-head {
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 0.75rem;
      flex-wrap: wrap;
    }
    .executive-focus-title {
      margin: 0;
      font-family: var(--font-serif);
      font-size: clamp(1.15rem, 1.8vw, 1.4rem);
      line-height: 1.08;
      letter-spacing: -0.02em;
      color: var(--text-1);
    }
    .executive-focus-copy {
      margin: 0;
      font-size: 0.88rem;
      line-height: 1.6;
      color: var(--text-1);
      max-width: 58rem;
    }
    .executive-focus-grid {
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 0.65rem;
    }
    .executive-focus-item {
      padding: 0.72rem 0.78rem;
      border: 1px solid var(--border);
      border-radius: var(--radius-sm);
      background: rgba(255, 255, 255, 0.78);
      min-width: 0;
    }
    .executive-focus-item span {
      display: block;
      margin-bottom: 0.14rem;
      font-size: 0.68rem;
      font-weight: 700;
      letter-spacing: 0.05em;
      text-transform: uppercase;
      color: var(--text-3);
    }
    .executive-focus-item strong {
      display: block;
      font-size: 0.83rem;
      font-weight: 600;
      line-height: 1.4;
      color: var(--text-1);
      overflow-wrap: anywhere;
    }
    .review-flow-grid {
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 0.65rem;
    }
    .review-step {
      padding: 0.78rem 0.82rem;
      border: 1px solid var(--border);
      border-radius: var(--radius-sm);
      background: rgba(255, 255, 255, 0.66);
      min-width: 0;
    }
    .review-step-index {
      display: block;
      margin-bottom: 0.28rem;
      font-size: 0.68rem;
      font-weight: 700;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      color: var(--c-info);
    }
    .review-step h4 {
      margin-bottom: 0.3rem;
      color: var(--text-1);
    }
    .review-step p {
      margin: 0;
      font-size: 0.78rem;
      line-height: 1.5;
      color: var(--text-2);
    }
    .hero-highlights {
      grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
    }
    .snapshot-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
      gap: 0.65rem;
    }
    .snapshot-card {
      padding: 0.8rem 0.85rem;
      border: 1px solid var(--border);
      border-radius: var(--radius-sm);
      background: rgba(255, 255, 255, 0.72);
    }
    .snapshot-label {
      margin-bottom: 0.2rem;
      font-size: 0.7rem;
      font-weight: 700;
      letter-spacing: 0.05em;
      text-transform: uppercase;
      color: var(--text-3);
    }
    .snapshot-value {
      margin-bottom: 0.25rem;
      font-size: 1rem;
      font-weight: 700;
      line-height: 1.2;
      color: var(--text-1);
    }
    .snapshot-detail {
      margin: 0;
      font-size: 0.76rem;
      line-height: 1.45;
      color: var(--text-2);
    }

    /* ── Metric cards ───────────────────────────────────── */
    .metric-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
      gap: 0.75rem;
      align-items: stretch;
    }
    .metric-card {
      padding: 0.85rem 1rem;
      border: 1px solid var(--border);
      border-radius: var(--radius-sm);
      background: var(--surface-sunken);
      height: 100%;
    }
    .metric-card[data-tone="critical"] { border-color: var(--c-critical-border); background: var(--c-critical-bg); }
    .metric-card[data-tone="high"]     { border-color: var(--c-high-border);     background: var(--c-high-bg); }
    .metric-card[data-tone="medium"]   { border-color: var(--c-medium-border);   background: var(--c-medium-bg); }
    .metric-card[data-tone="warning"]  { border-color: var(--c-medium-border);   background: var(--c-medium-bg); }
    .metric-card[data-tone="info"],
    .metric-card[data-tone="accent"]   { border-color: var(--c-info-border);     background: var(--c-info-bg); }
    .metric-label {
      font-size: 0.72rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--text-3);
      margin-bottom: 0.25rem;
    }
    .metric-value {
      font-size: 1.55rem;
      font-weight: 700;
      line-height: 1;
      color: var(--text-1);
    }
    .metric-card[data-tone="critical"] .metric-value { color: var(--c-critical); }
    .metric-card[data-tone="high"]     .metric-value { color: var(--c-high); }
    .metric-card[data-tone="medium"]   .metric-value { color: var(--c-medium); }
    .metric-card[data-tone="warning"]  .metric-value { color: var(--c-medium); }
    .metric-card[data-tone="info"],
    .metric-card[data-tone="accent"]   { color: var(--c-info); }
    .metric-detail {
      font-size: 0.78rem;
      color: var(--text-2);
      margin-top: 0.25rem;
      margin-bottom: 0;
    }

    /* ── Chips ──────────────────────────────────────────── */
    .chip {
      display: inline-flex;
      align-items: center;
      padding: 0.18rem 0.55rem;
      font-size: 0.72rem;
      font-weight: 600;
      border-radius: var(--radius-chip);
      border: 1px solid var(--border);
      background: var(--surface-sunken);
      color: var(--text-2);
      white-space: nowrap;
    }
    .chip-with-count {
      gap: 0.38rem;
    }
    .chip-label {
      min-width: 0;
    }
    .chip-count {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-width: 1.15rem;
      height: 1.15rem;
      padding: 0 0.28rem;
      border-radius: 999px;
      background: rgba(17, 24, 39, 0.08);
      color: var(--text-1);
      font-size: 0.68rem;
      font-weight: 700;
      line-height: 1;
    }
    .chip[data-tone="critical"] { background: var(--c-critical-bg); border-color: var(--c-critical-border); color: var(--c-critical); }
    .chip[data-tone="high"]     { background: var(--c-high-bg);     border-color: var(--c-high-border);     color: var(--c-high); }
    .chip[data-tone="medium"]   { background: var(--c-medium-bg);   border-color: var(--c-medium-border);   color: var(--c-medium); }
    .chip[data-tone="info"],
    .chip[data-tone="accent"]   { background: var(--c-info-bg);     border-color: var(--c-info-border);     color: var(--c-info); }
    .chip[data-tone="warning"]  { background: var(--c-medium-bg);   border-color: var(--c-medium-border);   color: var(--c-medium); }
    .chip[data-tone="critical"] .chip-count {
      background: rgba(220, 38, 38, 0.12);
      color: var(--c-critical);
    }
    .chip[data-tone="high"] .chip-count {
      background: rgba(234, 88, 12, 0.12);
      color: var(--c-high);
    }
    .chip[data-tone="medium"] .chip-count,
    .chip[data-tone="warning"] .chip-count {
      background: rgba(217, 119, 6, 0.14);
      color: var(--c-medium);
    }
    .chip[data-tone="info"] .chip-count,
    .chip[data-tone="accent"] .chip-count {
      background: rgba(37, 99, 235, 0.12);
      color: var(--c-info);
    }
    .chip-row {
      display: flex;
      flex-wrap: wrap;
      gap: 0.3rem;
    }
    .empty-copy {
      margin: 0;
      color: var(--text-3);
      font-size: 0.82rem;
      line-height: 1.55;
    }

    /* ── Label ──────────────────────────────────────────── */
    .label {
      font-size: 0.7rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--text-3);
      margin-bottom: 0.3rem;
    }

    /* ── Data tables ────────────────────────────────────── */
    .table-scroll { overflow-x: auto; }
    .table-wrap { overflow-x: auto; }
    .data-table,
    .compact-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.82rem;
    }
    .data-table th,
    .compact-table th {
      padding: 0.5rem 0.75rem;
      text-align: left;
      font-size: 0.72rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      color: var(--text-3);
      background: var(--surface-sunken);
      border-bottom: 1px solid var(--border);
      white-space: nowrap;
    }
    .data-table td,
    .compact-table td {
      padding: 0.55rem 0.75rem;
      border-bottom: 1px solid var(--border);
      vertical-align: top;
      overflow-wrap: anywhere;
    }
    .data-table tr:last-child td,
    .compact-table tr:last-child td { border-bottom: 0; }
    .data-table tr:hover td { background: var(--surface-sunken); }
    .compact-list { margin: 0; }
    .inline-link { word-break: break-all; }

    /* ── Priority queue ─────────────────────────────────── */
    .queue-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.84rem;
    }
    .queue-table th {
      padding: 0.5rem 0.75rem;
      text-align: left;
      font-size: 0.72rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      color: var(--text-3);
      background: var(--surface-sunken);
      border-bottom: 1px solid var(--border);
    }
    .queue-row td {
      padding: 0.9rem 0.75rem;
      border-bottom: 1px solid var(--border);
      vertical-align: top;
    }
    .queue-row:last-child td { border-bottom: 0; }
    .queue-num {
      width: 2.5rem;
      color: var(--text-3);
      font-size: 0.8rem;
      font-weight: 600;
      text-align: center;
    }
    .queue-main { width: 100%; }
    .queue-row[data-priority="Critical"] td.queue-num { border-left: 3px solid var(--c-critical); }
    .queue-row[data-priority="High"]     td.queue-num { border-left: 3px solid var(--c-high); }
    .queue-row[data-priority="Medium"]   td.queue-num { border-left: 3px solid var(--c-medium); }
    .queue-row[data-priority="Low"]      td.queue-num { border-left: 3px solid var(--c-low); }
    .queue-cve-id {
      font-size: 0.88rem;
      font-weight: 700;
      color: var(--text-1);
      text-decoration: none;
    }
    .queue-cve-id:hover { color: var(--c-info); text-decoration: underline; }
    .queue-desc {
      font-size: 0.82rem;
      color: var(--text-2);
      margin: 0.3rem 0 0;
      line-height: 1.5;
    }
    .queue-desktop {
      display: none;
    }
    .queue-mobile {
      display: grid;
    }
    .queue-mobile-list {
      gap: 0.85rem;
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
    }
    .queue-mobile-card {
      padding: 1rem 1.05rem;
      border: 1px solid var(--border);
      border-radius: var(--radius-sm);
      background: linear-gradient(180deg, #ffffff 0%, #f8f9fc 100%);
      display: grid;
      gap: 0.75rem;
      box-shadow: var(--shadow-sm);
    }
    .queue-mobile-card[data-priority="Critical"] { border-left: 3px solid var(--c-critical); }
    .queue-mobile-card[data-priority="High"] { border-left: 3px solid var(--c-high); }
    .queue-mobile-card[data-priority="Medium"] { border-left: 3px solid var(--c-medium); }
    .queue-mobile-card[data-priority="Low"] { border-left: 3px solid var(--c-low); }
    .queue-mobile-top {
      display: flex;
      align-items: center;
      gap: 0.75rem;
      flex-wrap: wrap;
    }
    .queue-mobile-rank {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 2rem;
      height: 2rem;
      border-radius: 999px;
      background: var(--surface);
      border: 1px solid var(--border);
      font-size: 0.8rem;
      font-weight: 700;
      color: var(--text-2);
    }
    .queue-mobile-action {
      padding: 0.7rem 0.8rem;
      border: 1px solid var(--border);
      border-radius: var(--radius-sm);
      background: var(--surface);
    }
    .queue-mobile-action p:last-child {
      margin-bottom: 0;
    }
    .queue-mobile-link {
      font-size: 0.82rem;
      font-weight: 600;
    }
    .queue-metrics {
      display: flex;
      flex-wrap: wrap;
      gap: 0.75rem 1rem;
      font-size: 0.8rem;
      color: var(--text-2);
    }
    .queue-metrics strong {
      color: var(--text-1);
      margin-right: 0.2rem;
    }
    .queue-context-grid {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 0.55rem;
    }
    .queue-context-item {
      padding: 0.55rem 0.65rem;
      border: 1px solid var(--border);
      border-radius: var(--radius-sm);
      background: rgba(255, 255, 255, 0.8);
      min-width: 0;
    }
    .queue-context-item span {
      display: block;
      margin-bottom: 0.15rem;
      font-size: 0.68rem;
      font-weight: 700;
      letter-spacing: 0.05em;
      text-transform: uppercase;
      color: var(--text-3);
    }
    .queue-context-item strong {
      display: block;
      font-size: 0.82rem;
      font-weight: 600;
      line-height: 1.35;
      color: var(--text-1);
      overflow-wrap: anywhere;
    }

    /* ── Dossier 3-zone card ────────────────────────────── */
    .dossier {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      margin-bottom: 0.85rem;
      overflow: hidden;
    }
    .dossier:last-child { margin-bottom: 0; }
    .dossier-head {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 0.5rem 1rem;
      padding: 0.9rem 1.2rem;
      background: var(--surface-sunken);
      border-bottom: 1px solid var(--border);
    }
    .dossier-cve-id {
      font-family: var(--font-serif);
      font-size: clamp(1.18rem, 1.75vw, 1.45rem);
      font-weight: 700;
      color: var(--text-1);
      letter-spacing: -0.02em;
    }
    .dossier-scores {
      display: flex;
      gap: 1.25rem;
      margin-left: auto;
      flex-wrap: wrap;
    }
    .score-item {
      font-size: 0.8rem;
      color: var(--text-2);
    }
    .score-item strong {
      font-size: 1rem;
      color: var(--text-1);
      margin-right: 0.2rem;
    }
    .dossier-body {
      padding: 1.1rem 1.2rem;
      border-bottom: 1px solid var(--border);
      display: grid;
      gap: 0.95rem;
    }
    .dossier-desc {
      font-size: 0.88rem;
      color: var(--text-2);
      margin-bottom: 0;
      max-width: 72rem;
      display: -webkit-box;
      -webkit-box-orient: vertical;
      -webkit-line-clamp: 4;
      overflow: hidden;
    }
    .action-callout {
      padding: 0.85rem 1rem;
      border-radius: var(--radius-sm);
      border-left: 3px solid var(--border-strong);
      background: linear-gradient(180deg, rgba(255,255,255,0.75), rgba(255,255,255,0.35));
      margin-bottom: 0;
    }
    .action-callout[data-urgency="critical"] { border-left-color: var(--c-critical); background: var(--c-critical-bg); }
    .action-callout[data-urgency="high"]     { border-left-color: var(--c-high);     background: var(--c-high-bg); }
    .action-callout[data-urgency="medium"]   { border-left-color: var(--c-medium);   background: var(--c-medium-bg); }
    .action-callout[data-urgency="info"],
    .action-callout[data-urgency="accent"]   { border-left-color: var(--c-info);     background: var(--c-info-bg); }
    .action-callout-label {
      font-size: 0.7rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      color: var(--text-3);
      margin-bottom: 0.3rem;
    }
    .action-callout-text {
      font-size: 0.88rem;
      color: var(--text-1);
      margin: 0;
      line-height: 1.55;
    }
    .dossier-rationale {
      font-size: 0.82rem;
      color: var(--text-2);
      margin: 0;
      line-height: 1.6;
    }
    .dossier-summary {
      margin: 0;
      font-size: 0.86rem;
      color: var(--text-2);
      line-height: 1.65;
      max-width: 74rem;
      display: -webkit-box;
      -webkit-box-orient: vertical;
      -webkit-line-clamp: 3;
      overflow: hidden;
    }
    .dossier-context {
      font-size: 0.82rem;
      color: var(--text-2);
      margin-bottom: 0;
    }
    .insight-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 0.7rem;
    }
    .insight-card {
      padding: 0.75rem 0.85rem;
      border: 1px solid var(--border);
      border-radius: var(--radius-sm);
      background: var(--surface-sunken);
      min-width: 0;
    }
    .insight-value {
      margin: 0;
      font-size: 0.88rem;
      font-weight: 600;
      color: var(--text-1);
      line-height: 1.45;
    }
    .insight-detail {
      margin: 0.25rem 0 0;
      font-size: 0.78rem;
      color: var(--text-2);
      line-height: 1.45;
    }
    .attack-preview {
      display: grid;
      gap: 0.85rem;
      padding: 0.95rem 1rem;
      border: 1px solid var(--c-info-border);
      border-radius: var(--radius-sm);
      background: linear-gradient(180deg, #fbfdff 0%, #f1f6ff 100%);
      box-shadow: inset 0 1px 0 rgba(255,255,255,0.7);
    }
    .attack-preview-empty {
      border-color: var(--border-strong);
      background: linear-gradient(180deg, #fbfcfe 0%, #f5f7fa 100%);
    }
    .attack-preview-head {
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 0.8rem;
      flex-wrap: wrap;
    }
    .attack-preview-head h3 {
      margin-bottom: 0;
      font-size: 1.02rem;
      color: var(--text-1);
    }
    .attack-preview-copy {
      margin: 0;
      font-size: 0.84rem;
      line-height: 1.65;
      color: var(--text-1);
      max-width: 72rem;
      display: -webkit-box;
      -webkit-box-orient: vertical;
      -webkit-line-clamp: 3;
      overflow: hidden;
    }
    .attack-preview-taxonomy {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 0.75rem;
    }
    .attack-mini-stack {
      display: grid;
      gap: 0.35rem;
      min-width: 0;
    }
    .attack-mini-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 0.65rem;
    }
    .attack-mini-card {
      padding: 0.75rem 0.8rem;
      border: 1px solid rgba(191, 219, 254, 0.9);
      border-radius: var(--radius-sm);
      background: rgba(255,255,255,0.85);
      min-width: 0;
    }
    .attack-mini-id {
      margin-bottom: 0.2rem;
      font-size: 0.76rem;
      font-weight: 700;
      letter-spacing: 0.04em;
      text-transform: uppercase;
      color: var(--c-info);
    }
    .attack-mini-name {
      margin: 0;
      font-size: 0.86rem;
      font-weight: 600;
      line-height: 1.4;
      color: var(--text-1);
    }
    .attack-mini-meta {
      margin: 0.28rem 0 0;
      font-size: 0.76rem;
      line-height: 1.45;
      color: var(--text-2);
    }

    /* ── Dossier accordion ──────────────────────────────── */
    .dossier-accordion {
      padding: 0;
    }
    .dossier-drawer {
      border-top: 1px solid var(--border);
    }
    .dossier-drawer summary {
      padding: 0.65rem 1.2rem;
      font-size: 0.82rem;
      font-weight: 600;
      color: var(--text-2);
      cursor: pointer;
      list-style: none;
      display: flex;
      align-items: center;
      gap: 0.75rem;
      user-select: none;
    }
    .dossier-drawer summary::-webkit-details-marker { display: none; }
    .dossier-drawer summary::before {
      content: "▶";
      font-size: 0.6rem;
      color: var(--text-3);
      transition: transform 150ms;
    }
    .dossier-drawer[open] summary::before { transform: rotate(90deg); }
    .dossier-drawer summary:hover { background: var(--surface-sunken); }
    .dossier-drawer[open] summary {
      background: linear-gradient(180deg, #fbfcfe 0%, #f4f7fb 100%);
      color: var(--text-1);
    }
    .dossier-drawer-title {
      min-width: 0;
      margin-right: auto;
    }
    .drawer-meta {
      font-size: 0.75rem;
      font-weight: 600;
      color: var(--text-3);
      text-align: right;
      overflow-wrap: anywhere;
    }
    .dossier-drawer-body,
    .dossier-drawer-inner {
      padding: 0.9rem 1.2rem 1.1rem;
      background: var(--surface-sunken);
      border-top: 1px solid var(--border);
    }
    .routing-grid {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 1rem;
    }
    .routing-grid dt {
      margin-bottom: 0.35rem;
    }
    .routing-grid dd {
      margin: 0;
      display: flex;
      flex-wrap: wrap;
      gap: 0.35rem;
    }

    /* ── Evidence groups ────────────────────────────────── */
    .evidence-groups {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
      gap: 1rem;
    }
    .evidence-group h5 { margin-bottom: 0.5rem; }
    .evidence-group dl { margin: 0; }
    .provider-links {
      margin-top: 0.65rem;
    }

    /* ── Decision cards ─────────────────────────────────── */
    .decision-grid-3 {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 0.75rem;
    }
    .decision-stack {
      display: grid;
      gap: 0.75rem;
      align-content: start;
    }
    .decision-card {
      padding: 0.85rem 1rem;
      border: 1px solid var(--border);
      border-radius: var(--radius-sm);
      background: var(--surface-sunken);
      min-width: 0;
      height: 100%;
    }
    .decision-card[data-priority="Critical"] { border-left: 3px solid var(--c-critical); background: var(--c-critical-bg); }
    .decision-card[data-priority="High"]     { border-left: 3px solid var(--c-high);     background: var(--c-high-bg); }
    .decision-card[data-priority="Medium"]   { border-left: 3px solid var(--c-medium);   background: var(--c-medium-bg); }
    .decision-topline {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 0.5rem 0.75rem;
      margin-bottom: 0.6rem;
    }
    .decision-topline h4 {
      margin: 0;
      font-size: 1rem;
      color: var(--text-1);
    }
    .decision-action-line {
      margin-bottom: 0.75rem;
      font-size: 0.9rem;
      font-weight: 600;
      color: var(--text-1);
      line-height: 1.45;
    }
    .decision-chip-row {
      margin-bottom: 0.75rem;
    }
    .decision-why {
      margin: 0;
      font-size: 0.82rem;
      line-height: 1.55;
      color: var(--text-2);
    }
    .decision-meta {
      display: grid;
      grid-template-columns: 120px 1fr;
      gap: 0.35rem 0.85rem;
      margin: 0;
      font-size: 0.82rem;
    }
    .decision-meta dt {
      color: var(--text-3);
      font-weight: 600;
    }
    .decision-meta dd {
      margin: 0;
      color: var(--text-2);
    }

    /* ── Bucket cards (action plan) ─────────────────────── */
    .action-plan-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 0.75rem;
    }
    .action-plan-stack {
      display: grid;
      gap: 1rem;
      align-content: start;
    }
    .action-plan-section {
      display: grid;
      gap: 0.75rem;
    }
    .bucket-card {
      padding: 0.85rem 1rem;
      border: 1px solid var(--border);
      border-radius: var(--radius-sm);
      background: var(--surface-sunken);
      min-width: 0;
      height: 100%;
    }
    .bucket-topline {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 0.5rem;
      margin-bottom: 0.55rem;
    }
    .bucket-topline h4 {
      margin: 0;
      color: var(--text-1);
    }
    .bucket-summary {
      margin: 0 0 0.75rem;
      font-size: 0.82rem;
      line-height: 1.55;
      color: var(--text-2);
    }
    .bucket-meta {
      display: grid;
      grid-template-columns: 110px 1fr;
      gap: 0.35rem 0.8rem;
      margin: 0;
      font-size: 0.82rem;
    }
    .bucket-meta dt {
      color: var(--text-3);
      font-weight: 600;
    }
    .bucket-meta dd {
      margin: 0;
      color: var(--text-1);
      overflow-wrap: anywhere;
    }

    /* ── Remediation items ──────────────────────────────── */
    .remediation-items {
      display: flex;
      flex-direction: column;
      gap: 0.6rem;
    }
    .remediation-item {
      padding: 0.7rem 0.9rem;
      border: 1px solid var(--border);
      border-radius: var(--radius-sm);
      background: var(--surface-sunken);
      font-size: 0.82rem;
    }
    .subtle {
      margin-bottom: 0.3rem;
      font-size: 0.8rem;
      color: var(--text-2);
    }

    /* ── ATT&CK ──────────────────────────────────────────── */
    .attack-detail-stack {
      display: grid;
      gap: 0.9rem;
    }
    .attack-snapshot-card {
      padding: 1rem 1.05rem;
      border: 1px solid var(--c-info-border);
      border-radius: var(--radius-sm);
      background: linear-gradient(180deg, #fcfdff 0%, #f1f6ff 100%);
      display: grid;
      gap: 0.8rem;
    }
    .attack-snapshot-head {
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 0.75rem;
      flex-wrap: wrap;
    }
    .attack-overview-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
      gap: 0.75rem;
    }
    .attack-taxonomy-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 0.75rem;
    }
    .attack-block-card {
      padding: 0.85rem 0.95rem;
      border: 1px solid var(--border);
      border-radius: var(--radius-sm);
      background: linear-gradient(180deg, #fbfcff 0%, #f5f8ff 100%);
      min-width: 0;
      height: 100%;
    }
    .attack-status-card {
      padding: 0.9rem 1rem;
      border: 1px solid var(--c-info-border);
      border-radius: var(--radius-sm);
      background: linear-gradient(180deg, #f8fbff 0%, #eef5ff 100%);
      display: grid;
      gap: 0.7rem;
    }
    .attack-note {
      margin: 0;
      font-size: 0.84rem;
      line-height: 1.65;
      color: var(--text-1);
    }
    .attack-technique-section {
      display: grid;
      gap: 0.5rem;
    }
    .attack-technique-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 0.75rem;
    }
    .attack-technique-card {
      padding: 0.95rem 1rem;
      border: 1px solid rgba(191, 219, 254, 0.95);
      border-radius: calc(var(--radius-sm) + 2px);
      background: linear-gradient(180deg, #ffffff 0%, #f7fbff 100%);
      min-width: 0;
      display: grid;
      gap: 0.65rem;
      box-shadow: var(--shadow-sm);
    }
    .attack-technique-kicker {
      margin: 0;
      font-size: 0.67rem;
      font-weight: 700;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      color: var(--text-3);
    }
    .attack-technique-head {
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 0.75rem;
      margin-bottom: 0;
    }
    .attack-technique-id {
      margin-bottom: 0.15rem;
      font-size: 0.78rem;
      font-weight: 700;
      letter-spacing: 0.04em;
      text-transform: uppercase;
      color: var(--c-info);
    }
    .attack-technique-link {
      color: var(--c-info);
      text-decoration: none;
    }
    .attack-technique-link:hover {
      text-decoration: underline;
    }
    .attack-technique-name {
      margin: 0;
      font-size: 0.96rem;
      line-height: 1.35;
      color: var(--text-1);
    }
    .attack-technique-body {
      display: grid;
      gap: 0.55rem;
    }
    .attack-technique-meta-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 0.65rem;
      padding-top: 0.05rem;
      font-size: 0.78rem;
      color: var(--text-2);
    }
    .attack-technique-meta-row span {
      font-weight: 600;
      color: var(--text-3);
      text-transform: uppercase;
      letter-spacing: 0.04em;
      font-size: 0.67rem;
    }
    .attack-technique-meta-row strong {
      color: var(--text-1);
      font-weight: 700;
      text-align: right;
    }
    .attack-technique-chip-row {
      display: flex;
      flex-wrap: wrap;
      gap: 0.35rem;
    }
    .attack-technique-footer {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 0.65rem;
      padding-top: 0.1rem;
      font-size: 0.74rem;
      color: var(--text-3);
    }
    .attack-technique-ref {
      color: var(--c-info);
      font-weight: 600;
      text-decoration: none;
      white-space: nowrap;
    }
    .attack-technique-ref:hover {
      text-decoration: underline;
    }
    .attack-dl,
    .governance-dl {
      margin: 0;
      display: grid;
      grid-template-columns: auto 1fr;
      gap: 0.35rem 1rem;
      font-size: 0.82rem;
      align-items: start;
    }
    .attack-dl dt,
    .governance-dl dt {
      font-weight: 600;
      color: var(--text-2);
      white-space: nowrap;
    }
    .attack-dl dd,
    .governance-dl dd {
      margin: 0;
      color: var(--text-1);
    }
    .governance-item { margin-bottom: 0.5rem; }

    /* ── Two-col layout ─────────────────────────────────── */
    .two-col {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 1rem;
      align-items: start;
    }
    .three-col {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 0.75rem;
      align-items: start;
    }
    .hero-grid {
      grid-template-columns: minmax(0, 1.28fr) minmax(320px, 0.72fr);
    }
    .executive-meta-card {
      align-content: start;
    }
    .decision-layout {
      grid-template-columns: minmax(0, 0.95fr) minmax(0, 1.05fr);
    }
    .decision-layout > .panel-card {
      height: auto;
      align-self: start;
    }
    .decision-layout > .panel-card.stack {
      align-content: start;
    }
    .attack-governance-layout {
      display: grid;
      grid-template-columns: minmax(0, 1.25fr) minmax(320px, 0.75fr);
      gap: 1rem;
      align-items: start;
    }
    .attack-side-stack {
      display: grid;
      gap: 1rem;
      align-content: start;
    }
    .attack-primary-card {
      align-self: start;
    }
    .summary-list {
      display: grid;
      gap: 0.5rem;
      margin: 0;
      padding-left: 1.2rem;
      font-size: 0.84rem;
      color: var(--text-2);
      line-height: 1.55;
    }
    .kv-card-grid {
      display: grid;
      gap: 0.75rem;
    }
    .kv-card {
      padding: 0.85rem 1rem;
      border: 1px solid var(--border);
      border-radius: var(--radius-sm);
      background: var(--surface-sunken);
      height: 100%;
    }
    .kv-card h4 {
      margin-bottom: 0.55rem;
      color: var(--text-1);
      overflow-wrap: anywhere;
    }
    .compact-meta {
      display: grid;
      grid-template-columns: 92px 1fr;
      gap: 0.35rem 0.75rem;
      margin: 0;
      font-size: 0.82rem;
    }
    .compact-meta dt {
      color: var(--text-3);
      font-weight: 600;
    }
    .compact-meta dd {
      margin: 0;
      color: var(--text-2);
      overflow-wrap: anywhere;
    }

    /* ── Bullet list ────────────────────────────────────── */
    .bullet-list {
      padding-left: 1.3rem;
      margin: 0;
      font-size: 0.84rem;
      color: var(--text-1);
      line-height: 1.7;
    }

    /* ── Command chip / code ────────────────────────────── */
    .command-chip {
      display: inline-block;
      padding: 0.15rem 0.5rem;
      font-family: var(--font-mono);
      font-size: 0.78rem;
      background: var(--surface-sunken);
      border: 1px solid var(--border);
      border-radius: var(--radius-chip);
      color: var(--text-1);
    }

    /* ── Meta row (key-value) ───────────────────────────── */
    .meta-grid {
      display: grid;
      grid-template-columns: auto 1fr;
      gap: 0.3rem 1rem;
      font-size: 0.82rem;
    }
    .meta-grid dt {
      font-weight: 600;
      color: var(--text-2);
      white-space: nowrap;
    }
    .meta-grid dd {
      margin: 0;
      color: var(--text-1);
    }

    /* ── Method grid (how-to-read) ──────────────────────── */
    .method-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 0.75rem;
    }
    .method-card {
      padding: 0.75rem 0.9rem;
      border: 1px solid var(--border);
      border-radius: var(--radius-sm);
      background: var(--surface-sunken);
      font-size: 0.82rem;
      height: 100%;
    }
    .report-footer {
      margin-top: 1.15rem;
      padding-bottom: env(safe-area-inset-bottom, 0px);
    }
    .report-footer-shell {
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto;
      gap: 1rem;
      align-items: center;
      padding: 1rem 1.2rem;
      border: 1px solid var(--border);
      border-radius: var(--radius);
      background: linear-gradient(180deg, rgba(255,255,255,0.98), rgba(246,248,252,0.98));
      box-shadow: var(--shadow-sm);
    }
    .report-footer-note {
      margin: 0;
      max-width: 52rem;
      font-size: 0.84rem;
      line-height: 1.6;
      color: var(--text-2);
    }
    .report-footer-meta {
      display: grid;
      justify-items: end;
      gap: 0.3rem;
      font-size: 0.78rem;
      color: var(--text-3);
      text-align: right;
    }
    .report-footer-link {
      font-weight: 700;
      color: var(--c-info);
      text-decoration: none;
    }
    .report-footer-link:hover {
      text-decoration: underline;
    }
    .report-tail-spacer {
      height: max(320px, calc(14rem + env(safe-area-inset-bottom, 0px)));
    }

    /* ── Context toggle ─────────────────────────────────── */
    .context-toggle summary {
      display: inline-flex;
      align-items: center;
      gap: 0.4rem;
      cursor: pointer;
      font-size: 0.82rem;
      font-weight: 600;
      color: var(--text-2);
      margin-bottom: 0.75rem;
      list-style: none;
      padding: 0.35rem 0.7rem;
      border: 1px solid var(--border);
      border-radius: var(--radius-sm);
    }
    .context-toggle summary::-webkit-details-marker { display: none; }
    .context-toggle[open] summary { margin-bottom: 0.9rem; }

    /* ── Empty state ────────────────────────────────────── */
    .empty-state {
      padding: 2.5rem 1.5rem;
      text-align: center;
      color: var(--text-3);
      font-size: 0.9rem;
    }
    .empty-state strong { display: block; font-size: 1.1rem; color: var(--text-2); margin-bottom: 0.5rem; }
    .distribution-row {
      display: grid;
      grid-template-columns: 92px 1fr auto;
      align-items: center;
      gap: 0.65rem;
      margin-bottom: 0.55rem;
    }
    .distribution-row:last-child {
      margin-bottom: 0;
    }
    .distribution-label,
    .distribution-count {
      font-size: 0.8rem;
      color: var(--text-2);
    }
    .distribution-track {
      position: relative;
      height: 0.55rem;
      border-radius: 999px;
      background: var(--border);
      overflow: hidden;
    }
    .distribution-fill {
      position: absolute;
      inset: 0 auto 0 0;
      border-radius: inherit;
      background: var(--text-3);
    }
    .distribution-fill.tone-critical { background: var(--c-critical); }
    .distribution-fill.tone-high { background: var(--c-high); }
    .distribution-fill.tone-medium { background: var(--c-medium); }
    .distribution-fill.tone-neutral { background: var(--c-low); }
    .distribution-fill.tone-accent { background: var(--c-info); }

    /* ── Misc ───────────────────────────────────────────── */
    .muted { color: var(--text-3); font-size: 0.8rem; }
    .na    { color: var(--text-3); font-style: italic; font-size: 0.82rem; }

    /* ── Media queries ──────────────────────────────────── */
    @media (max-width: 900px) {
      .stats-row { flex-direction: column; }
      .stat-cell { border-right: 0; border-bottom: 1px solid var(--border); }
      .stat-cell:last-child { border-bottom: 0; }
      .dossier-scores { margin-left: 0; }
      .page-nav { overflow-x: auto; flex-wrap: nowrap; }
      .topbar {
        align-items: flex-start;
      }
      .topbar-chips {
        margin-left: 0;
      }
      .hero-grid,
      .decision-layout,
      .attack-governance-layout {
        grid-template-columns: 1fr;
      }
      .review-flow-grid,
      .executive-focus-grid {
        grid-template-columns: repeat(2, minmax(0, 1fr));
      }
    }
    @media (max-width: 780px) {
      .queue-mobile-list {
        grid-template-columns: 1fr;
      }
      .queue-context-grid {
        grid-template-columns: 1fr;
      }
    }
    @media (max-width: 660px) {
      .evidence-groups,
      .two-col,
      .three-col,
      .attack-preview-taxonomy,
      .review-flow-grid,
      .executive-focus-grid,
      .method-grid,
      .routing-grid,
      .insight-grid,
      .attack-overview-grid,
      .attack-taxonomy-grid,
      .attack-technique-grid {
        grid-template-columns: 1fr;
      }
      .report-footer-shell,
      .report-footer-meta {
        grid-template-columns: 1fr;
        justify-items: start;
        text-align: left;
      }
      .stats-row {
        border-radius: var(--radius);
      }
      .section-header,
      .section-inner {
        padding-left: 1rem;
        padding-right: 1rem;
      }
      .dossier-head,
      .dossier-body,
      .dossier-drawer summary,
      .dossier-drawer-body {
        padding-left: 1rem;
        padding-right: 1rem;
      }
      .drawer-meta {
        font-size: 0.72rem;
      }
      .compact-meta,
      .decision-meta,
      .bucket-meta {
        grid-template-columns: 1fr;
      }
      .bucket-topline {
        align-items: flex-start;
        flex-direction: column;
      }
      .attack-technique-meta-row,
      .attack-technique-footer {
        align-items: flex-start;
        flex-direction: column;
      }
      .data-table,
      .compact-table,
      .queue-table {
        min-width: 560px;
      }
    }
    """

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>vuln-prioritizer operations report</title>
  <style>{styles}</style>
</head>
<body>
  <main>
    <header class="report-shell">
      <div class="topbar">
        <div class="topbar-copy">
          <div class="topbar-brand">vuln-prioritizer</div>
          <div class="topbar-meta">Offline HTML report</div>
        </div>
        <div class="topbar-meta">Generated {_html_text(metadata.get("generated_at"))}</div>
        <div class="topbar-meta">Input {_html_text(metadata.get("input_path"))}</div>
        <div class="topbar-meta">Format {_html_text(metadata.get("input_format"))}</div>
        <div class="topbar-chips">
          {_html_chip(f"Policy {metadata.get('policy_profile', 'default')}", tone="accent")}
          {_html_chip(f"ATT&CK {'Enabled' if attack_enabled else 'Disabled'}", tone="accent" if attack_enabled else "neutral")}
          {_html_chip(f"Warnings {warning_count}", tone="warning" if warning_count else "neutral")}
        </div>
      </div>
      <nav class="page-nav" aria-label="Report sections">{nav_html}</nav>
      <div class="stats-row">{stats_html}</div>
    </header>

    <section class="section" id="executive-brief" data-section="executive-brief">
      <div class="section-header">
        <h1>Vulnerability prioritization report</h1>
        <p class="section-subtitle">{escape(_html_brief_summary(metadata, sorted_findings, attack_summary, occurrence_summary))}</p>
      </div>
      <div class="section-inner">
        <div class="two-col hero-grid">
          <article class="panel-card stack executive-hero-card">
            <div class="executive-hero-head">
              <div>
                <p class="label">What to know first</p>
                <p class="hero-lead">Start with the top finding. Confirm owner and route, then open detailed evidence only if the decision is not already obvious.</p>
              </div>
              <div class="chip-row">
                {_html_chip(f"Visible queue {visible_findings}", tone="neutral")}
                {_html_chip(f"KEV {kev_visible}", tone="critical" if kev_visible else "neutral")}
                {_html_chip(f"Suppressed by VEX {suppressed_count}", tone="warning" if suppressed_count else "neutral")}
              </div>
            </div>
            {executive_focus_html}
          </article>
          <article class="panel-card stack executive-meta-card">
            <div>
              <p class="label">Run metadata</p>
              <dl class="meta-grid">
                {_html_meta_row("Generated at", metadata.get("generated_at"))}
                {_html_meta_row("Input", metadata.get("input_path"))}
                {_html_meta_row("Format", metadata.get("input_format"))}
                {_html_meta_row("Policy profile", metadata.get("policy_profile", "default"))}
                {_html_meta_row("Visible findings", visible_findings)}
                {_html_meta_row("Valid CVEs", metadata.get("valid_input", 0))}
                {_html_meta_row("Warnings", warning_count)}
              </dl>
            </div>
            <div>
              <p class="label">Use this view</p>
              <p class="muted">The top bar already gives the headline counts. This panel only keeps the run context that matters while reviewing the queue.</p>
            </div>
          </article>
        </div>
      </div>
    </section>

    <section id="key-signals" data-section="key-signals" hidden aria-hidden="true">
      <h2>Key Signals</h2>
    </section>

    <section class="section" id="priority-queue" data-section="priority-queue">
      <div class="section-header">
        <h2>Priority Queue</h2>
        <p class="section-subtitle">Start here. The queue is designed for quick reading before diving into evidence.</p>
      </div>
      <div class="section-inner">
        {priority_queue_html}
      </div>
    </section>

    <section class="section" id="decision-action" data-section="decision-action">
      <div class="section-header">
        <h2>Decision &amp; Action</h2>
        <p class="section-subtitle">Ownership, sequencing, and why the top of the queue moved above a CVSS-only view.</p>
      </div>
      <div class="section-inner">
        <div class="two-col decision-layout">
        <article class="panel-card stack">
          <div>
            <p class="label">Escalation queue</p>
            <h3>What needs action now</h3>
          </div>
          {decision_cards_html}
        </article>
        <article class="panel-card stack">
          <div>
            <p class="label">Ownership</p>
            <h3>Action plan</h3>
          </div>
          {action_plan_html}
        </article>
        </div>
      </div>
    </section>

    <section class="section" id="finding-dossiers" data-section="finding-dossiers">
      <div class="section-header">
        <h2>Finding Dossiers</h2>
        <p class="section-subtitle">Detailed CVE views with recommended action up front and supporting evidence behind expanders.</p>
      </div>
      <div class="section-inner">
        {dossier_html}
      </div>
    </section>

    <section class="section" id="coverage-context" data-section="coverage-context">
      <div class="section-header">
        <h2>Coverage &amp; Context</h2>
        <p class="section-subtitle">Shows enrichment completeness and what routing context actually survived into the payload.</p>
      </div>
      <div class="section-inner">
        <div class="metric-grid">{"".join(provider_cards)}</div>
      </div>
      <div class="section-inner">
        <div class="three-col">
          <article class="panel-card stack">
            <div>
              <p class="label">Coverage mix</p>
              <h3>Priority distribution</h3>
            </div>
            {"".join(priority_distribution)}
          </article>
          <article class="panel-card stack">
            <div>
              <p class="label">Routing context</p>
              <h3>Who and what is affected</h3>
            </div>
            <div>
              <p class="label">Services</p>
              <div class="chip-row">{_html_counter_chip_list(occurrence_summary["services"], empty_text="No service ownership data captured.")}</div>
            </div>
            <div>
              <p class="label">Owners</p>
              <div class="chip-row">{_html_counter_chip_list(occurrence_summary["owners"], empty_text="No owner routing data captured.")}</div>
            </div>
            <div>
              <p class="label">Exposure</p>
              <div class="chip-row">{_html_counter_chip_list(occurrence_summary["exposures"], empty_text="No exposure signals captured.")}</div>
            </div>
            <div>
              <p class="label">Environments</p>
              <div class="chip-row">{_html_counter_chip_list(occurrence_summary["environments"], empty_text="No environment labels captured.")}</div>
            </div>
          </article>
          <article class="panel-card stack">
            <div>
              <p class="label">Quality signals</p>
              <h3>Warnings and density</h3>
            </div>
            {warnings_html}
            <ul class="bullet-list">
              <li><strong>Occurrences retained:</strong> {_html_text(occurrence_summary["occurrence_total"])}</li>
              <li><strong>Components in queue:</strong> {_html_text(occurrence_summary["component_count"])}</li>
              <li><strong>Targets in queue:</strong> {_html_text(occurrence_summary["target_count"])}</li>
              <li><strong>Mapped assets:</strong> {_html_text(occurrence_summary["asset_count"])}</li>
            </ul>
          </article>
        </div>
      </div>
      <div class="section-inner">
        <article class="panel-card stack">
          <div>
            <p class="label">Payload completeness</p>
            <h3>Input and preservation</h3>
          </div>
          {input_sources_html}
          <p class="muted">The table above shows which inputs made it into the saved analysis payload that powers this report.</p>
        </article>
      </div>
      <div class="section-inner">
        <article class="panel-card stack">
          <div>
            <p class="label">Provider notes</p>
            <h3>Provider transparency</h3>
          </div>
          {provider_transparency_html}
        </article>
      </div>
    </section>

    <section class="section" id="attack-governance" data-section="attack-governance">
      <div class="section-header">
        <h2>ATT&amp;CK &amp; Governance</h2>
        <p class="section-subtitle">Threat behavior plus control-state coverage: suppressed, investigated, waived, or missing.</p>
      </div>
      <div class="section-inner">
        <div class="attack-governance-layout">
        <article class="panel-card stack attack-primary-card">
          <div>
            <p class="label">Threat behavior</p>
            <h3>ATT&amp;CK context</h3>
          </div>
          {attack_context_html}
        </article>
        <div class="attack-side-stack">
          <article class="panel-card stack">
            <div>
              <p class="label">Control state</p>
              <h3>Governance state</h3>
            </div>
            <ul class="bullet-list">
              <li><strong>Suppressed by VEX:</strong> {_html_text(suppressed_count)}</li>
              <li><strong>Under investigation:</strong> {_html_text(under_investigation)}</li>
              <li><strong>Waived findings:</strong> {_html_text(waived_count)}</li>
              <li><strong>Waiver review due:</strong> {_html_text(review_due_count)}</li>
              <li><strong>Expired waivers:</strong> {_html_text(expired_waiver_count)}</li>
              <li><strong>Waiver file:</strong> {_html_text(metadata.get("waiver_file"), default="Not supplied for this run.")}</li>
            </ul>
          </article>
          <article class="panel-card stack">
            <div>
              <p class="label">Next improvements</p>
              <h3>Missing context</h3>
            </div>
            {improvement_html}
          </article>
        </div>
        </div>
      </div>
    </section>

    <section class="section" id="how-to-read" data-section="how-to-read">
      <div class="section-header">
        <h2>How to Read This Report</h2>
        <p class="section-subtitle">Interpretation rules for reviewers. Secondary to the live queue, but useful for governance and audit context.</p>
      </div>
      <div class="section-inner">
        <details class="context-toggle">
          <summary>Open method notes</summary>
          <div class="method-grid">
            {"".join(f'<article class="method-card"><h4>{escape(title)}</h4><p class="empty-copy">{escape(copy)}</p></article>' for title, copy in definition_cards)}
          </div>
        </details>
      </div>
    </section>

    <footer class="report-footer">
      <div class="report-footer-shell">
        <div>
          <p class="label">End of report</p>
          <p class="report-footer-note">Static offline export for triage, routing, and evidence review. This footer adds final spacing so the last section is fully reachable in embedded browsers.</p>
        </div>
        <div class="report-footer-meta">
          <span>Generated {_html_text(metadata.get("generated_at"))}</span>
          <span>Input {_html_text(metadata.get("input_path"))}</span>
          <a class="report-footer-link" href="#executive-brief">Back to top</a>
        </div>
      </div>
    </footer>
    <div class="report-tail-spacer" aria-hidden="true"></div>

  </main>
</body>
</html>
"""

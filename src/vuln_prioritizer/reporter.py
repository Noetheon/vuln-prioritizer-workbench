"""Report generation and terminal rendering."""

from __future__ import annotations

import json
from html import escape
from pathlib import Path

from rich.console import Group
from rich.panel import Panel
from rich.table import Table

from vuln_prioritizer.models import (
    AnalysisContext,
    AttackData,
    AttackMapping,
    AttackSummary,
    ComparisonFinding,
    DoctorReport,
    EpssData,
    EvidenceBundleManifest,
    KevData,
    NvdData,
    PrioritizedFinding,
    RollupBucket,
    RollupCandidate,
    RollupMetadata,
    SnapshotDiffItem,
    SnapshotDiffMetadata,
    SnapshotDiffSummary,
    SnapshotMetadata,
)


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

    for finding in findings:
        table.add_row(
            finding.cve_id,
            _format_priority_indicator(
                finding.priority_label,
                finding.suppressed_by_vex,
                in_kev=finding.in_kev,
                waived=finding.waived,
            ),
            format_score(finding.cvss_base_score, digits=1),
            format_score(finding.epss, digits=3),
            "Yes" if finding.in_kev else "No",
            _format_attack_indicator(finding.attack_mapped, len(finding.attack_technique_details)),
            finding.attack_relevance,
            ", ".join(finding.provenance.source_formats) or "N.A.",
            truncate_text(finding.description or "N.A.", 90),
        )

    return table


def render_compare_table(comparisons: list[ComparisonFinding]) -> Table:
    """Build the Rich comparison table shown in the terminal."""
    table = Table(title="CVSS-only vs Enriched Prioritization", show_lines=False)
    table.add_column("CVE", style="bold")
    table.add_column("CVSS-only")
    table.add_column("Enriched")
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
            ),
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
        f"Findings shown: {context.findings_count}",
        f"Filtered out: {context.filtered_out_count}",
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
    if context.suppressed_by_vex:
        lines.append(f"Suppressed by VEX: {context.suppressed_by_vex}")
    if context.under_investigation_count:
        lines.append(f"Under investigation: {context.under_investigation_count}")
    if context.waived_count:
        lines.append(f"Waived: {context.waived_count}")

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
            "| CVE ID | Description | CVSS | Severity | CVSS Version | EPSS | EPSS Percentile | "
            "KEV | ATT&CK | Attack Relevance | Sources | Asset Criticality | VEX | Waiver | "
            "Priority | Rationale | Recommended Action | Context Recommendation |",
            "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | "
            "--- | --- | --- | --- | --- |",
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
                "| CVE ID | Mapping Types | Techniques | Tactics | Capability Groups "
                "| ATT&CK Note |",
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


def generate_json_report(
    findings: list[PrioritizedFinding],
    context: AnalysisContext,
) -> str:
    """Render the JSON export."""
    payload = build_analysis_report_payload(findings, context)
    return json.dumps(payload, indent=2, sort_keys=True)


def build_analysis_report_payload(
    findings: list[PrioritizedFinding],
    context: AnalysisContext,
) -> dict:
    """Build the canonical analysis payload shared by JSON and HTML renderers."""
    return {
        "metadata": context.model_dump(exclude={"attack_summary"}),
        "attack_summary": context.attack_summary.model_dump(),
        "findings": [finding.model_dump() for finding in findings],
    }


def build_snapshot_report_payload(
    findings: list[PrioritizedFinding],
    metadata: SnapshotMetadata,
) -> dict:
    """Build the canonical snapshot payload."""
    return {
        "metadata": metadata.model_dump(exclude={"attack_summary"}),
        "attack_summary": metadata.attack_summary.model_dump(),
        "findings": [finding.model_dump() for finding in findings],
    }


def generate_summary_markdown(report_payload: dict) -> str:
    """Render a short executive Markdown summary from an analysis-style payload."""
    metadata = report_payload.get("metadata", {})
    attack_summary = report_payload.get("attack_summary", {})
    findings = report_payload.get("findings", [])
    counts_by_priority = metadata.get("counts_by_priority", {})
    lines = [
        "# Vulnerability Prioritization Summary",
        "",
        f"- Input: `{metadata.get('input_path', 'N.A.')}`",
        f"- Input format: `{metadata.get('input_format', 'N.A.')}`",
        f"- Policy profile: `{metadata.get('policy_profile', 'default')}`",
        f"- Findings shown: {metadata.get('findings_count', 0)}",
        f"- Critical: {counts_by_priority.get('Critical', 0)}",
        f"- High: {counts_by_priority.get('High', 0)}",
        f"- KEV hits: {metadata.get('kev_hits', 0)}",
        f"- Waived: {metadata.get('waived_count', 0)}",
        f"- ATT&CK mapped CVEs: {attack_summary.get('mapped_cves', 0)}",
        "",
        "## Top Findings",
    ]
    if findings:
        top_findings = findings[:5]
        for finding in top_findings:
            lines.append(
                "- "
                + f"{finding.get('cve_id', 'N.A.')} — "
                + _priority_display_label(
                    str(finding.get("priority_label", "N.A.")),
                    bool(finding.get("in_kev")),
                    bool(finding.get("waived")),
                )
                + ": "
                + normalize_whitespace(str(finding.get("rationale", "N.A.")))
            )
    else:
        lines.append("- No findings matched the current filters.")
    return "\n".join(lines) + "\n"


def generate_compare_markdown(
    comparisons: list[ComparisonFinding],
    context: AnalysisContext,
) -> str:
    """Render the Markdown comparison report."""
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
            "| CVE ID | Description | CVSS-only | Enriched | ATT&CK | Attack Relevance | "
            "Delta | Changed | CVSS | EPSS | KEV | Waiver | Reason |",
            "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
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
                        _priority_display_label(row.enriched_label, row.in_kev, row.waived)
                    ),
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


def generate_compare_json(
    comparisons: list[ComparisonFinding],
    context: AnalysisContext,
) -> str:
    """Render the JSON comparison export."""
    payload = {
        "metadata": context.model_dump(exclude={"attack_summary"}),
        "attack_summary": context.attack_summary.model_dump(),
        "comparisons": [row.model_dump() for row in comparisons],
    }
    return json.dumps(payload, indent=2, sort_keys=True)


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


def generate_snapshot_diff_json(
    items: list[SnapshotDiffItem],
    summary: SnapshotDiffSummary,
    metadata: SnapshotDiffMetadata,
) -> str:
    """Render the JSON snapshot diff export."""
    payload = {
        "metadata": metadata.model_dump(),
        "summary": summary.model_dump(),
        "items": [item.model_dump() for item in items],
    }
    return json.dumps(payload, indent=2, sort_keys=True)


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
        "| Rank | Bucket | Priority | Actionable/Total | Critical | KEV | Waived | Owners | "
        "Patch First | Why First | Next Actions |",
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


def generate_rollup_json(
    buckets: list[RollupBucket],
    metadata: RollupMetadata,
) -> str:
    """Render the JSON rollup export."""
    payload = {
        "metadata": metadata.model_dump(),
        "buckets": [bucket.model_dump() for bucket in buckets],
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def _format_rollup_candidates(candidates: list[RollupCandidate]) -> str:
    if not candidates:
        return "N.A."
    return "; ".join(f"{candidate.cve_id} ({candidate.rank_reason})" for candidate in candidates)


def _format_rollup_reason(bucket: RollupBucket) -> str:
    if bucket.actionable_count == 0:
        base = "All findings waived"
    else:
        parts = [bucket.highest_priority]
        if bucket.kev_count:
            parts.append("KEV")
        if bucket.internet_facing_count:
            parts.append("internet-facing")
        if bucket.production_count:
            parts.append("prod")
        if bucket.waived_count:
            parts.append(f"{bucket.waived_count} waived")
        base = " + ".join(parts)

    if not bucket.context_hints:
        return base
    return base + " (" + ", ".join(bucket.context_hints) + ")"


def generate_doctor_json(report: DoctorReport) -> str:
    """Render the JSON doctor report."""
    return json.dumps(report.model_dump(), indent=2, sort_keys=True)


def generate_evidence_bundle_manifest_json(manifest: EvidenceBundleManifest) -> str:
    """Render the JSON manifest stored inside evidence bundles."""
    return json.dumps(manifest.model_dump(), indent=2, sort_keys=True)


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


def generate_explain_json(
    finding: PrioritizedFinding,
    nvd: NvdData,
    epss: EpssData,
    kev: KevData,
    attack: AttackData,
    context: AnalysisContext,
    comparison: ComparisonFinding | None = None,
) -> str:
    """Render a single-CVE detailed JSON explanation."""
    payload = {
        "metadata": context.model_dump(exclude={"attack_summary"}),
        "attack_summary": context.attack_summary.model_dump(),
        "finding": finding.model_dump(),
        "nvd": nvd.model_dump(),
        "epss": epss.model_dump(),
        "kev": kev.model_dump(),
        "attack": attack.model_dump(),
        "comparison": comparison.model_dump() if comparison is not None else None,
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def generate_sarif_report(
    findings: list[PrioritizedFinding],
    context: AnalysisContext,
) -> str:
    """Render a SARIF report for analyze output."""
    level_map = {
        "Critical": "error",
        "High": "error",
        "Medium": "warning",
        "Low": "note",
    }
    results: list[dict] = []
    for finding in findings:
        message = (
            f"{finding.cve_id}: {finding.priority_label} priority "
            "based on CVSS/EPSS/KEV with contextual enrichment."
        )
        results.append(
            {
                "ruleId": f"vuln-prioritizer/{finding.priority_label.lower()}",
                "level": level_map.get(finding.priority_label, "note"),
                "message": {"text": message},
                "properties": {
                    "cve": finding.cve_id,
                    "priority": finding.priority_label,
                    "cvss": finding.cvss_base_score,
                    "epss": finding.epss,
                    "in_kev": finding.in_kev,
                    "attack_relevance": finding.attack_relevance,
                    "sources": finding.provenance.source_formats,
                    "components": finding.provenance.components,
                    "suppressed_by_vex": finding.suppressed_by_vex,
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": finding.provenance.affected_paths[0]
                                if finding.provenance.affected_paths
                                else context.input_path
                            }
                        }
                    }
                ],
            }
        )
    payload = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "vuln-prioritizer",
                        "version": context.schema_version,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(payload, indent=2, sort_keys=True)


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
        )
        exploit_status = _format_exploit_status(bool(finding.get("in_kev")))
        rationale = escape(finding.get("rationale") or "N.A.")
        description = escape(finding.get("description") or "N.A.")
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
            f"<td>{escape(finding.get('context_recommendation') or 'N.A.')}</td>"
            "</tr>"
        )
    findings_count = escape(str(metadata.get("findings_count", 0)))
    suppressed_count = escape(str(metadata.get("suppressed_by_vex", 0)))
    waived_count = escape(str(metadata.get("waived_count", 0)))
    mapped_cves = escape(str(attack_summary.get("mapped_cves", 0)))
    kev_count = escape(str(kev_hits))
    critical_total = escape(str(critical_count))
    findings_header = "<th>CVE</th><th>Urgency</th><th>CVSS</th><th>EPSS</th>"
    findings_header += "<th>Exploit Status</th><th>Sources</th><th>Rationale</th>"
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
        <p>
          <strong>Policy profile:</strong>
          {escape(str(metadata.get("policy_profile", "default")))}
        </p>
      </div>
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


def format_score(value: float | None, digits: int) -> str:
    """Format numeric output or return N.A."""
    if value is None:
        return "N.A."
    return f"{value:.{digits}f}"


def format_change(delta_rank: int) -> str:
    """Render the comparison delta for terminal and Markdown output."""
    if delta_rank > 0:
        return f"Up {delta_rank}"
    if delta_rank < 0:
        return f"Down {abs(delta_rank)}"
    return "No change"


def truncate_text(value: str, limit: int) -> str:
    """Keep long descriptions compact in the terminal view."""
    value = normalize_whitespace(value)
    if len(value) <= limit:
        return value
    return value[: limit - 3] + "..."


def escape_pipes(value: str) -> str:
    """Escape Markdown table separators."""
    return normalize_whitespace(value).replace("|", "\\|").strip()


def normalize_whitespace(value: str) -> str:
    """Flatten multi-line values for console and Markdown rendering."""
    return " ".join(value.replace("\r", " ").replace("\n", " ").split())


def comma_or_na(values: list[str]) -> str:
    """Render lists consistently."""
    return ", ".join(values) if values else "N.A."


def format_filters(active_filters: list[str]) -> str:
    """Render filters consistently across Markdown and terminal output."""
    return ", ".join(active_filters) if active_filters else "None"


def _run_metadata_lines(context: AnalysisContext) -> list[str]:
    lines = [
        f"- Generated at: `{context.generated_at}`",
        f"- Input file: `{context.input_path}`",
        f"- Output format: `{context.output_format}`",
        f"- ATT&CK context enabled: `{'yes' if context.attack_enabled else 'no'}`",
        f"- ATT&CK source: `{context.attack_source}`",
        f"- Cache enabled: `{'yes' if context.cache_enabled else 'no'}`",
    ]
    if context.output_path:
        lines.append(f"- Output path: `{context.output_path}`")
    if context.cache_dir:
        lines.append(f"- Cache directory: `{context.cache_dir}`")
    if context.attack_mapping_file:
        lines.append(f"- ATT&CK mapping file: `{context.attack_mapping_file}`")
    if context.attack_technique_metadata_file:
        lines.append(
            f"- ATT&CK technique metadata file: `{context.attack_technique_metadata_file}`"
        )
    if context.mapping_framework:
        lines.append(f"- ATT&CK mapping framework: `{context.mapping_framework}`")
    if context.mapping_framework_version:
        lines.append(f"- ATT&CK mapping framework version: `{context.mapping_framework_version}`")
    if context.attack_version:
        lines.append(f"- ATT&CK version: `{context.attack_version}`")
    if context.attack_domain:
        lines.append(f"- ATT&CK domain: `{context.attack_domain}`")
    if context.waiver_file:
        lines.append(f"- Waiver file: `{context.waiver_file}`")
    lines.append(f"- Policy overrides: `{format_filters(context.policy_overrides)}`")
    return lines


def _summary_lines(context: AnalysisContext) -> list[str]:
    lines = [
        f"- Total input rows: {context.total_input}",
        f"- Valid unique CVEs: {context.valid_input}",
        f"- Findings shown: {context.findings_count}",
        f"- Filtered out: {context.filtered_out_count}",
        f"- NVD hits: {context.nvd_hits}/{context.valid_input}",
        f"- EPSS hits: {context.epss_hits}/{context.valid_input}",
        f"- KEV hits: {context.kev_hits}/{context.valid_input}",
        f"- ATT&CK hits: {context.attack_hits}/{context.valid_input}",
        f"- Waived: {context.waived_count}",
    ]
    for label in ("Critical", "High", "Medium", "Low"):
        lines.append(f"- {label}: {context.counts_by_priority.get(label, 0)}")
    lines.append(f"- Active filters: {format_filters(context.active_filters)}")
    return lines


def _attack_methodology_lines(context: AnalysisContext) -> list[str]:
    if not context.attack_enabled:
        return ["- ATT&CK context was disabled for this run."]
    return [
        "- ATT&CK context is sourced from explicit local files only.",
        "- No heuristic or LLM-generated CVE-to-ATT&CK mapping is performed.",
        "- ATT&CK relevance is reported separately and does not change the primary priority score.",
    ]


def _attack_summary_lines(summary: AttackSummary, enabled: bool) -> list[str]:
    if not enabled:
        return ["ATT&CK context was disabled for this export."]

    lines = [
        f"- CVEs with ATT&CK mappings: {summary.mapped_cves}",
        f"- Unmapped CVEs: {summary.unmapped_cves}",
        "- Mapping type distribution: " + _format_distribution(summary.mapping_type_distribution),
        "- Technique distribution: " + _format_distribution(summary.technique_distribution),
        "- Tactic distribution: " + _format_distribution(summary.tactic_distribution),
        "- ATT&CK mappings are imported from explicit local CTID or local CSV files only.",
    ]
    return lines


def _warning_lines(warnings: list[str]) -> list[str]:
    if warnings:
        return [f"- {warning}" for warning in warnings]
    return ["- None"]


def _format_distribution(distribution: dict[str, int]) -> str:
    if not distribution:
        return "None"
    return ", ".join(
        f"{key}: {value}"
        for key, value in sorted(distribution.items(), key=lambda item: (-item[1], item[0]))
    )


def _format_attack_indicator(mapped: bool, technique_count: int) -> str:
    if not mapped:
        return "Unmapped"
    return f"{technique_count} technique(s)"


def _format_priority_indicator(
    priority_label: str,
    suppressed_by_vex: bool,
    *,
    in_kev: bool,
    waived: bool = False,
) -> str:
    parts: list[str] = []
    if in_kev:
        parts.append("KEV")
    if suppressed_by_vex:
        parts.append("suppressed")
    if waived:
        parts.append("waived")
    if not parts:
        return priority_label
    return f"{priority_label} ({', '.join(parts)})"


def _priority_display_label(priority_label: str, in_kev: bool, waived: bool = False) -> str:
    parts = [priority_label]
    if in_kev:
        parts.append("KEV")
    if waived:
        parts.append("Waived")
    return " / ".join(parts)


def _format_exploit_status(in_kev: bool) -> str:
    if in_kev:
        return "Known exploited (KEV)"
    return "No KEV listing"


def _format_vex_statuses(vex_statuses: dict[str, int]) -> str:
    if not vex_statuses:
        return "N.A."
    return _format_distribution(vex_statuses)


def _format_waiver_status(finding: PrioritizedFinding) -> str:
    if not finding.waived:
        return "N.A."
    details = [
        f"owner={finding.waiver_owner or 'N.A.'}",
        f"expires={finding.waiver_expires_on or 'N.A.'}",
    ]
    if finding.waiver_scope:
        details.append(f"scope={finding.waiver_scope}")
    return ", ".join(details)


def _mapping_types(mappings: list[AttackMapping]) -> list[str]:
    values: list[str] = []
    for mapping in mappings:
        if mapping.mapping_type and mapping.mapping_type not in values:
            values.append(mapping.mapping_type)
    return values


def _capability_groups(mappings: list[AttackMapping]) -> list[str]:
    values: list[str] = []
    for mapping in mappings:
        if mapping.capability_group and mapping.capability_group not in values:
            values.append(mapping.capability_group)
    return values

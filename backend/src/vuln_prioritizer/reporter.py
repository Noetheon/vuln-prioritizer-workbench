"""Report generation facade and terminal rendering."""

from __future__ import annotations

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
)
from vuln_prioritizer.reporting_format import (
    _format_attack_indicator,
    _format_distribution,
    _format_exploit_status,
    _format_priority_indicator,
    _format_vex_statuses,
    _format_waiver_status,
    comma_or_na,
    format_change,
    format_data_quality_flags,
    format_score,
    normalize_whitespace,
    truncate_text,
)
from vuln_prioritizer.reporting_html import generate_html_report
from vuln_prioritizer.reporting_io import write_output
from vuln_prioritizer.reporting_markdown import (
    generate_compare_markdown,
    generate_explain_markdown,
    generate_markdown_report,
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
    generate_state_service_history_json,
    generate_state_top_services_json,
    generate_state_trends_json,
    generate_state_waivers_json,
    generate_summary_markdown,
)
from vuln_prioritizer.reporting_snapshot import (
    generate_rollup_markdown,
    generate_snapshot_diff_markdown,
    render_rollup_table,
    render_snapshot_diff_table,
)
from vuln_prioritizer.reporting_state import (
    render_state_history_table,
    render_state_import_panel,
    render_state_init_panel,
    render_state_service_history_table,
    render_state_top_services_table,
    render_state_trends_table,
    render_state_waivers_table,
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
    "generate_state_service_history_json",
    "generate_state_top_services_json",
    "generate_state_trends_json",
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
    "render_state_service_history_table",
    "render_state_top_services_table",
    "render_state_trends_table",
    "render_state_waivers_table",
    "render_summary_panel",
    "write_output",
]


def render_findings_table(findings: list[PrioritizedFinding]) -> Table:
    """Build the Rich table shown in the terminal."""
    table = Table(title="Vulnerability Prioritization", show_lines=False)
    table.add_column("CVE", style="bold")
    table.add_column("Priority")
    table.add_column("Op Rank")
    table.add_column("CVSS")
    table.add_column("EPSS")
    table.add_column("KEV")
    table.add_column("DQ")
    table.add_column("Confidence")
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
            str(finding.operational_rank or "N.A."),
            format_score(finding.cvss_base_score, digits=1),
            format_score(finding.epss, digits=3),
            "Yes" if finding.in_kev else "No",
            truncate_text(format_data_quality_flags(finding), 40),
            finding.data_quality_confidence,
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
    table.add_column("DQ")
    table.add_column("Confidence")
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
            truncate_text(format_data_quality_flags(row), 40),
            row.data_quality_confidence,
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
    if context.defensive_context_sources:
        lines.append(
            "Defensive context: "
            + ", ".join(source.upper() for source in context.defensive_context_sources)
            + f" ({context.defensive_context_hits}/{context.valid_input})"
        )
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
    if context.provider_snapshot_id:
        lines.append(f"Provider snapshot ID: {context.provider_snapshot_id}")
    if context.provider_snapshot_hash:
        lines.append(f"Provider snapshot hash: {context.provider_snapshot_hash}")
    if context.provider_snapshot_sources:
        lines.append("Provider snapshot sources: " + ", ".join(context.provider_snapshot_sources))
    snapshot_generated_at = context.provider_freshness.get("provider_snapshot_generated_at")
    if snapshot_generated_at:
        lines.append(f"Provider snapshot generated at: {snapshot_generated_at}")
    if context.nvd_diagnostics.requested:
        diagnostics = context.nvd_diagnostics
        lines.append(
            "NVD diagnostics: "
            + f"requested={diagnostics.requested}, "
            + f"cache_hits={diagnostics.cache_hits}, "
            + f"network_fetches={diagnostics.network_fetches}, "
            + f"failures={diagnostics.failures}, "
            + f"content_hits={diagnostics.content_hits}, "
            + f"empty_records={diagnostics.empty_records}, "
            + f"stale_cache_hits={diagnostics.stale_cache_hits}"
        )
    if context.provider_degraded:
        lines.append("Provider degraded: yes")
    if context.epss_diagnostics.requested:
        diagnostics = context.epss_diagnostics
        lines.append(
            "EPSS diagnostics: "
            + f"requested={diagnostics.requested}, "
            + f"cache_hits={diagnostics.cache_hits}, "
            + f"network_fetches={diagnostics.network_fetches}, "
            + f"failures={diagnostics.failures}, "
            + f"content_hits={diagnostics.content_hits}, "
            + f"empty_records={diagnostics.empty_records}, "
            + f"stale_cache_hits={diagnostics.stale_cache_hits}"
        )
    if context.kev_diagnostics.requested:
        diagnostics = context.kev_diagnostics
        lines.append(
            "KEV diagnostics: "
            + f"requested={diagnostics.requested}, "
            + f"cache_hits={diagnostics.cache_hits}, "
            + f"network_fetches={diagnostics.network_fetches}, "
            + f"failures={diagnostics.failures}, "
            + f"content_hits={diagnostics.content_hits}, "
            + f"empty_records={diagnostics.empty_records}, "
            + f"stale_cache_hits={diagnostics.stale_cache_hits}"
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
    signal_table.add_row("Data Quality Flags", format_data_quality_flags(finding))
    signal_table.add_row("Data Quality Confidence", finding.data_quality_confidence)
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
    data_quality_panel = Panel(
        "\n".join(
            f"- {flag.code} ({flag.severity}): {flag.message}"
            for flag in finding.data_quality_flags
        )
        if finding.data_quality_flags
        else "None",
        title="Data Quality",
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
        data_quality_panel,
        action_panel,
        context_panel,
        applicability_table,
        remediation_table,
        references_panel,
    )

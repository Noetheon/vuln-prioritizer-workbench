"""Rich table renderers for terminal reports."""

from __future__ import annotations

from rich.table import Table

from vuln_prioritizer.models import (
    ComparisonFinding,
    EvidenceBundleVerificationItem,
    EvidenceBundleVerificationSummary,
    PrioritizedFinding,
)
from vuln_prioritizer.reporting_format import (
    _format_attack_indicator,
    _format_priority_indicator,
    format_data_quality_flags,
    format_score,
    truncate_text,
)


def render_findings_table(findings: list[PrioritizedFinding]) -> Table:
    """Build the Rich table shown in the terminal."""
    table = Table(title="Vulnerability Prioritization", show_lines=False)
    table.add_column("CVE", style="bold")
    table.add_column("Priority")
    table.add_column("Op Rank")
    table.add_column("Op Score")
    table.add_column("CVSS")
    table.add_column("EPSS")
    table.add_column("KEV")
    table.add_column("DQ")
    table.add_column("Confidence")
    table.add_column("ATT&CK")
    table.add_column("Attack Relevance")
    table.add_column("Source")
    table.add_column("Description", overflow="fold")
    table.add_column("SLA")
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
            str(finding.operational_score),
            format_score(finding.cvss_base_score, digits=1),
            format_score(finding.epss, digits=3),
            "Yes" if finding.in_kev else "No",
            truncate_text(format_data_quality_flags(finding), 40),
            finding.data_quality_confidence,
            _format_attack_indicator(finding.attack_mapped, len(finding.attack_technique_details)),
            finding.attack_relevance,
            ", ".join(finding.provenance.source_formats) or "N.A.",
            truncate_text(finding.description or "N.A.", 90),
            _finding_sla_label(finding),
            truncate_text(finding.recommended_action, 120),
        )

    return table


def _finding_sla_label(finding: PrioritizedFinding) -> str:
    if finding.decision_guidance is None:
        return "N.A."
    return finding.decision_guidance.sla.label


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


__all__ = [
    "_finding_sla_label",
    "render_compare_table",
    "render_evidence_bundle_verification_table",
    "render_findings_table",
]

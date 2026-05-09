"""Rich explain-view renderer for terminal reports."""

from __future__ import annotations

from rich.console import Group
from rich.panel import Panel
from rich.table import Table

from vuln_prioritizer.models import (
    AttackData,
    ComparisonFinding,
    EpssData,
    KevData,
    NvdData,
    PrioritizedFinding,
)
from vuln_prioritizer.reporting_format import (
    _format_exploit_status,
    _format_vex_statuses,
    _format_waiver_status,
    comma_or_na,
    format_change,
    format_data_quality_flags,
    format_score,
    normalize_whitespace,
)


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
    signal_table.add_row("Priority State", finding.priority_state or finding.priority_label)
    signal_table.add_row("Operational Score", str(finding.operational_score))
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
    if finding.decision_guidance:
        decision_guidance_text = "\n".join(
            [
                f"Template: {finding.decision_guidance.template_label}",
                (
                    f"SLA: {finding.decision_guidance.sla.label} - "
                    f"{finding.decision_guidance.sla.guidance}"
                ),
                "Decision: " + normalize_whitespace(finding.decision_guidance.decision_statement),
                "Business impact: "
                + normalize_whitespace(finding.decision_guidance.business_impact.text),
                "Visibility: " + normalize_whitespace(finding.decision_guidance.visibility),
            ]
        )
    else:
        decision_guidance_text = "N.A."
    decision_panel = Panel(decision_guidance_text, title="Decision Guidance")
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
        decision_panel,
        action_panel,
        context_panel,
        applicability_table,
        remediation_table,
        references_panel,
    )


__all__ = ["render_explain_view"]

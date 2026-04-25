"""Markdown report renderers."""

from __future__ import annotations

from vuln_prioritizer.models import (
    AnalysisContext,
    AttackData,
    ComparisonFinding,
    EpssData,
    KevData,
    NvdData,
    PrioritizedFinding,
)
from vuln_prioritizer.reporting_format import (
    _attack_methodology_lines,
    _attack_summary_lines,
    _capability_groups,
    _format_attack_indicator,
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
)


def generate_markdown_report(
    findings: list[PrioritizedFinding],
    context: AnalysisContext,
) -> str:
    """Render the Markdown report."""
    findings_header = (
        "| CVE ID | Description | CVSS | Severity | CVSS Version | EPSS | EPSS Percentile | "
        + "KEV | ATT&CK | Attack Relevance | Sources | Asset Criticality | VEX | Waiver | "
        + "Priority | Operational Rank | Context Rank Reasons | Rationale | Recommended Action | "
        + "Context Recommendation |"
    )
    findings_divider = (
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | "
        + "--- | --- | --- | --- | --- | --- | --- |"
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
                    str(finding.operational_rank or "N.A."),
                    escape_pipes(", ".join(finding.context_rank_reasons) or "N.A."),
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

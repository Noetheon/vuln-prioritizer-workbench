"""Explain Markdown report renderer."""
# ruff: noqa: F401,F403,F405,I001,E501

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
    format_data_quality_flags,
    format_score,
    normalize_whitespace,
)
from vuln_prioritizer.services.baseline_comparison import (
    build_cvss_baseline_comparison_payload,
)
from vuln_prioritizer.reporting_markdown_analysis import (
    _business_impact,
    _decision_sla,
    _decision_statement,
    _decision_template,
    _decision_visibility,
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
            f"- Data Quality Flags: `{format_data_quality_flags(finding)}`",
            f"- Data Quality Confidence: `{finding.data_quality_confidence}`",
            f"- Published: `{nvd.published or 'N.A.'}`",
            f"- Last Modified: `{nvd.last_modified or 'N.A.'}`",
            f"- CWEs: {comma_or_na(nvd.cwes)}",
            f"- ATT&CK Source: `{attack.source}`",
            f"- ATT&CK Relevance: `{attack.attack_relevance}`",
            f"- ATT&CK Techniques: {comma_or_na(attack.attack_techniques)}",
            f"- ATT&CK Tactics: {comma_or_na(attack.attack_tactics)}",
            f"- ATT&CK Note: {attack.attack_note or 'N.A.'}",
            "- Defensive Context Sources: "
            + comma_or_na(
                sorted({context.source.upper() for context in finding.defensive_contexts})
            ),
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
            "## Why This Priority",
        ]
    )
    if finding.explanation:
        lines.extend(
            [
                normalize_whitespace(finding.explanation.human_readable),
                "",
                "| Code | Source | Signal | Value | Threshold | Reason |",
                "| --- | --- | --- | --- | --- | --- |",
            ]
        )
        for reason in finding.explanation.reasons:
            lines.append(
                "| "
                + " | ".join(
                    [
                        escape_pipes(reason.code),
                        escape_pipes(reason.source),
                        escape_pipes(reason.signal),
                        escape_pipes(reason.value or "N.A."),
                        escape_pipes(reason.threshold or "N.A."),
                        escape_pipes(reason.message),
                    ]
                )
                + " |"
            )
        if finding.explanation.notes:
            lines.extend(["", "### Notes"])
            for note in finding.explanation.notes:
                lines.append(
                    f"- `{note.code}` ({note.source}, {note.severity}): "
                    + normalize_whitespace(note.message)
                )
    else:
        lines.append("No structured priority explanation was generated.")
    lines.extend(
        [
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

    lines.extend(["", "## Defensive Context", ""])
    if finding.defensive_contexts:
        lines.extend(
            [
                "| Source | ID | Severity | SSVC Decision | Summary |",
                "| --- | --- | --- | --- | --- |",
            ]
        )
        for context_item in finding.defensive_contexts:
            lines.append(
                "| "
                + " | ".join(
                    [
                        escape_pipes(context_item.source.upper()),
                        escape_pipes(context_item.source_id or "N.A."),
                        escape_pipes(context_item.severity or "N.A."),
                        escape_pipes(context_item.ssvc_decision or "N.A."),
                        escape_pipes(
                            normalize_whitespace(
                                context_item.summary or context_item.title or "N.A."
                            )
                        ),
                    ]
                )
                + " |"
            )
    else:
        lines.append("No OSV, GHSA, Vulnrichment or SSVC context was included.")

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
            "## Decision Guidance",
            f"- Template: `{_decision_template(finding)}`",
            f"- SLA: `{_decision_sla(finding)}`",
            f"- Visibility: {normalize_whitespace(_decision_visibility(finding))}",
            f"- Business Impact: {normalize_whitespace(_business_impact(finding))}",
            "",
            normalize_whitespace(_decision_statement(finding)),
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


__all__ = [
    "generate_explain_markdown",
]

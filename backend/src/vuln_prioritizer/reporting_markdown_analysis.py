"""Analysis Markdown report renderer."""
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


def generate_markdown_report(
    findings: list[PrioritizedFinding],
    context: AnalysisContext,
) -> str:
    """Render the Markdown report."""
    findings_columns = [
        "CVE ID",
        "Description",
        "CVSS",
        "Severity",
        "CVSS Version",
        "EPSS",
        "EPSS Percentile",
        "KEV",
        "ATT&CK",
        "Attack Relevance",
        "Sources",
        "Asset Criticality",
        "VEX",
        "Waiver",
        "Priority",
        "Priority State",
        "Operational Score",
        "Data Quality",
        "Confidence",
        "Operational Rank",
        "Context Rank Reasons",
        "Rationale",
        "Decision Template",
        "SLA",
        "Decision Statement",
        "Business Impact",
        "Recommended Action",
        "Context Recommendation",
    ]
    findings_header = "| " + " | ".join(findings_columns) + " |"
    findings_divider = "| " + " | ".join("---" for _ in findings_columns) + " |"
    attack_header = (
        "| CVE ID | Mapping Types | Techniques | Tactics | Capability Groups | ATT&CK Note |"
    )
    defensive_context_header = "| CVE ID | Sources | IDs | Severity | SSVC Decision | Summary |"
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
    lines.extend(_baseline_comparison_section(findings))
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
                    finding.priority_state or finding.priority_label,
                    str(finding.operational_score),
                    escape_pipes(format_data_quality_flags(finding)),
                    escape_pipes(finding.data_quality_confidence),
                    str(finding.operational_rank or "N.A."),
                    escape_pipes(", ".join(finding.context_rank_reasons) or "N.A."),
                    escape_pipes(finding.rationale),
                    escape_pipes(_decision_template(finding)),
                    escape_pipes(_decision_sla(finding)),
                    escape_pipes(_decision_statement(finding)),
                    escape_pipes(_business_impact(finding)),
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

    lines.extend(["", "## Defensive Context", ""])
    if any(finding.defensive_contexts for finding in findings):
        lines.extend(
            [
                defensive_context_header,
                "| --- | --- | --- | --- | --- | --- |",
            ]
        )
        for finding in findings:
            if not finding.defensive_contexts:
                continue
            lines.append(
                "| "
                + " | ".join(
                    [
                        finding.cve_id,
                        escape_pipes(
                            ", ".join(
                                sorted(
                                    {
                                        context.source.upper()
                                        for context in finding.defensive_contexts
                                    }
                                )
                            )
                            or "N.A."
                        ),
                        escape_pipes(
                            ", ".join(
                                context.source_id or "N.A."
                                for context in finding.defensive_contexts[:5]
                            )
                        ),
                        escape_pipes(
                            ", ".join(
                                context.severity or "N.A."
                                for context in finding.defensive_contexts[:5]
                            )
                        ),
                        escape_pipes(
                            ", ".join(
                                context.ssvc_decision or "N.A."
                                for context in finding.defensive_contexts[:5]
                            )
                        ),
                        escape_pipes(
                            normalize_whitespace(
                                finding.defensive_contexts[0].summary
                                or finding.defensive_contexts[0].title
                                or "N.A."
                            )
                        ),
                    ]
                )
                + " |"
            )
    else:
        lines.append("No OSV, GHSA, Vulnrichment or SSVC context was included.")

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


def _decision_template(finding: PrioritizedFinding) -> str:
    if finding.decision_guidance is None:
        return "N.A."
    return finding.decision_guidance.template_label


def _decision_sla(finding: PrioritizedFinding) -> str:
    if finding.decision_guidance is None:
        return "N.A."
    sla = finding.decision_guidance.sla
    target = ""
    if sla.target_hours is not None and sla.target_hours <= 48:
        target = f" ({sla.target_hours}h)"
    elif sla.target_days is not None:
        target = f" ({sla.target_days}d)"
    return f"{sla.label}{target}"


def _decision_statement(finding: PrioritizedFinding) -> str:
    if finding.decision_guidance is None:
        return "N.A."
    return finding.decision_guidance.decision_statement


def _business_impact(finding: PrioritizedFinding) -> str:
    if finding.decision_guidance is None:
        return "N.A."
    return finding.decision_guidance.business_impact.text


def _decision_visibility(finding: PrioritizedFinding) -> str:
    if finding.decision_guidance is None:
        return "N.A."
    return finding.decision_guidance.visibility


def _baseline_comparison_section(findings: list[PrioritizedFinding]) -> list[str]:
    comparison = build_cvss_baseline_comparison_payload(
        findings,
        top_change_limit=5,
        include_comparisons=False,
    )
    summary = comparison["summary"]
    methodology = comparison["methodology"]
    lines = [
        "",
        "## CVSS-only Baseline Comparison",
        f"- Changed rows: {summary['changed']}",
        f"- Up: {summary['up']}",
        f"- Down: {summary['down']}",
        f"- Unchanged: {summary['unchanged']}",
        "- Method limit: " + normalize_whitespace(str(methodology["limitations"])),
    ]
    top_changes = comparison["top_changes"]
    if top_changes:
        lines.extend(["", "### Top Baseline Changes"])
        for item in top_changes:
            lines.append(
                "- "
                + f"{item['cve_id']}: {item['old_priority']} "
                + f"(rank {item['old_rank']}) -> {item['new_priority']} "
                + f"(rank {item['new_rank']}); "
                + normalize_whitespace(str(item["reason"]))
            )
    return lines


__all__ = [
    "_baseline_comparison_section",
    "_business_impact",
    "_decision_sla",
    "_decision_statement",
    "_decision_template",
    "_decision_visibility",
    "generate_markdown_report",
]

"""Comparison Markdown report renderer."""
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


def generate_compare_markdown(
    comparisons: list[ComparisonFinding],
    context: AnalysisContext,
) -> str:
    """Render the Markdown comparison report."""
    comparison_header = (
        "| CVE ID | Description | CVSS-only | Enriched | VEX | ATT&CK | Attack Relevance | "
        + "Delta | Changed | CVSS | EPSS | KEV | Data Quality | Confidence | Waiver | Reason |"
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
            "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | "
            + "--- | --- | --- | --- |",
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
                    escape_pipes(format_data_quality_flags(row)),
                    escape_pipes(row.data_quality_confidence),
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


__all__ = [
    "generate_compare_markdown",
]

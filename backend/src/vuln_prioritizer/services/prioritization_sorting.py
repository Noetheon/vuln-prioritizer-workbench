"""Stable sort helpers for prioritized findings and comparison rows."""

from __future__ import annotations

from typing import Literal

from vuln_prioritizer.models import ComparisonFinding, PrioritizedFinding

SortField = Literal["priority", "epss", "cvss", "cve", "operational"]


def sort_prioritized_findings(
    findings: list[PrioritizedFinding],
    *,
    sort_by: SortField = "priority",
) -> list[PrioritizedFinding]:
    """Return prioritized findings in deterministic Workbench/report order."""
    return sorted(findings, key=lambda finding: _finding_sort_key(finding, sort_by))


def sort_comparison_findings(
    comparisons: list[ComparisonFinding],
    *,
    sort_by: SortField = "priority",
) -> list[ComparisonFinding]:
    """Return comparison rows in the matching prioritized order."""
    return sorted(comparisons, key=lambda row: _comparison_sort_key(row, sort_by))


def descending_numeric(value: float | None) -> tuple[int, float]:
    """Sort numeric values descending while keeping missing values last."""
    if value is None:
        return 1, 0.0
    return 0, -value


def _finding_sort_key(finding: PrioritizedFinding, sort_by: SortField) -> tuple:
    if sort_by == "operational":
        return (
            finding.operational_rank or 999999,
            finding.cve_id,
        )
    if sort_by == "epss":
        return (
            descending_numeric(finding.epss),
            finding.priority_rank,
            0 if finding.in_kev else 1,
            descending_numeric(finding.cvss_base_score),
            finding.cve_id,
        )
    if sort_by == "cvss":
        return (
            descending_numeric(finding.cvss_base_score),
            finding.priority_rank,
            0 if finding.in_kev else 1,
            descending_numeric(finding.epss),
            finding.cve_id,
        )
    if sort_by == "cve":
        return (finding.cve_id,)

    return (
        finding.priority_rank,
        0 if finding.in_kev else 1,
        descending_numeric(finding.epss),
        descending_numeric(finding.cvss_base_score),
        finding.cve_id,
    )


def _comparison_sort_key(row: ComparisonFinding, sort_by: SortField) -> tuple:
    if sort_by == "operational":
        return (
            row.operational_rank or 999999,
            row.cve_id,
        )
    if sort_by == "epss":
        return (
            descending_numeric(row.epss),
            row.enriched_rank,
            0 if row.in_kev else 1,
            descending_numeric(row.cvss_base_score),
            row.cve_id,
        )
    if sort_by == "cvss":
        return (
            descending_numeric(row.cvss_base_score),
            row.enriched_rank,
            0 if row.in_kev else 1,
            descending_numeric(row.epss),
            row.cve_id,
        )
    if sort_by == "cve":
        return (row.cve_id,)

    return (
        row.enriched_rank,
        0 if row.in_kev else 1,
        descending_numeric(row.epss),
        descending_numeric(row.cvss_base_score),
        row.cve_id,
    )

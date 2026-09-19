"""Render inventory-assessment limitations alongside vulnerability report counts."""

from __future__ import annotations

from app.contracts.sbom import SbomAssessmentV1
from app.services.report_formatting import safe_cell, safe_html
from app.services.report_models import MarkdownReportPayload

_LIMIT = (
    "Matching is limited to the uploaded inventory and recorded database. "
    "Zero findings do not prove complete coverage or that deployed software is safe."
)


def _assessment(payload: MarkdownReportPayload) -> SbomAssessmentV1 | None:
    raw = payload.summary.get("sbom_assessment")
    return SbomAssessmentV1.model_validate(raw) if isinstance(raw, dict) else None


def _rows(assessment: SbomAssessmentV1) -> list[tuple[str, object]]:
    return [
        ("Assessment status", assessment.status),
        ("Software subject", assessment.target_ref),
        ("Scanner", f"Grype {assessment.scanner_version}"),
        ("Database built", assessment.database_built_at),
        ("Database SHA256", assessment.database_sha256),
        ("Inventory observed", assessment.observed_at),
        ("Scanned", assessment.scanned_at),
        ("Inventory components", assessment.component_count),
        ("Components with PURL and version", assessment.identified_component_count),
        ("Scanner matches", assessment.scanner_match_count),
        ("Matches with CVE mapping", assessment.prioritized_match_count),
        ("Matches without CVE mapping", assessment.unassigned_match_count),
    ]


def markdown_sbom_assessment(payload: MarkdownReportPayload) -> list[str]:
    """Include provenance and limitations even when a run has no CVE findings."""
    assessment = _assessment(payload)
    if assessment is None:
        return []
    return [
        "",
        "## SBOM Assessment",
        "",
        _LIMIT,
        "",
        "| Field | Value |",
        "| --- | --- |",
        *[f"| {label} | {safe_cell(value)} |" for label, value in _rows(assessment)],
        "",
        *[f"- {safe_cell(warning)}" for warning in assessment.warnings],
    ]


def html_sbom_assessment(payload: MarkdownReportPayload) -> str:
    """Render an escaped assessment section in the executive report."""
    assessment = _assessment(payload)
    if assessment is None:
        return ""
    rows = "".join(
        f"<tr><th>{safe_html(label)}</th><td>{safe_html(value)}</td></tr>"
        for label, value in _rows(assessment)
    )
    warnings = "".join(f"<li>{safe_html(item)}</li>" for item in assessment.warnings)
    return (
        '<section aria-label="SBOM assessment"><h2>SBOM Assessment</h2>'
        f"<p>{_LIMIT}</p><table><tbody>{rows}</tbody></table><ul>{warnings}</ul></section>\n"
    )

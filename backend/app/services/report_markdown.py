"""Markdown Workbench report renderer."""

from __future__ import annotations

from app.services.report_formatting import format_number as _format_number
from app.services.report_formatting import iso_datetime as _iso_datetime
from app.services.report_formatting import metadata_bool as _metadata_bool
from app.services.report_formatting import metadata_list as _metadata_list
from app.services.report_formatting import safe_cell as _safe_cell
from app.services.report_markdown_sections import (
    _markdown_detection_coverage_section,
    _markdown_governance_section,
)
from app.services.report_models import MarkdownReportPayload
from app.services.report_renderer_common import (
    _counts_by_priority,
    _priority_label,
    _redacted_bundle_payload,
)


def render_markdown_report(payload: MarkdownReportPayload) -> str:
    """Render a deterministic technical Markdown report from stored analysis data."""
    payload, _redactions = _redacted_bundle_payload(payload)
    finding_count = len(payload.findings)
    counts = _counts_by_priority(payload.findings)
    lines = [
        "# Technical Vulnerability Report",
        "",
        "## Summary",
        "",
        "| Field | Value |",
        "| --- | --- |",
        f"| Project | {_safe_cell(payload.project_name)} |",
        f"| Project ID | {_safe_cell(payload.project_id)} |",
        f"| Analysis Run | {_safe_cell(payload.run_id)} |",
        f"| Run Status | {_safe_cell(payload.run_status)} |",
        f"| Input Type | {_safe_cell(payload.input_type)} |",
        f"| Input File | {_safe_cell(payload.filename)} |",
        f"| Generated At | {_safe_cell(_iso_datetime(payload.generated_at))} |",
        f"| Finding Count | {finding_count} |",
        f"| Critical | {counts['Critical']} |",
        f"| High | {counts['High']} |",
        f"| Medium | {counts['Medium']} |",
        f"| Low | {counts['Low']} |",
    ]
    if payload.project_context_source:
        lines.insert(
            9,
            "| Project Context | Current project projection at export time "
            "(not immutable run evidence) |",
        )
    if payload.governance_rollups:
        lines.extend(_markdown_governance_section(payload.governance_rollups, payload.findings))
    if payload.detection_coverage:
        lines.extend(_markdown_detection_coverage_section(payload.detection_coverage))
    lines.extend(
        [
            "",
            "## Top Findings",
            "",
        ]
    )
    if payload.findings:
        lines.extend(
            [
                (
                    "| Operational Rank | CVE | Priority | Score | EPSS | CVSS | KEV | Status | "
                    "Asset | Component | Action |"
                ),
                "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
            ]
        )
        for finding in payload.findings:
            lines.append(
                "| "
                + " | ".join(
                    [
                        str(finding.operational_rank),
                        _safe_cell(finding.cve_id),
                        _safe_cell(_priority_label(finding.priority)),
                        _safe_cell(_format_number(finding.risk_score)),
                        _safe_cell(_format_number(finding.epss)),
                        _safe_cell(_format_number(finding.cvss_base_score)),
                        "Yes" if finding.in_kev else "No",
                        _safe_cell(finding.status),
                        _safe_cell(finding.asset),
                        _safe_cell(finding.component),
                        _safe_cell(finding.recommended_action),
                    ]
                )
                + " |"
            )
    else:
        lines.append("No findings were recorded for this analysis run.")

    lines.extend(
        [
            "",
            "## Reasons",
            "",
        ]
    )
    if payload.findings:
        lines.extend(
            [
                "| CVE | Rationale | Recommended Action |",
                "| --- | --- | --- |",
            ]
        )
        for finding in payload.findings:
            lines.append(
                "| "
                + " | ".join(
                    [
                        _safe_cell(finding.cve_id),
                        _safe_cell(finding.rationale),
                        _safe_cell(finding.recommended_action),
                    ]
                )
                + " |"
            )
    else:
        lines.append("No rationale records are available for this analysis run.")

    lines.extend(
        [
            "",
            "## Data Quality",
            "",
        ]
    )
    if payload.findings:
        lines.extend(
            [
                "| CVE | Confidence | Flags |",
                "| --- | --- | --- |",
            ]
        )
        for finding in payload.findings:
            flags = "; ".join(finding.data_quality_flags) if finding.data_quality_flags else "None"
            lines.append(
                "| "
                + " | ".join(
                    [
                        _safe_cell(finding.cve_id),
                        _safe_cell(finding.data_quality_confidence or "unknown"),
                        _safe_cell(flags),
                    ]
                )
                + " |"
            )
    else:
        lines.append("No data quality records are available for this analysis run.")

    lines.extend(
        [
            "",
            "## Provider Snapshot",
            "",
        ]
    )
    snapshot = payload.provider_snapshot
    if snapshot is None:
        lines.append("No provider snapshot was linked to this analysis run.")
    else:
        locked_provider_data = _metadata_bool(snapshot.source_metadata, "locked_provider_data")
        selected_sources = _metadata_list(snapshot.source_metadata, "selected_sources")
        lines.extend(
            [
                "| Field | Value |",
                "| --- | --- |",
                f"| Snapshot ID | {_safe_cell(snapshot.id)} |",
                f"| Content Hash | {_safe_cell(snapshot.content_hash)} |",
                f"| NVD Last Sync | {_safe_cell(snapshot.nvd_last_sync)} |",
                f"| EPSS Date | {_safe_cell(snapshot.epss_date)} |",
                f"| KEV Catalog Version | {_safe_cell(snapshot.kev_catalog_version)} |",
                f"| Locked Provider Data | {_safe_cell(locked_provider_data)} |",
                f"| Selected Sources | {_safe_cell(selected_sources)} |",
            ]
        )
        for key, value in sorted(snapshot.source_hashes.items()):
            lines.append(f"| Source Hash: {_safe_cell(key)} | {_safe_cell(value)} |")
        for key in ("source_path", "item_count", "missing", "validation_error"):
            if key in snapshot.source_metadata:
                lines.append(
                    f"| Metadata: {_safe_cell(key)} | {_safe_cell(snapshot.source_metadata[key])} |"
                )

    return "\n".join(lines).rstrip() + "\n"


__all__ = [
    "_markdown_detection_coverage_section",
    "_markdown_governance_section",
    "render_markdown_report",
]

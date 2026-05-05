"""Report rendering and export helpers for the template Workbench."""

from __future__ import annotations

import csv
import hashlib
import html
import json
import re
import zipfile
from collections import Counter
from collections.abc import Sequence
from dataclasses import replace
from datetime import datetime
from io import BytesIO, StringIO
from pathlib import Path
from typing import Any

from app.models import Finding, FindingOccurrence, ProviderSnapshot
from app.services.report_contracts import (
    ANALYSIS_RESULT_SCHEMA,
    ANALYSIS_RESULT_SCHEMA_VERSION,
    CSV_FINDINGS_COLUMNS,
    DETERMINISTIC_ZIP_FILE_MODE,
    DETERMINISTIC_ZIP_TIMESTAMP,
    EVIDENCE_BUNDLE_MANIFEST_SCHEMA_VERSION,
    MARKDOWN_SPECIAL_CHARS,
    PRIORITY_LABELS,
    REPORT_FILENAME_ATTACK_NAVIGATOR,
    REPORT_FILENAME_GOVERNANCE_ASSET_CONTEXT,
    REPORT_FILENAME_GOVERNANCE_DETECTION_COVERAGE,
    REPORT_FILENAME_GOVERNANCE_ROLLUPS,
    REPORT_FILENAME_GOVERNANCE_VEX,
    REPORT_FILENAME_GOVERNANCE_WAIVERS,
    REPORT_KIND_ATTACK_NAVIGATOR,
    REPORT_KIND_EVIDENCE_BUNDLE,
    REPORT_KIND_GOVERNANCE_ASSET_CONTEXT,
    REPORT_KIND_GOVERNANCE_DETECTION_COVERAGE,
    REPORT_KIND_GOVERNANCE_ROLLUPS,
    REPORT_KIND_GOVERNANCE_VEX,
    REPORT_KIND_GOVERNANCE_WAIVERS,
)
from app.services.report_models import (
    MarkdownProviderSnapshot,
    MarkdownReportFinding,
    MarkdownReportPayload,
    ReportVerificationError,
)
from vuln_prioritizer.reporting_evidence import (
    verify_evidence_bundle as verify_evidence_bundle_archive,
)
from vuln_prioritizer.security_redaction import redact_value

EXECUTIVE_REPORT_CSS = """
:root {
  color-scheme: light;
  --bg: #f6f8fb;
  --surface: #ffffff;
  --text: #18202f;
  --muted: #5d6a7d;
  --border: #d8dee8;
  --accent: #1665d8;
  --accent-soft: #e8f1ff;
  --critical: #b42318;
  --high: #b54708;
  --medium: #8a6116;
  --low: #186a3b;
}
* {
  box-sizing: border-box;
}
body {
  margin: 0;
  background: var(--bg);
  color: var(--text);
  font-family:
    Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  font-size: 15px;
  line-height: 1.55;
}
.report-shell {
  width: min(1160px, calc(100% - 32px));
  margin: 0 auto;
  padding: 32px 0 48px;
}
header,
section {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 8px;
  margin-bottom: 18px;
  padding: 24px;
}
h1,
h2,
h3,
p {
  margin-top: 0;
}
h1 {
  margin-bottom: 10px;
  font-size: 32px;
  line-height: 1.15;
}
h2 {
  margin-bottom: 12px;
  font-size: 22px;
  line-height: 1.25;
}
.eyebrow {
  margin-bottom: 6px;
  color: var(--accent);
  font-size: 12px;
  font-weight: 700;
  letter-spacing: 0;
  text-transform: uppercase;
}
.lede {
  max-width: 840px;
  color: var(--muted);
}
.section-heading {
  margin-bottom: 14px;
}
.meta-grid,
.metric-grid,
.provider-grid {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 12px;
}
.meta-grid {
  margin: 18px 0 0;
}
.meta-grid div,
.metric,
.provider-grid div {
  min-width: 0;
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 12px;
  background: #fbfcfe;
}
dt,
.metric span {
  color: var(--muted);
  font-size: 12px;
  font-weight: 700;
  text-transform: uppercase;
}
dd {
  margin: 4px 0 0;
  overflow-wrap: anywhere;
}
.metric strong {
  display: block;
  margin-top: 4px;
  font-size: 26px;
  line-height: 1.1;
}
.table-wrap {
  overflow-x: auto;
}
table {
  width: 100%;
  min-width: 920px;
  border-collapse: collapse;
}
th,
td {
  border-bottom: 1px solid var(--border);
  padding: 10px 8px;
  text-align: left;
  vertical-align: top;
}
th {
  color: var(--muted);
  font-size: 12px;
  text-transform: uppercase;
}
td {
  overflow-wrap: anywhere;
}
.badge {
  display: inline-flex;
  border-radius: 999px;
  padding: 2px 8px;
  background: var(--accent-soft);
  color: var(--accent);
  font-size: 12px;
  font-weight: 700;
  white-space: nowrap;
}
tbody td:nth-child(-n + 7),
thead th:nth-child(-n + 7) {
  white-space: nowrap;
}
.badge-critical {
  background: #fee4e2;
  color: var(--critical);
}
.badge-high {
  background: #ffead5;
  color: var(--high);
}
.badge-medium {
  background: #fef3c7;
  color: var(--medium);
}
.badge-low {
  background: #dcfae6;
  color: var(--low);
}
.recommendation-list {
  margin: 0;
  padding-left: 24px;
}
.recommendation-list li + li {
  margin-top: 12px;
}
.recommendation-list strong {
  display: block;
}
.empty-state {
  color: var(--muted);
}
@media (max-width: 820px) {
  .report-shell {
    width: min(100% - 20px, 1160px);
    padding-top: 16px;
  }
  header,
  section {
    padding: 16px;
  }
  h1 {
    font-size: 26px;
  }
  .meta-grid,
  .metric-grid,
  .provider-grid {
    grid-template-columns: 1fr;
  }
}
@media print {
  body {
    background: #ffffff;
    color: #000000;
  }
  .report-shell {
    width: 100%;
    padding: 0;
  }
  header,
  section {
    border-color: #c8c8c8;
    break-inside: avoid;
    page-break-inside: avoid;
  }
  .table-wrap {
    overflow: visible;
  }
  table {
    min-width: 0;
  }
}
""".strip()


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


def _markdown_governance_section(
    governance_rollups: dict[str, Any],
    findings: list[MarkdownReportFinding],
) -> list[str]:
    services = _dict_list(governance_rollups.get("top_services_by_risk"))[:5]
    assets = _dict_list(governance_rollups.get("top_assets_by_risk"))[:5]
    owners = _dict_list(governance_rollups.get("owners"))[:5]
    environments = _dict_list(governance_rollups.get("environments"))[:5]
    waiver_debt = _dict_value(governance_rollups.get("waiver_debt"))
    waiver_items = _dict_list(waiver_debt.get("items"))[:5]
    vex_summary = _governance_vex_summary(findings)
    lines = [
        "",
        "## Governance Rollups",
        "",
        "| Field | Value |",
        "| --- | --- |",
        f"| Waivers | {_safe_cell(waiver_debt.get('waiver_count', 0))} |",
        f"| Active Waivers | {_safe_cell(waiver_debt.get('active_count', 0))} |",
        f"| Expired Waivers | {_safe_cell(waiver_debt.get('expired_count', 0))} |",
        f"| Review Due Waivers | {_safe_cell(waiver_debt.get('review_due_count', 0))} |",
        f"| Expiring Soon Waivers | {_safe_cell(waiver_debt.get('expiring_soon_count', 0))} |",
        f"| Accepted Findings | {_safe_cell(waiver_debt.get('accepted_finding_count', 0))} |",
        f"| VEX Suppressed Findings | {_safe_cell(vex_summary['suppressed_by_vex_count'])} |",
        f"| VEX Under Investigation | {_safe_cell(vex_summary['under_investigation_count'])} |",
        "",
        "### Top Services by Risk",
        "",
    ]
    if not services:
        lines.append("No service rollups are available for this analysis run.")
    else:
        lines.extend(
            [
                "| Service | Findings | Critical | High | Risk Score | Waiver Debt |",
                "| --- | --- | --- | --- | --- | --- |",
            ]
        )
        for service in services:
            waiver_debt_count = int(service.get("expired_waiver_count") or 0) + int(
                service.get("review_due_waiver_count") or 0
            )
            lines.append(
                "| "
                + " | ".join(
                    [
                        _safe_cell(service.get("label")),
                        _safe_cell(service.get("finding_count", 0)),
                        _safe_cell(service.get("critical_count", 0)),
                        _safe_cell(service.get("high_count", 0)),
                        _safe_cell(_format_number(service.get("risk_score_total"))),
                        _safe_cell(waiver_debt_count),
                    ]
                )
                + " |"
            )
    lines.extend(
        [
            "",
            "### Top Assets by Risk",
            "",
        ]
    )
    if not assets:
        lines.append("No asset rollups are available for this analysis run.")
    else:
        lines.extend(
            [
                "| Asset | Findings | Critical | High | Risk Score | Accepted | VEX Suppressed |",
                "| --- | --- | --- | --- | --- | --- | --- |",
            ]
        )
        for asset in assets:
            lines.append(
                "| "
                + " | ".join(
                    [
                        _safe_cell(asset.get("label")),
                        _safe_cell(asset.get("finding_count", 0)),
                        _safe_cell(asset.get("critical_count", 0)),
                        _safe_cell(asset.get("high_count", 0)),
                        _safe_cell(_format_number(asset.get("risk_score_total"))),
                        _safe_cell(asset.get("accepted_count", 0)),
                        _safe_cell(asset.get("suppressed_by_vex_count", 0)),
                    ]
                )
                + " |"
            )
    lines.extend(
        [
            "",
            "### Accepted Risk and Expiring Waivers",
            "",
        ]
    )
    if waiver_items:
        lines.extend(
            [
                "| Scope | Owner | Status | Expires | Review | Matched Findings |",
                "| --- | --- | --- | --- | --- | --- |",
            ]
        )
        for item in waiver_items:
            lines.append(
                "| "
                + " | ".join(
                    [
                        _safe_cell(item.get("scope")),
                        _safe_cell(item.get("owner")),
                        _safe_cell(item.get("status")),
                        _safe_cell(item.get("expires_at")),
                        _safe_cell(item.get("review_at")),
                        _safe_cell(item.get("matched_findings", 0)),
                    ]
                )
                + " |"
            )
    else:
        lines.append("No accepted-risk waiver debt is currently recorded for this run.")

    lines.extend(
        [
            "",
            "### Owner and Environment Rollups",
            "",
            "| Dimension | Label | Findings | Critical | High | Accepted | Waiver Debt |",
            "| --- | --- | --- | --- | --- | --- | --- |",
        ]
    )
    for dimension, rows in (("Owner", owners), ("Environment", environments)):
        for row in rows:
            waiver_debt_count = int(row.get("expired_waiver_count") or 0) + int(
                row.get("review_due_waiver_count") or 0
            )
            lines.append(
                "| "
                + " | ".join(
                    [
                        _safe_cell(dimension),
                        _safe_cell(row.get("label")),
                        _safe_cell(row.get("finding_count", 0)),
                        _safe_cell(row.get("critical_count", 0)),
                        _safe_cell(row.get("high_count", 0)),
                        _safe_cell(row.get("accepted_count", 0)),
                        _safe_cell(waiver_debt_count),
                    ]
                )
                + " |"
            )
    if not owners and not environments:
        lines.append("| Owner | Unassigned | 0 | 0 | 0 | 0 | 0 |")

    lines.extend(
        [
            "",
            "### VEX Summary",
            "",
            "| Field | Value |",
            "| --- | --- |",
            f"| Suppressed by VEX | {_safe_cell(vex_summary['suppressed_by_vex_count'])} |",
            f"| Under Investigation | {_safe_cell(vex_summary['under_investigation_count'])} |",
            f"| Fixed | {_safe_cell(vex_summary['fixed_count'])} |",
        ]
    )
    return lines


def _markdown_detection_coverage_section(detection_coverage: dict[str, Any]) -> list[str]:
    summary = _dict_value(detection_coverage.get("summary"))
    weak_items = [
        item
        for item in _dict_list(detection_coverage.get("items"))
        if str(item.get("coverage_level")) in {"partial", "not_covered", "unknown"}
    ][:5]
    lines = [
        "",
        "## Detection Coverage",
        "",
        "| Field | Value |",
        "| --- | --- |",
        f"| Covered | {_safe_cell(summary.get('covered', 0))} |",
        f"| Partial | {_safe_cell(summary.get('partial', 0))} |",
        f"| Not Covered | {_safe_cell(summary.get('not_covered', 0))} |",
        f"| Unknown | {_safe_cell(summary.get('unknown', 0))} |",
        "",
        (
            "Detection coverage is operator-supplied defensive review evidence; "
            "it is not proof of security or exploitation."
        ),
    ]
    if weak_items:
        lines.extend(
            [
                "",
                "### Coverage Gaps",
                "",
                "| Technique | Coverage | Findings | Owner | Action |",
                "| --- | --- | --- | --- | --- |",
            ]
        )
        for item in weak_items:
            lines.append(
                "| "
                + " | ".join(
                    [
                        _safe_cell(item.get("technique_id")),
                        _safe_cell(item.get("coverage_level")),
                        _safe_cell(item.get("finding_count", 0)),
                        _safe_cell(item.get("owner") or "Unassigned"),
                        _safe_cell(item.get("recommended_action")),
                    ]
                )
                + " |"
            )
    return lines


def render_analysis_result_json(payload: MarkdownReportPayload) -> str:
    """Render the stable machine-readable analysis-result.v1 JSON export."""
    payload, _redactions = _redacted_bundle_payload(payload)
    result = {
        "schema": ANALYSIS_RESULT_SCHEMA,
        "schema_version": ANALYSIS_RESULT_SCHEMA_VERSION,
        "generated_at": _iso_datetime(payload.generated_at),
        "project": {
            "id": payload.project_id,
            "name": payload.project_name,
            "description": payload.project_description,
            "owner_id": payload.project_owner_id,
            "created_at": _iso_datetime(payload.project_created_at)
            if payload.project_created_at
            else None,
            "updated_at": _iso_datetime(payload.project_updated_at)
            if payload.project_updated_at
            else None,
        },
        "analysis_run": {
            "id": payload.run_id,
            "project_id": payload.project_id,
            "status": payload.run_status,
            "input_type": payload.input_type,
            "filename": payload.filename,
            "started_at": _iso_datetime(payload.run_started_at) if payload.run_started_at else None,
            "finished_at": _iso_datetime(payload.run_finished_at)
            if payload.run_finished_at
            else None,
            "error_message": payload.run_error,
            "errors": payload.run_errors,
            "summary": payload.summary,
        },
        "provider_snapshot": _analysis_provider_snapshot(payload.provider_snapshot),
        "findings": [_analysis_finding(finding) for finding in payload.findings],
        "explanations": {
            finding.cve_id: finding.explanation
            for finding in payload.findings
            if finding.explanation
        },
    }
    if payload.governance_rollups:
        result["governance_rollups"] = payload.governance_rollups
    if payload.detection_coverage:
        result["detection_coverage"] = payload.detection_coverage
    return json.dumps(result, indent=2, sort_keys=True) + "\n"


def render_findings_csv(payload: MarkdownReportPayload) -> str:
    """Render a spreadsheet-safe findings CSV export."""
    payload, _redactions = _redacted_bundle_payload(payload)
    output = StringIO()
    writer = csv.DictWriter(output, fieldnames=CSV_FINDINGS_COLUMNS, lineterminator="\n")
    writer.writeheader()
    for finding in payload.findings:
        writer.writerow(
            {
                "cve_id": _csv_safe_cell(finding.cve_id),
                "priority": _csv_safe_cell(_priority_label(finding.priority)),
                "status": _csv_safe_cell(finding.status),
                "kev": "yes" if finding.in_kev else "no",
                "epss": _csv_safe_cell(_format_number(finding.epss)),
                "cvss": _csv_safe_cell(_format_number(finding.cvss_base_score)),
                "data_quality_confidence": _csv_safe_cell(
                    finding.data_quality_confidence or "unknown"
                ),
                "data_quality_flags": _csv_safe_cell(";".join(finding.data_quality_flags)),
                "component": _csv_safe_cell(finding.component),
                "asset": _csv_safe_cell(finding.asset_key or finding.asset),
                "owner": _csv_safe_cell(finding.owner),
                "service": _csv_safe_cell(finding.business_service),
                "vex_statuses": _csv_safe_cell(_vex_statuses_label(finding)),
                "suppressed_by_vex": "yes"
                if _boolish_signal(finding, "suppressed_by_vex")
                else "no",
                "under_investigation": (
                    "yes" if _boolish_signal(finding, "under_investigation") else "no"
                ),
                "waived": "yes" if _boolish_signal(finding, "waived") else "no",
                "waiver_status": _csv_safe_cell(finding.explanation.get("waiver_status")),
                "waiver_owner": _csv_safe_cell(finding.explanation.get("waiver_owner")),
                "waiver_expires_on": _csv_safe_cell(finding.explanation.get("waiver_expires_on")),
                "waiver_review_on": _csv_safe_cell(finding.explanation.get("waiver_review_on")),
                "attack_mapped": "yes" if _boolish_signal(finding, "attack_mapped") else "no",
                "attack_techniques": _csv_safe_cell(
                    ";".join(
                        str(item) for item in _list_value(finding.explanation, "attack_techniques")
                    )
                ),
                "defensive_context_sources": _csv_safe_cell(
                    ";".join(
                        sorted(
                            {
                                str(item.get("source")).upper()
                                for item in _list_value(finding.explanation, "defensive_contexts")
                                if isinstance(item, dict) and item.get("source")
                            }
                        )
                    )
                ),
                "decision_template": _csv_safe_cell(
                    _decision_guidance_from_payload(finding).get("template_label")
                    or _decision_guidance_from_payload(finding).get("template")
                ),
                "decision_sla": _csv_safe_cell(finding.decision_sla),
                "decision_statement": _csv_safe_cell(finding.decision_statement),
                "business_impact": _csv_safe_cell(finding.business_impact),
                "recommended_action": _csv_safe_cell(finding.recommended_action),
            }
        )
    return output.getvalue()


def render_evidence_bundle_zip(
    payload: MarkdownReportPayload,
    *,
    attack_navigator_layer: dict[str, Any] | None = None,
) -> tuple[bytes, dict[str, Any]]:
    """Render a deterministic evidence ZIP and return its manifest payload."""
    bundle_payload, payload_redactions = _redacted_bundle_payload(payload)
    analysis_payload = json.loads(render_analysis_result_json(bundle_payload))
    redacted_analysis, analysis_redactions = _redact_bundle_value(analysis_payload)
    provider_payload = _analysis_provider_snapshot(bundle_payload.provider_snapshot) or {
        "available": False
    }
    redacted_provider, provider_redactions = _redact_bundle_value(provider_payload)

    entries = [
        (
            "analysis.json",
            _json_bytes(redacted_analysis),
            "analysis-json",
        ),
        (
            "technical.md",
            render_markdown_report(bundle_payload).encode("utf-8"),
            "technical-markdown",
        ),
        (
            "executive.html",
            render_html_executive_report(bundle_payload).encode("utf-8"),
            "executive-html",
        ),
        (
            "provider-snapshot.json",
            _json_bytes(redacted_provider),
            "provider-snapshot",
        ),
    ]
    governance_entries = _governance_bundle_entries(bundle_payload)
    entries.extend(governance_entries)
    if attack_navigator_layer is not None:
        redacted_layer, layer_redactions = _redact_bundle_value(
            attack_navigator_layer,
            path_prefix="attack_navigator_layer",
        )
        provider_redactions.extend(layer_redactions)
        entries.append(
            (
                REPORT_FILENAME_ATTACK_NAVIGATOR,
                _json_bytes(redacted_layer),
                REPORT_KIND_ATTACK_NAVIGATOR,
            )
        )
    file_entries = [
        _bundle_file_entry(path=path, content=content, kind=kind) for path, content, kind in entries
    ]
    artifact_hashes = {entry["path"]: entry["sha256"] for entry in file_entries}
    input_hashes = _bundle_input_hashes(payload)
    source_input_paths = [item["path"] for item in input_hashes]
    manifest: dict[str, Any] = {
        "schema_version": EVIDENCE_BUNDLE_MANIFEST_SCHEMA_VERSION,
        "bundle_kind": REPORT_KIND_EVIDENCE_BUNDLE,
        "generated_at": _iso_datetime(payload.generated_at),
        "source_analysis_path": "analysis.json",
        "source_analysis_sha256": artifact_hashes["analysis.json"],
        "source_input_path": source_input_paths[0] if source_input_paths else None,
        "source_input_paths": source_input_paths,
        "source_input_hashes": input_hashes,
        "provider_snapshot": {
            "bundle_path": "provider-snapshot.json",
            "sha256": artifact_hashes["provider-snapshot.json"],
            "content_hash": bundle_payload.provider_snapshot.content_hash
            if bundle_payload.provider_snapshot is not None
            else None,
            "id": bundle_payload.provider_snapshot.id
            if bundle_payload.provider_snapshot is not None
            else None,
        },
        "artifact_hashes": artifact_hashes,
        "findings_count": len(bundle_payload.findings),
        "kev_hits": sum(1 for finding in bundle_payload.findings if finding.in_kev),
        "waived_count": sum(
            1 for finding in bundle_payload.findings if _boolish_signal(finding, "waived")
        ),
        "attack_mapped_cves": sum(
            1 for finding in bundle_payload.findings if _boolish_signal(finding, "attack_mapped")
        ),
        "included_input_copy": False,
        "redaction": {
            "enabled": True,
            "policy": "sensitive keys and local path fields are replaced with [REDACTED]",
            "redacted_keys": sorted(
                set(payload_redactions + analysis_redactions + provider_redactions)
            ),
        },
        "files": file_entries,
    }
    if governance_entries:
        manifest["governance_artifacts"] = [
            {
                "bundle_path": path,
                "kind": kind,
                "sha256": artifact_hashes[path],
            }
            for path, _content, kind in governance_entries
        ]
    if REPORT_FILENAME_ATTACK_NAVIGATOR in artifact_hashes:
        manifest["attack_navigator_layer"] = {
            "bundle_path": REPORT_FILENAME_ATTACK_NAVIGATOR,
            "sha256": artifact_hashes[REPORT_FILENAME_ATTACK_NAVIGATOR],
        }

    output = BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path, content, _kind in entries:
            _write_deterministic_zip_member(archive, path, content)
        _write_deterministic_zip_member(archive, "manifest.json", _json_bytes(manifest))
    return output.getvalue(), manifest


def verify_evidence_bundle_zip(
    bundle_path: Path,
    *,
    display_path: str | None = None,
) -> dict[str, Any]:
    """Verify an evidence bundle ZIP and return the published report contract."""
    try:
        metadata, summary, items = verify_evidence_bundle_archive(bundle_path)
    except ValueError as exc:
        raise ReportVerificationError(str(exc)) from exc

    metadata_payload = metadata.model_dump(mode="json")
    if display_path is not None:
        metadata_payload["bundle_path"] = display_path
    return {
        "metadata": metadata_payload,
        "summary": summary.model_dump(mode="json"),
        "items": [item.model_dump(mode="json") for item in items],
    }


def _json_bytes(payload: Any) -> bytes:
    return (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _bundle_file_entry(*, path: str, content: bytes, kind: str) -> dict[str, Any]:
    return {
        "path": path,
        "kind": kind,
        "size_bytes": len(content),
        "sha256": hashlib.sha256(content).hexdigest(),
    }


def _bundle_input_hashes(payload: MarkdownReportPayload) -> list[dict[str, Any]]:
    upload = _dict_value(payload.summary.get("input_upload"))
    input_sha256 = upload.get("sha256") or payload.summary.get("input_sha256")
    if not isinstance(input_sha256, str) or not re.fullmatch(r"[a-f0-9]{64}", input_sha256):
        return []
    filename = (
        upload.get("stored_filename")
        or upload.get("original_filename")
        or payload.filename
        or "uploaded-input"
    )
    size_bytes = upload.get("size_bytes")
    return [
        {
            "path": _safe_bundle_filename(filename),
            "size_bytes": int(size_bytes) if isinstance(size_bytes, int | float) else 0,
            "sha256": input_sha256,
        }
    ]


def _safe_bundle_filename(value: object) -> str:
    filename = Path(str(value)).name.strip() if value is not None else ""
    return filename or "uploaded-input"


def _governance_bundle_entries(
    payload: MarkdownReportPayload,
) -> list[tuple[str, bytes, str]]:
    if not payload.governance_rollups and not payload.detection_coverage:
        return []
    artifacts = []
    if payload.governance_rollups:
        artifacts.extend(
            [
                (
                    REPORT_FILENAME_GOVERNANCE_ROLLUPS,
                    _governance_rollups_export(payload),
                    REPORT_KIND_GOVERNANCE_ROLLUPS,
                ),
                (
                    REPORT_FILENAME_GOVERNANCE_WAIVERS,
                    _governance_waivers_export(payload),
                    REPORT_KIND_GOVERNANCE_WAIVERS,
                ),
                (
                    REPORT_FILENAME_GOVERNANCE_VEX,
                    _governance_vex_export(payload),
                    REPORT_KIND_GOVERNANCE_VEX,
                ),
                (
                    REPORT_FILENAME_GOVERNANCE_ASSET_CONTEXT,
                    _governance_asset_context_export(payload),
                    REPORT_KIND_GOVERNANCE_ASSET_CONTEXT,
                ),
            ]
        )
    detection_coverage = _governance_detection_coverage_export(payload)
    if detection_coverage is not None:
        artifacts.append(
            (
                REPORT_FILENAME_GOVERNANCE_DETECTION_COVERAGE,
                detection_coverage,
                REPORT_KIND_GOVERNANCE_DETECTION_COVERAGE,
            )
        )
    return [(path, _json_bytes(content), kind) for path, content, kind in artifacts]


def _governance_rollups_export(payload: MarkdownReportPayload) -> dict[str, Any]:
    return {
        "schema": "governance-rollups.v1",
        "schema_version": "1.0.0",
        "generated_at": _iso_datetime(payload.generated_at),
        "project_id": payload.project_id,
        "run_id": payload.run_id,
        "rollups": payload.governance_rollups,
    }


def _governance_waivers_export(payload: MarkdownReportPayload) -> dict[str, Any]:
    waiver_debt = _dict_value(payload.governance_rollups.get("waiver_debt"))
    accepted_findings = [
        _governance_finding_row(finding)
        for finding in payload.findings
        if _boolish_signal(finding, "waived") or finding.status.lower().endswith("accepted")
    ]
    return {
        "schema": "governance-waivers.v1",
        "schema_version": "1.0.0",
        "generated_at": _iso_datetime(payload.generated_at),
        "project_id": payload.project_id,
        "run_id": payload.run_id,
        "waiver_debt": waiver_debt,
        "accepted_findings": accepted_findings,
    }


def _governance_vex_export(payload: MarkdownReportPayload) -> dict[str, Any]:
    vex_findings = [
        _governance_finding_row(finding)
        for finding in payload.findings
        if _boolish_signal(finding, "suppressed_by_vex")
        or _boolish_signal(finding, "under_investigation")
        or _vex_statuses_label(finding)
    ]
    return {
        "schema": "governance-vex-summary.v1",
        "schema_version": "1.0.0",
        "generated_at": _iso_datetime(payload.generated_at),
        "project_id": payload.project_id,
        "run_id": payload.run_id,
        "summary": _governance_vex_summary(payload.findings),
        "findings": vex_findings,
    }


def _governance_asset_context_export(payload: MarkdownReportPayload) -> dict[str, Any]:
    return {
        "schema": "governance-asset-context.v1",
        "schema_version": "1.0.0",
        "generated_at": _iso_datetime(payload.generated_at),
        "project_id": payload.project_id,
        "run_id": payload.run_id,
        "owners": _dict_list(payload.governance_rollups.get("owners")),
        "services": _dict_list(payload.governance_rollups.get("services")),
        "top_assets_by_risk": _dict_list(payload.governance_rollups.get("top_assets_by_risk")),
        "environments": _dict_list(payload.governance_rollups.get("environments")),
        "assets": _asset_context_rows(payload.findings),
    }


def _governance_detection_coverage_export(
    payload: MarkdownReportPayload,
) -> dict[str, Any] | None:
    if not payload.detection_coverage:
        return None
    summary = _dict_value(payload.detection_coverage.get("summary"))
    items = _dict_list(payload.detection_coverage.get("items"))
    controls = _dict_list(payload.detection_coverage.get("controls"))
    if not items and not controls:
        return None
    return {
        "schema": "detection-coverage.v1",
        "schema_version": "1.0.0",
        "generated_at": _iso_datetime(payload.generated_at),
        "project_id": payload.project_id,
        "run_id": payload.run_id,
        "summary": summary,
        "items": items,
        "controls": controls,
        "limitations": [
            (
                "Detection coverage is operator-supplied defensive review evidence; it is "
                "not proof that exploitation did or did not occur."
            ),
            (
                "Partial, missing, and unknown coverage identify review gaps that still need "
                "SOC validation or compensating-control documentation."
            ),
        ],
    }


def _asset_context_rows(findings: list[MarkdownReportFinding]) -> list[dict[str, Any]]:
    grouped: dict[str, list[MarkdownReportFinding]] = {}
    for finding in findings:
        label = finding.asset_key or finding.asset or "Unassigned"
        grouped.setdefault(label, []).append(finding)
    rows: list[dict[str, Any]] = []
    for label, items in grouped.items():
        first = items[0]
        rows.append(
            {
                "asset_key": first.asset_key,
                "label": label,
                "owner": first.owner,
                "business_service": first.business_service,
                "environment": first.environment,
                "exposure": first.exposure,
                "criticality": first.criticality,
                "finding_count": len(items),
                "accepted_count": sum(
                    1
                    for finding in items
                    if _boolish_signal(finding, "waived")
                    or finding.status.lower().endswith("accepted")
                ),
                "suppressed_by_vex_count": sum(
                    1 for finding in items if _boolish_signal(finding, "suppressed_by_vex")
                ),
                "top_cves": [finding.cve_id for finding in items[:5]],
            }
        )
    rows.sort(
        key=lambda item: (
            -int(item["finding_count"]),
            str(item["business_service"] or ""),
            str(item["label"]),
        )
    )
    return rows


def _governance_finding_row(finding: MarkdownReportFinding) -> dict[str, Any]:
    waiver = _dict_value(finding.explanation.get("waiver"))
    return {
        "id": finding.id,
        "cve_id": finding.cve_id,
        "priority": _priority_label(finding.priority),
        "status": finding.status,
        "risk_score": finding.risk_score,
        "asset": finding.asset,
        "asset_key": finding.asset_key,
        "owner": finding.owner,
        "business_service": finding.business_service,
        "environment": finding.environment,
        "waived": _boolish_signal(finding, "waived"),
        "waiver_status": _string_from_mapping(waiver, "waiver_status")
        or _string_from_mapping(finding.explanation, "waiver_status"),
        "waiver_owner": _string_from_mapping(waiver, "waiver_owner")
        or _string_from_mapping(finding.explanation, "waiver_owner"),
        "waiver_expires_on": _string_from_mapping(waiver, "waiver_expires_on")
        or _string_from_mapping(finding.explanation, "waiver_expires_on"),
        "waiver_review_on": _string_from_mapping(waiver, "waiver_review_on")
        or _string_from_mapping(finding.explanation, "waiver_review_on"),
        "suppressed_by_vex": _boolish_signal(finding, "suppressed_by_vex"),
        "under_investigation": _boolish_signal(finding, "under_investigation"),
        "vex_statuses": _vex_statuses_label(finding),
        "decision_statement": finding.decision_statement,
    }


def _governance_vex_summary(findings: list[MarkdownReportFinding]) -> dict[str, Any]:
    status_counts: Counter[str] = Counter()
    for finding in findings:
        status_counts.update(_vex_status_counts_from_explanation(finding.explanation))
    return {
        "suppressed_by_vex_count": sum(
            1 for finding in findings if _boolish_signal(finding, "suppressed_by_vex")
        ),
        "under_investigation_count": sum(
            1 for finding in findings if _boolish_signal(finding, "under_investigation")
        ),
        "fixed_count": sum(1 for finding in findings if finding.status.lower().endswith("fixed")),
        "status_counts": dict(sorted(status_counts.items())),
    }


def _redacted_bundle_payload(
    payload: MarkdownReportPayload,
) -> tuple[MarkdownReportPayload, list[str]]:
    redactions: list[str] = []

    def redact(value: Any, path: str) -> Any:
        redacted, paths = _redact_bundle_value(value, path_prefix=path)
        redactions.extend(paths)
        return redacted

    provider_snapshot = None
    if payload.provider_snapshot is not None:
        provider_snapshot = replace(
            payload.provider_snapshot,
            id=redact(payload.provider_snapshot.id, "provider_snapshot.id"),
            content_hash=redact(
                payload.provider_snapshot.content_hash,
                "provider_snapshot.content_hash",
            ),
            nvd_last_sync=redact(
                payload.provider_snapshot.nvd_last_sync,
                "provider_snapshot.nvd_last_sync",
            ),
            epss_date=redact(payload.provider_snapshot.epss_date, "provider_snapshot.epss_date"),
            kev_catalog_version=redact(
                payload.provider_snapshot.kev_catalog_version,
                "provider_snapshot.kev_catalog_version",
            ),
            created_at=redact(payload.provider_snapshot.created_at, "provider_snapshot.created_at"),
            source_hashes=redact(
                payload.provider_snapshot.source_hashes,
                "provider_snapshot.source_hashes",
            ),
            source_metadata=redact(
                payload.provider_snapshot.source_metadata,
                "provider_snapshot.source_metadata",
            ),
        )

    findings: list[MarkdownReportFinding] = []
    for index, finding in enumerate(payload.findings):
        finding_path = f"findings.{index}"
        findings.append(
            replace(
                finding,
                cve_id=redact(finding.cve_id, f"{finding_path}.cve_id"),
                priority=redact(finding.priority, f"{finding_path}.priority"),
                status=redact(finding.status, f"{finding_path}.status"),
                asset=redact(finding.asset, f"{finding_path}.asset"),
                component=redact(finding.component, f"{finding_path}.component"),
                rationale=redact(finding.rationale, f"{finding_path}.rationale"),
                recommended_action=redact(
                    finding.recommended_action,
                    f"{finding_path}.recommended_action",
                ),
                id=redact(finding.id, f"{finding_path}.id"),
                dedup_key=redact(finding.dedup_key, f"{finding_path}.dedup_key"),
                asset_key=redact(finding.asset_key, f"{finding_path}.asset_key"),
                owner=redact(finding.owner, f"{finding_path}.owner"),
                business_service=redact(
                    finding.business_service,
                    f"{finding_path}.business_service",
                ),
                environment=redact(finding.environment, f"{finding_path}.environment"),
                exposure=redact(finding.exposure, f"{finding_path}.exposure"),
                criticality=redact(finding.criticality, f"{finding_path}.criticality"),
                component_purl=redact(finding.component_purl, f"{finding_path}.component_purl"),
                decision_statement=redact(
                    finding.decision_statement,
                    f"{finding_path}.decision_statement",
                ),
                business_impact=redact(
                    finding.business_impact,
                    f"{finding_path}.business_impact",
                ),
                decision_sla=redact(finding.decision_sla, f"{finding_path}.decision_sla"),
                data_quality_flags=redact(
                    finding.data_quality_flags,
                    f"{finding_path}.data_quality_flags",
                ),
                vulnerability=redact(finding.vulnerability, f"{finding_path}.vulnerability"),
                explanation=redact(finding.explanation, f"{finding_path}.explanation"),
                data_quality=redact(finding.data_quality, f"{finding_path}.data_quality"),
                evidence=redact(finding.evidence, f"{finding_path}.evidence"),
                occurrences=redact(finding.occurrences, f"{finding_path}.occurrences"),
            )
        )

    return (
        replace(
            payload,
            project_name=redact(payload.project_name, "project.name"),
            project_description=redact(payload.project_description, "project.description"),
            project_owner_id=redact(payload.project_owner_id, "project.owner_id"),
            input_type=redact(payload.input_type, "analysis_run.input_type"),
            filename=redact(payload.filename, "analysis_run.filename"),
            summary=redact(payload.summary, "analysis_run.summary"),
            run_error=redact(payload.run_error, "analysis_run.error_message"),
            run_errors=redact(payload.run_errors, "analysis_run.errors"),
            governance_rollups=redact(payload.governance_rollups, "governance_rollups"),
            detection_coverage=redact(payload.detection_coverage, "detection_coverage"),
            findings=findings,
            provider_snapshot=provider_snapshot,
        ),
        redactions,
    )


def _redact_bundle_value(value: Any, *, path_prefix: str = "") -> tuple[Any, list[str]]:
    return redact_value(value, path_prefix=path_prefix)


def _write_deterministic_zip_member(
    archive: zipfile.ZipFile,
    path: str,
    content: bytes,
) -> None:
    info = zipfile.ZipInfo(filename=path, date_time=DETERMINISTIC_ZIP_TIMESTAMP)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3
    info.external_attr = DETERMINISTIC_ZIP_FILE_MODE
    archive.writestr(info, content)


def render_html_executive_report(payload: MarkdownReportPayload) -> str:
    """Render a deterministic, escaped executive HTML report."""
    payload, _redactions = _redacted_bundle_payload(payload)
    finding_count = len(payload.findings)
    counts = _counts_by_priority(payload.findings)
    top_findings = payload.findings[:10]
    critical_or_high = counts["Critical"] + counts["High"]
    generated_at = _safe_html(_iso_datetime(payload.generated_at))
    snapshot = payload.provider_snapshot
    locked_provider_data = (
        _metadata_bool(snapshot.source_metadata, "locked_provider_data")
        if snapshot is not None
        else "N/A"
    )
    executive_summary = _executive_summary_text(
        finding_count,
        critical_or_high,
        locked_provider_data,
    )

    rows = "\n".join(_html_top_risk_row(finding) for finding in top_findings)
    if not rows:
        rows = (
            '<tr><td colspan="9" class="empty-state">'
            "No findings were recorded for this analysis run.</td></tr>"
        )

    recommendations = "\n".join(_html_recommendation_item(finding) for finding in top_findings[:5])
    if not recommendations:
        recommendations = "<li>No remediation recommendations are available for this run.</li>"
    governance_section = (
        f"{_html_governance_rollups(payload.governance_rollups, payload.findings)}\n\n"
        if payload.governance_rollups
        else ""
    )

    return (
        "<!doctype html>\n"
        '<html lang="en">\n'
        "<head>\n"
        '  <meta charset="utf-8">\n'
        '  <meta name="viewport" content="width=device-width, initial-scale=1">\n'
        "  <title>Executive Vulnerability Report</title>\n"
        "  <style>\n"
        f"{EXECUTIVE_REPORT_CSS}\n"
        "  </style>\n"
        "</head>\n"
        "<body>\n"
        '  <main class="report-shell">\n'
        "    <header>\n"
        '      <p class="eyebrow">Executive Vulnerability Report</p>\n'
        f"      <h1>{_safe_html(payload.project_name)}</h1>\n"
        '      <p class="lede">Decision-ready vulnerability prioritization summary '
        f"for analysis run {_safe_html(payload.run_id)} generated at {generated_at}.</p>\n"
        '      <dl class="meta-grid">\n'
        f"        <div><dt>Project ID</dt><dd>{_safe_html(payload.project_id)}</dd></div>\n"
        f"        <div><dt>Run Status</dt><dd>{_safe_html(payload.run_status)}</dd></div>\n"
        f"        <div><dt>Input Type</dt><dd>{_safe_html(payload.input_type)}</dd></div>\n"
        f"        <div><dt>Input File</dt><dd>{_safe_html(payload.filename)}</dd></div>\n"
        "      </dl>\n"
        "    </header>\n"
        "\n"
        '    <section aria-labelledby="executive-summary">\n'
        '      <div class="section-heading">\n'
        '        <p class="eyebrow">Summary</p>\n'
        '        <h2 id="executive-summary">Executive Summary</h2>\n'
        "      </div>\n"
        '      <div class="metric-grid">\n'
        f"        {_html_metric('Findings', finding_count)}\n"
        f"        {_html_metric('Critical', counts['Critical'])}\n"
        f"        {_html_metric('High', counts['High'])}\n"
        f"        {_html_metric('Critical or High', critical_or_high)}\n"
        "      </div>\n"
        "      <p>"
        f"{_safe_html(executive_summary)}"
        "</p>\n"
        "    </section>\n"
        "\n"
        f"{governance_section}"
        '    <section aria-labelledby="business-impact">\n'
        '      <div class="section-heading">\n'
        '        <p class="eyebrow">Impact</p>\n'
        '        <h2 id="business-impact">Business Impact</h2>\n'
        "      </div>\n"
        f"      <p>{_safe_html(_business_impact_summary(payload.findings))}</p>\n"
        "    </section>\n"
        "\n"
        '    <section aria-labelledby="top-risks">\n'
        '      <div class="section-heading">\n'
        '        <p class="eyebrow">Priorities</p>\n'
        '        <h2 id="top-risks">Top Risks</h2>\n'
        "      </div>\n"
        '      <div class="table-wrap">\n'
        "        <table>\n"
        "          <thead>\n"
        "            <tr><th>Rank</th><th>CVE</th><th>Priority</th><th>Score</th>"
        "<th>EPSS</th><th>CVSS</th><th>KEV</th><th>Asset</th>"
        "<th>Decision Statement</th></tr>\n"
        "          </thead>\n"
        f"          <tbody>\n{rows}\n          </tbody>\n"
        "        </table>\n"
        "      </div>\n"
        "    </section>\n"
        "\n"
        '    <section aria-labelledby="recommendations">\n'
        '      <div class="section-heading">\n'
        '        <p class="eyebrow">Actions</p>\n'
        '        <h2 id="recommendations">Recommendations</h2>\n'
        "      </div>\n"
        f'      <ol class="recommendation-list">\n{recommendations}\n      </ol>\n'
        "    </section>\n"
        "\n"
        '    <section aria-labelledby="provider-freshness">\n'
        '      <div class="section-heading">\n'
        '        <p class="eyebrow">Evidence</p>\n'
        '        <h2 id="provider-freshness">Provider Freshness</h2>\n'
        "      </div>\n"
        f"{_html_provider_snapshot(snapshot)}\n"
        "    </section>\n"
        "  </main>\n"
        "</body>\n"
        "</html>\n"
    )


def _html_metric(label: str, value: object) -> str:
    return (
        '<div class="metric">'
        f"<span>{_safe_html(label)}</span>"
        f"<strong>{_safe_html(value)}</strong>"
        "</div>"
    )


def _html_governance_rollups(
    governance_rollups: dict[str, Any],
    findings: list[MarkdownReportFinding],
) -> str:
    services = _dict_list(governance_rollups.get("top_services_by_risk"))[:5]
    assets = _dict_list(governance_rollups.get("top_assets_by_risk"))[:5]
    waiver_debt = _dict_value(governance_rollups.get("waiver_debt"))
    waiver_items = _dict_list(waiver_debt.get("items"))[:5]
    vex_summary = _governance_vex_summary(findings)
    service_rows = "\n".join(_html_service_rollup_row(service) for service in services)
    if not service_rows:
        service_rows = (
            '<tr><td colspan="6" class="empty-state">'
            "No service rollups are available for this analysis run.</td></tr>"
        )
    asset_rows = "\n".join(_html_asset_rollup_row(asset) for asset in assets)
    if not asset_rows:
        asset_rows = (
            '<tr><td colspan="7" class="empty-state">'
            "No asset rollups are available for this analysis run.</td></tr>"
        )
    waiver_rows = "\n".join(_html_waiver_debt_row(item) for item in waiver_items)
    if not waiver_rows:
        waiver_rows = (
            '<tr><td colspan="6" class="empty-state">'
            "No accepted-risk waiver debt is currently recorded for this run.</td></tr>"
        )
    return (
        '    <section aria-labelledby="governance-rollups">\n'
        '      <div class="section-heading">\n'
        '        <p class="eyebrow">Governance</p>\n'
        '        <h2 id="governance-rollups">Service Risk, Accepted Risk, and VEX</h2>\n'
        "      </div>\n"
        '      <div class="metric-grid">\n'
        f"        {_html_metric('Waivers', waiver_debt.get('waiver_count', 0))}\n"
        f"        {_html_metric('Expired', waiver_debt.get('expired_count', 0))}\n"
        f"        {_html_metric('Review Due', waiver_debt.get('review_due_count', 0))}\n"
        f"        {_html_metric('Expiring Soon', waiver_debt.get('expiring_soon_count', 0))}\n"
        "        "
        f"{_html_metric('Accepted Findings', waiver_debt.get('accepted_finding_count', 0))}\n"
        f"        {_html_metric('VEX Suppressed', vex_summary['suppressed_by_vex_count'])}\n"
        "      </div>\n"
        "      <h3>Service Rollup</h3>\n"
        '      <div class="table-wrap">\n'
        "        <table>\n"
        "          <thead>\n"
        "            <tr><th>Service</th><th>Findings</th><th>Critical</th><th>High</th>"
        "<th>Risk Score</th><th>Waiver Debt</th></tr>\n"
        "          </thead>\n"
        f"          <tbody>\n{service_rows}\n          </tbody>\n"
        "        </table>\n"
        "      </div>\n"
        "      <h3>Asset Rollup</h3>\n"
        '      <div class="table-wrap">\n'
        "        <table>\n"
        "          <thead>\n"
        "            <tr><th>Asset</th><th>Findings</th><th>Critical</th><th>High</th>"
        "<th>Risk Score</th><th>Accepted</th><th>VEX Suppressed</th></tr>\n"
        "          </thead>\n"
        f"          <tbody>\n{asset_rows}\n          </tbody>\n"
        "        </table>\n"
        "      </div>\n"
        "      <h3>Accepted Risk and Expiring Waivers</h3>\n"
        '      <div class="table-wrap">\n'
        "        <table>\n"
        "          <thead>\n"
        "            <tr><th>Scope</th><th>Owner</th><th>Status</th><th>Expires</th>"
        "<th>Review</th><th>Matched</th></tr>\n"
        "          </thead>\n"
        f"          <tbody>\n{waiver_rows}\n          </tbody>\n"
        "        </table>\n"
        "      </div>\n"
        "    </section>"
    )


def _html_service_rollup_row(service: dict[str, Any]) -> str:
    waiver_debt_count = int(service.get("expired_waiver_count") or 0) + int(
        service.get("review_due_waiver_count") or 0
    )
    return (
        "            <tr>"
        f"<td>{_safe_html(service.get('label'))}</td>"
        f"<td>{_safe_html(service.get('finding_count', 0))}</td>"
        f"<td>{_safe_html(service.get('critical_count', 0))}</td>"
        f"<td>{_safe_html(service.get('high_count', 0))}</td>"
        f"<td>{_safe_html(_format_number(service.get('risk_score_total')))}</td>"
        f"<td>{_safe_html(waiver_debt_count)}</td>"
        "</tr>"
    )


def _html_asset_rollup_row(asset: dict[str, Any]) -> str:
    return (
        "            <tr>"
        f"<td>{_safe_html(asset.get('label'))}</td>"
        f"<td>{_safe_html(asset.get('finding_count', 0))}</td>"
        f"<td>{_safe_html(asset.get('critical_count', 0))}</td>"
        f"<td>{_safe_html(asset.get('high_count', 0))}</td>"
        f"<td>{_safe_html(_format_number(asset.get('risk_score_total')))}</td>"
        f"<td>{_safe_html(asset.get('accepted_count', 0))}</td>"
        f"<td>{_safe_html(asset.get('suppressed_by_vex_count', 0))}</td>"
        "</tr>"
    )


def _html_waiver_debt_row(item: dict[str, Any]) -> str:
    return (
        "            <tr>"
        f"<td>{_safe_html(item.get('scope'))}</td>"
        f"<td>{_safe_html(item.get('owner'))}</td>"
        f"<td>{_safe_html(item.get('status'))}</td>"
        f"<td>{_safe_html(item.get('expires_at'))}</td>"
        f"<td>{_safe_html(item.get('review_at'))}</td>"
        f"<td>{_safe_html(item.get('matched_findings', 0))}</td>"
        "</tr>"
    )


def _html_top_risk_row(finding: MarkdownReportFinding) -> str:
    priority = _priority_label(finding.priority)
    priority_class = f"badge-{priority.lower()}"
    return (
        "            <tr>"
        f"<td>{finding.operational_rank}</td>"
        f"<td>{_safe_html(finding.cve_id)}</td>"
        f'<td><span class="badge {priority_class}">{_safe_html(priority)}</span></td>'
        f"<td>{_safe_html(_format_number(finding.risk_score))}</td>"
        f"<td>{_safe_html(_format_number(finding.epss))}</td>"
        f"<td>{_safe_html(_format_number(finding.cvss_base_score))}</td>"
        f"<td>{'Yes' if finding.in_kev else 'No'}</td>"
        f"<td>{_safe_html(finding.asset)}</td>"
        f"<td>{_safe_html(_decision_statement(finding))}</td>"
        "</tr>"
    )


def _html_recommendation_item(finding: MarkdownReportFinding) -> str:
    sla = f" SLA: {finding.decision_sla}" if finding.decision_sla else ""
    action = finding.recommended_action or _decision_statement(finding)
    heading = f"{finding.cve_id} - {_priority_label(finding.priority)}"
    return (
        "        <li>"
        f"<strong>{_safe_html(heading)}</strong>"
        f"<span>{_safe_html(action + sla)}</span>"
        "</li>"
    )


def _html_provider_snapshot(snapshot: MarkdownProviderSnapshot | None) -> str:
    if snapshot is None:
        return "<p>No provider snapshot was linked to this analysis run.</p>"

    selected_sources = _metadata_list(snapshot.source_metadata, "selected_sources")
    locked_provider_data = _metadata_bool(snapshot.source_metadata, "locked_provider_data")
    cells = [
        ("Snapshot ID", snapshot.id),
        ("Content Hash", snapshot.content_hash),
        ("NVD Last Sync", snapshot.nvd_last_sync),
        ("EPSS Date", snapshot.epss_date),
        ("KEV Catalog Version", snapshot.kev_catalog_version),
        ("Locked Provider Data", locked_provider_data),
        ("Selected Sources", selected_sources),
    ]
    for key, value in sorted(snapshot.source_hashes.items()):
        cells.append((f"Source Hash: {key}", value))
    for key in ("source_path", "item_count", "missing", "validation_error"):
        if key in snapshot.source_metadata:
            cells.append((f"Metadata: {key}", snapshot.source_metadata[key]))

    items = "\n".join(
        f"        <div><dt>{_safe_html(label)}</dt><dd>{_safe_html(value)}</dd></div>"
        for label, value in cells
    )
    return f'      <dl class="provider-grid">\n{items}\n      </dl>'


def _executive_summary_text(
    finding_count: int,
    critical_or_high: int,
    locked_provider_data: str,
) -> str:
    if finding_count == 0:
        return (
            "The analyzed run has no recorded findings. Confirm import coverage before "
            "treating this as a no-risk result."
        )
    return (
        f"The run contains {finding_count} finding(s), including {critical_or_high} "
        "critical or high priority item(s). Prioritize the listed top risks first and "
        "validate execution against provider freshness. "
        f"Locked provider data: {locked_provider_data}."
    )


def _business_impact_summary(findings: list[MarkdownReportFinding]) -> str:
    impacts = [finding.business_impact for finding in findings if finding.business_impact]
    if impacts:
        return impacts[0]
    assets = [finding.asset for finding in findings[:5] if finding.asset]
    if assets:
        return (
            "Business exposure is concentrated in the top ranked affected assets: "
            f"{', '.join(assets)}. Confirm owner, environment, and service criticality "
            "before final scheduling."
        )
    if findings:
        return (
            "Asset and owner context is not complete for the top findings. Treat missing "
            "business context as unverified and validate before accepting risk."
        )
    return "No business impact can be derived because no findings were recorded."


def _decision_statement(finding: MarkdownReportFinding) -> str:
    return finding.decision_statement or finding.recommended_action or "Review and assign an owner."


def _analysis_provider_snapshot(snapshot: MarkdownProviderSnapshot | None) -> dict[str, Any] | None:
    if snapshot is None:
        return None
    return {
        "id": snapshot.id,
        "created_at": snapshot.created_at,
        "content_hash": snapshot.content_hash,
        "nvd_last_sync": snapshot.nvd_last_sync,
        "epss_date": snapshot.epss_date,
        "kev_catalog_version": snapshot.kev_catalog_version,
        "source_hashes": snapshot.source_hashes,
        "source_metadata": snapshot.source_metadata,
    }


def _analysis_finding(finding: MarkdownReportFinding) -> dict[str, Any]:
    return {
        "id": finding.id,
        "cve_id": finding.cve_id,
        "status": finding.status,
        "priority": _priority_label(finding.priority),
        "priority_raw": finding.priority,
        "priority_rank": finding.priority_rank,
        "operational_rank": finding.operational_rank,
        "dedup_key": finding.dedup_key,
        "risk_score": finding.risk_score,
        "epss": finding.epss,
        "cvss_base_score": finding.cvss_base_score,
        "in_kev": finding.in_kev,
        "attack_mapped": _boolish_signal(finding, "attack_mapped"),
        "suppressed_by_vex": _boolish_signal(finding, "suppressed_by_vex"),
        "under_investigation": _boolish_signal(finding, "under_investigation"),
        "waived": _boolish_signal(finding, "waived"),
        "asset": {
            "label": finding.asset,
            "asset_key": finding.asset_key,
            "owner": finding.owner,
            "business_service": finding.business_service,
            "environment": finding.environment,
            "exposure": finding.exposure,
            "criticality": finding.criticality,
        },
        "component": {
            "label": finding.component,
            "purl": finding.component_purl,
        },
        "vulnerability": finding.vulnerability,
        "recommendation": {
            "rationale": finding.rationale,
            "recommended_action": finding.recommended_action,
            "decision_guidance": _decision_guidance_from_payload(finding),
            "decision_statement": finding.decision_statement,
            "decision_sla": finding.decision_sla,
            "business_impact": finding.business_impact,
        },
        "data_quality": {
            "confidence": finding.data_quality_confidence,
            "flags": finding.data_quality_flags,
            "raw": finding.data_quality,
        },
        "explanation": finding.explanation,
        "evidence": finding.evidence,
        "occurrences": finding.occurrences,
        "first_seen_at": _iso_datetime(finding.first_seen_at) if finding.first_seen_at else None,
        "last_seen_at": _iso_datetime(finding.last_seen_at) if finding.last_seen_at else None,
        "created_at": _iso_datetime(finding.created_at) if finding.created_at else None,
        "updated_at": _iso_datetime(finding.updated_at) if finding.updated_at else None,
    }


def _finding_payload(
    finding: Finding,
    *,
    occurrences: list[FindingOccurrence],
) -> MarkdownReportFinding:
    decision_guidance = _decision_guidance(finding)
    explanation = _dict_value(finding.explanation_json)
    base_decision_statement = _decision_text(
        decision_guidance,
        "decision_statement",
        fallback=finding.recommended_action,
    )
    return MarkdownReportFinding(
        id=str(finding.id),
        dedup_key=finding.dedup_key,
        operational_rank=finding.operational_rank,
        cve_id=finding.cve_id,
        priority=str(finding.priority),
        status=str(finding.status),
        priority_rank=finding.priority_rank,
        risk_score=finding.risk_score,
        epss=finding.epss,
        cvss_base_score=finding.cvss_base_score,
        in_kev=finding.in_kev,
        asset=_asset_label(finding),
        asset_key=finding.asset.asset_key if finding.asset is not None else None,
        owner=finding.asset.owner if finding.asset is not None else None,
        business_service=finding.asset.business_service if finding.asset is not None else None,
        environment=str(finding.asset.environment) if finding.asset is not None else None,
        exposure=str(finding.asset.exposure) if finding.asset is not None else None,
        criticality=str(finding.asset.criticality) if finding.asset is not None else None,
        component=_component_label(finding),
        component_purl=finding.component.purl if finding.component is not None else None,
        attack_mapped=finding.attack_mapped,
        suppressed_by_vex=finding.suppressed_by_vex,
        under_investigation=finding.under_investigation,
        waived=finding.waived,
        vulnerability=_vulnerability_payload(finding),
        rationale=finding.rationale,
        recommended_action=finding.recommended_action,
        explanation=explanation,
        data_quality=_dict_value(finding.data_quality_json),
        evidence=_dict_value(finding.evidence_json),
        occurrences=[_occurrence_payload(occurrence) for occurrence in occurrences],
        data_quality_confidence=_data_quality_confidence(finding),
        decision_statement=_governance_decision_statement(
            finding=finding,
            explanation=explanation,
            base_statement=base_decision_statement,
        ),
        business_impact=_decision_text(decision_guidance, "business_impact"),
        decision_sla=_decision_sla(decision_guidance),
        data_quality_flags=_data_quality_flags(finding),
        first_seen_at=finding.first_seen_at,
        last_seen_at=finding.last_seen_at,
        created_at=finding.created_at,
        updated_at=finding.updated_at,
    )


def _governance_decision_statement(
    *,
    finding: Finding,
    explanation: dict[str, Any],
    base_statement: str | None,
) -> str | None:
    statement = base_statement
    additions: list[str] = []
    waiver = _dict_value(explanation.get("waiver"))
    waiver_status = _string_from_mapping(waiver, "waiver_status") or _string_from_mapping(
        explanation, "waiver_status"
    )
    if finding.waived or waiver_status:
        additions.append(
            "Accepted-risk governance remains visible"
            + _governance_detail_clause(
                (
                    (
                        "owner",
                        _string_from_mapping(waiver, "waiver_owner")
                        or _string_from_mapping(explanation, "waiver_owner"),
                    ),
                    ("status", waiver_status),
                    (
                        "review",
                        _string_from_mapping(waiver, "waiver_review_on")
                        or _string_from_mapping(explanation, "waiver_review_on"),
                    ),
                    (
                        "expires",
                        _string_from_mapping(waiver, "waiver_expires_on")
                        or _string_from_mapping(explanation, "waiver_expires_on"),
                    ),
                )
            )
            + "."
        )
    if finding.suppressed_by_vex or finding.under_investigation:
        vex_statuses = _vex_statuses_label_from_explanation(explanation)
        additions.append(
            "VEX governance applies"
            + _governance_detail_clause(
                (
                    ("status", vex_statuses),
                    ("source", _string_from_mapping(explanation, "vex_source_format")),
                    ("record", _string_from_mapping(explanation, "vex_source_record_id")),
                )
            )
            + "."
        )
    if not additions:
        return statement
    prefix = statement.rstrip() if statement else "Decision Statement: review finding governance."
    return f"{prefix} {' '.join(additions)}"


def _governance_detail_clause(items: Sequence[tuple[str, str | None]]) -> str:
    details = [f"{label} {value}" for label, value in items if value]
    return f" ({'; '.join(details)})" if details else ""


def _provider_snapshot_payload(
    snapshot: ProviderSnapshot | None,
) -> MarkdownProviderSnapshot | None:
    if snapshot is None:
        return None
    return MarkdownProviderSnapshot(
        id=str(snapshot.id),
        content_hash=snapshot.content_hash,
        nvd_last_sync=snapshot.nvd_last_sync,
        epss_date=snapshot.epss_date,
        kev_catalog_version=snapshot.kev_catalog_version,
        created_at=_iso_datetime(snapshot.created_at),
        source_hashes=dict(snapshot.source_hashes_json or {}),
        source_metadata=dict(snapshot.source_metadata_json or {}),
    )


def _asset_label(finding: Finding) -> str | None:
    if finding.asset is None:
        return None
    return finding.asset.name or finding.asset.asset_key


def _component_label(finding: Finding) -> str | None:
    if finding.component is None:
        return None
    if finding.component.version:
        return f"{finding.component.name} {finding.component.version}"
    return finding.component.name


def _vulnerability_payload(finding: Finding) -> dict[str, Any]:
    vulnerability = finding.vulnerability
    if vulnerability is None:
        return {}
    return {
        "id": str(vulnerability.id),
        "source_id": vulnerability.source_id,
        "title": vulnerability.title,
        "description": vulnerability.description,
        "cvss_score": vulnerability.cvss_score,
        "cvss_vector": vulnerability.cvss_vector,
        "severity": vulnerability.severity,
        "cwe": vulnerability.cwe,
        "published_at": vulnerability.published_at,
        "modified_at": vulnerability.modified_at,
        "provider": dict(vulnerability.provider_json or {}),
    }


def _occurrence_payload(occurrence: FindingOccurrence) -> dict[str, Any]:
    evidence = _dict_value(occurrence.evidence_json)
    return {
        "id": str(occurrence.id),
        "analysis_run_id": str(occurrence.analysis_run_id),
        "source": occurrence.source,
        "scanner": occurrence.scanner,
        "raw_reference": occurrence.raw_reference,
        "fix_version": occurrence.fix_version,
        "evidence": evidence,
    }


def _data_quality_confidence(finding: Finding) -> str | None:
    explanation_json = _dict_value(finding.explanation_json)
    data_quality_json = _dict_value(finding.data_quality_json)
    value = explanation_json.get("data_quality_confidence") or data_quality_json.get("confidence")
    return str(value) if value else None


def _data_quality_flags(finding: Finding) -> list[str]:
    explanation_json = _dict_value(finding.explanation_json)
    data_quality_json = _dict_value(finding.data_quality_json)
    flags = _flag_items(explanation_json.get("data_quality_flags"))
    flags.extend(_flag_items(data_quality_json.get("flags")))
    deduped: list[str] = []
    for flag in flags:
        if flag not in deduped:
            deduped.append(flag)
    return deduped


def _decision_guidance(finding: Finding) -> dict[str, Any]:
    explanation_json = _dict_value(finding.explanation_json)
    return _dict_value(explanation_json.get("decision_guidance"))


def _decision_text(
    decision_guidance: dict[str, Any],
    key: str,
    *,
    fallback: str | None = None,
) -> str | None:
    value = decision_guidance.get(key)
    if isinstance(value, str):
        return value if value.strip() else fallback
    if isinstance(value, dict):
        for candidate_key in ("text", "summary", "statement", "label"):
            candidate = value.get(candidate_key)
            if isinstance(candidate, str) and candidate.strip():
                return candidate
    return fallback


def _decision_sla(decision_guidance: dict[str, Any]) -> str | None:
    sla = decision_guidance.get("sla")
    if isinstance(sla, str):
        return sla if sla.strip() else None
    if not isinstance(sla, dict):
        return None

    label = str(sla.get("label")).strip() if sla.get("label") else None
    target = sla.get("target_hours") or sla.get("hours")
    if target is None:
        target_days = sla.get("target_days") or sla.get("days")
        if target_days is not None:
            target = f"{target_days}d"
    elif isinstance(target, int | float) and float(target).is_integer():
        target = f"{int(target)}h"
    else:
        target = f"{target}h"

    parts = [part for part in (label, str(target).strip() if target else None) if part]
    return " / ".join(parts) if parts else None


def _flag_items(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    flags: list[str] = []
    for item in value:
        if isinstance(item, dict):
            parts = [
                str(item[key]) for key in ("code", "label", "message", "detail") if item.get(key)
            ]
            if parts:
                flags.append(" - ".join(parts))
        elif item:
            flags.append(str(item))
    return flags


def _counts_by_priority(findings: list[MarkdownReportFinding]) -> dict[str, int]:
    counts = Counter(_priority_label(finding.priority) for finding in findings)
    return {priority: counts.get(priority, 0) for priority in PRIORITY_LABELS}


def _priority_label(value: str) -> str:
    normalized = value.split(".", maxsplit=1)[-1].strip().lower()
    return {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
    }.get(normalized, "Low")


def _safe_cell(value: object | None) -> str:
    return _safe_inline(value).replace("|", "\\|")


def _safe_inline(value: object | None) -> str:
    if value is None:
        return "N/A"
    text = str(value).strip()
    if not text:
        return "N/A"
    text = re.sub(r"\s+", " ", text)
    escaped = html.escape(text, quote=True)
    return "".join(
        f"\\{character}" if character in MARKDOWN_SPECIAL_CHARS else character
        for character in escaped
    )


def _safe_html(value: object | None) -> str:
    if value is None:
        return "N/A"
    text = str(value).strip()
    if not text:
        return "N/A"
    return html.escape(re.sub(r"\s+", " ", text), quote=True)


def _csv_safe_cell(value: object | None) -> str:
    text = "" if value is None else str(value)
    if text.startswith(("\t", "\r", "\n")) or text.lstrip().startswith(("=", "+", "-", "@")):
        return "'" + text
    return text


def _decision_guidance_from_payload(finding: MarkdownReportFinding) -> dict[str, Any]:
    value = finding.explanation.get("decision_guidance")
    return dict(value) if isinstance(value, dict) else {}


def _string_from_mapping(mapping: dict[str, Any], key: str) -> str | None:
    value = mapping.get(key)
    return value if isinstance(value, str) and value.strip() else None


def _boolish_signal(finding: MarkdownReportFinding, key: str) -> bool:
    if hasattr(finding, key):
        return bool(getattr(finding, key))
    if key == "attack_mapped":
        value: Any = finding.explanation.get(key, False)
        if value is False:
            value = finding.evidence.get(key, False)
    else:
        value = finding.explanation.get(key, False)
    return bool(value)


def _list_value(mapping: dict[str, Any], key: str) -> list[Any]:
    value = mapping.get(key)
    return value if isinstance(value, list) else []


def _dict_list(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [dict(item) for item in value if isinstance(item, dict)]


def _vex_statuses_label(finding: MarkdownReportFinding) -> str:
    return _vex_statuses_label_from_explanation(finding.explanation)


def _vex_statuses_label_from_explanation(explanation: dict[str, Any]) -> str:
    status_counts = _vex_status_counts_from_explanation(explanation)
    if status_counts:
        return ";".join(f"{status}:{count}" for status, count in sorted(status_counts.items()))
    return ""


def _vex_status_counts_from_explanation(explanation: dict[str, Any]) -> Counter[str]:
    status_counts: Counter[str] = Counter()
    for record in (explanation, _dict_value(explanation.get("provenance"))):
        statuses = record.get("vex_statuses")
        if isinstance(statuses, dict) and statuses:
            for status, count in statuses.items():
                status_text = str(status).strip()
                if not status_text:
                    continue
                if isinstance(count, int | float):
                    status_counts[status_text] += int(count)
                elif count:
                    status_counts[status_text] += 1
            return status_counts
        status = record.get("vex_status")
        if isinstance(status, str) and status.strip():
            status_counts[status.strip()] += 1
            return status_counts
    return status_counts


def _format_number(value: float | None) -> str:
    if value is None:
        return "N/A"
    number = float(value)
    if number.is_integer():
        return str(int(number))
    return f"{number:.3f}".rstrip("0").rstrip(".")


def _iso_datetime(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _metadata_bool(metadata: dict[str, Any], key: str) -> str:
    if key not in metadata:
        return "N/A"
    return "Yes" if bool(metadata[key]) else "No"


def _metadata_list(metadata: dict[str, Any], key: str) -> str:
    value = metadata.get(key)
    if isinstance(value, list):
        items = [str(item) for item in value if item]
        return ", ".join(items) if items else "N/A"
    return str(value) if value else "N/A"


def _dict_value(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}

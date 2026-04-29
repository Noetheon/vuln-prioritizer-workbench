"""Template-stack report generation services."""

from __future__ import annotations

import hashlib
import html
import re
import uuid
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from sqlmodel import Session, col, select

from app.core.config import Settings
from app.models import (
    AnalysisRun,
    AnalysisRunStatus,
    Finding,
    FindingOccurrence,
    Project,
    ProviderSnapshot,
    Report,
)
from app.models.base import get_datetime_utc
from app.repositories import ReportRepository

REPORT_KIND_TECHNICAL_MARKDOWN = "technical-markdown"
REPORT_KIND_EXECUTIVE_HTML = "executive-html"
REPORT_FILENAME_TECHNICAL_MARKDOWN = "technical-report.md"
REPORT_FILENAME_EXECUTIVE_HTML = "executive-report.html"
REPORT_CONTENT_TYPE_MARKDOWN = "text/markdown; charset=utf-8"
REPORT_CONTENT_TYPE_HTML = "text/html; charset=utf-8"
REPORT_SUPPORTED_RUN_STATUSES = {
    AnalysisRunStatus.COMPLETED,
    AnalysisRunStatus.COMPLETED_WITH_ERRORS,
    AnalysisRunStatus.SUCCEEDED,
}
PRIORITY_LABELS = ("Critical", "High", "Medium", "Low")
MARKDOWN_SPECIAL_CHARS = "\\`*_{}[]()!"
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


class ReportGenerationError(RuntimeError):
    """Raised when a report cannot be generated from the stored run."""


@dataclass(frozen=True, slots=True)
class MarkdownProviderSnapshot:
    """Provider snapshot context shown in generated Markdown reports."""

    id: str | None
    content_hash: str | None
    nvd_last_sync: str | None
    epss_date: str | None
    kev_catalog_version: str | None
    source_hashes: dict[str, Any] = field(default_factory=dict)
    source_metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class MarkdownReportFinding:
    """Finding context shown in generated Markdown reports."""

    operational_rank: int
    cve_id: str
    priority: str
    status: str
    risk_score: float | None
    epss: float | None
    cvss_base_score: float | None
    in_kev: bool
    asset: str | None
    component: str | None
    rationale: str | None
    recommended_action: str | None
    data_quality_confidence: str | None
    decision_statement: str | None = None
    business_impact: str | None = None
    decision_sla: str | None = None
    data_quality_flags: list[str] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class MarkdownReportPayload:
    """Pure rendering payload for deterministic snapshot tests."""

    generated_at: datetime
    project_id: str
    project_name: str
    run_id: str
    run_status: str
    input_type: str
    filename: str | None
    summary: dict[str, Any]
    findings: list[MarkdownReportFinding]
    provider_snapshot: MarkdownProviderSnapshot | None


class ReportService:
    """Generate and persist report artifacts for template analysis runs."""

    def __init__(self, session: Session, settings: Settings) -> None:
        self.session = session
        self.settings = settings

    def create_markdown_report(self, *, run: AnalysisRun, project: Project) -> Report:
        """Generate a Markdown technical report and persist its metadata."""
        payload, findings, generated_at = self._report_payload(run=run, project=project)
        content = render_markdown_report(payload)
        return self._persist_report(
            run=run,
            project=project,
            generated_at=generated_at,
            finding_count=len(findings),
            provider_snapshot_id=run.provider_snapshot_id,
            content=content,
            kind=REPORT_KIND_TECHNICAL_MARKDOWN,
            report_format="markdown",
            filename=REPORT_FILENAME_TECHNICAL_MARKDOWN,
            content_type=REPORT_CONTENT_TYPE_MARKDOWN,
        )

    def create_html_report(self, *, run: AnalysisRun, project: Project) -> Report:
        """Generate an HTML executive report and persist its metadata."""
        payload, findings, generated_at = self._report_payload(run=run, project=project)
        content = render_html_executive_report(payload)
        return self._persist_report(
            run=run,
            project=project,
            generated_at=generated_at,
            finding_count=len(findings),
            provider_snapshot_id=run.provider_snapshot_id,
            content=content,
            kind=REPORT_KIND_EXECUTIVE_HTML,
            report_format="html",
            filename=REPORT_FILENAME_EXECUTIVE_HTML,
            content_type=REPORT_CONTENT_TYPE_HTML,
        )

    def _report_payload(
        self,
        *,
        run: AnalysisRun,
        project: Project,
    ) -> tuple[MarkdownReportPayload, list[Finding], datetime]:
        if run.status not in REPORT_SUPPORTED_RUN_STATUSES:
            raise ReportGenerationError(
                f"Analysis run must be completed before reporting; current status is {run.status}."
            )

        generated_at = get_datetime_utc()
        findings = self._run_findings(run)
        payload = MarkdownReportPayload(
            generated_at=generated_at,
            project_id=str(project.id),
            project_name=project.name,
            run_id=str(run.id),
            run_status=str(run.status),
            input_type=run.input_type,
            filename=run.filename,
            summary=dict(run.summary_json or {}),
            findings=[_finding_payload(finding) for finding in findings],
            provider_snapshot=_provider_snapshot_payload(run.provider_snapshot),
        )
        return payload, findings, generated_at

    def _persist_report(
        self,
        *,
        run: AnalysisRun,
        project: Project,
        generated_at: datetime,
        finding_count: int,
        provider_snapshot_id: uuid.UUID | None,
        content: str,
        kind: str,
        report_format: str,
        filename: str,
        content_type: str,
    ) -> Report:
        report_id = uuid.uuid4()
        report_path = self._report_path(
            project_id=project.id,
            run_id=run.id,
            report_id=report_id,
            filename=filename,
        )
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(content, encoding="utf-8")
        content_bytes = content.encode("utf-8")
        sha256 = hashlib.sha256(content_bytes).hexdigest()
        return ReportRepository(self.session).create_report(
            report_id=report_id,
            project_id=project.id,
            analysis_run_id=run.id,
            kind=kind,
            format=report_format,
            filename=filename,
            content_type=content_type,
            path=str(report_path),
            sha256=sha256,
            size_bytes=len(content_bytes),
            metadata_json={
                "generated_at": generated_at.isoformat(),
                "project_id": str(project.id),
                "analysis_run_id": str(run.id),
                "provider_snapshot_id": str(provider_snapshot_id)
                if provider_snapshot_id is not None
                else None,
                "finding_count": finding_count,
                "format": report_format,
                "kind": kind,
                "service": "template-report-service",
            },
        )

    def _run_findings(self, run: AnalysisRun) -> list[Finding]:
        statement = (
            select(Finding)
            .join(FindingOccurrence)
            .where(FindingOccurrence.analysis_run_id == run.id)
            .order_by(col(Finding.operational_rank), col(Finding.priority_rank), Finding.cve_id)
        )
        findings: list[Finding] = []
        seen_ids: set[uuid.UUID] = set()
        for finding in self.session.exec(statement).all():
            if finding.id in seen_ids:
                continue
            findings.append(finding)
            seen_ids.add(finding.id)
        return findings

    def _report_path(
        self,
        *,
        project_id: uuid.UUID,
        run_id: uuid.UUID,
        report_id: uuid.UUID,
        filename: str,
    ) -> Path:
        return (
            self.settings.report_dir_path
            / str(project_id)
            / str(run_id)
            / str(report_id)
            / filename
        )


def render_markdown_report(payload: MarkdownReportPayload) -> str:
    """Render a deterministic technical Markdown report from stored analysis data."""
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
        "",
        "## Top Findings",
        "",
    ]
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


def render_html_executive_report(payload: MarkdownReportPayload) -> str:
    """Render a deterministic, escaped executive HTML report."""
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


def _finding_payload(finding: Finding) -> MarkdownReportFinding:
    decision_guidance = _decision_guidance(finding)
    return MarkdownReportFinding(
        operational_rank=finding.operational_rank,
        cve_id=finding.cve_id,
        priority=str(finding.priority),
        status=str(finding.status),
        risk_score=finding.risk_score,
        epss=finding.epss,
        cvss_base_score=finding.cvss_base_score,
        in_kev=finding.in_kev,
        asset=_asset_label(finding),
        component=_component_label(finding),
        rationale=finding.rationale,
        recommended_action=finding.recommended_action,
        data_quality_confidence=_data_quality_confidence(finding),
        decision_statement=_decision_text(
            decision_guidance,
            "decision_statement",
            fallback=finding.recommended_action,
        ),
        business_impact=_decision_text(decision_guidance, "business_impact"),
        decision_sla=_decision_sla(decision_guidance),
        data_quality_flags=_data_quality_flags(finding),
    )


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
    return flags


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

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
REPORT_FILENAME_TECHNICAL_MARKDOWN = "technical-report.md"
REPORT_CONTENT_TYPE_MARKDOWN = "text/markdown; charset=utf-8"
REPORT_SUPPORTED_RUN_STATUSES = {
    AnalysisRunStatus.COMPLETED,
    AnalysisRunStatus.COMPLETED_WITH_ERRORS,
    AnalysisRunStatus.SUCCEEDED,
}
PRIORITY_LABELS = ("Critical", "High", "Medium", "Low")
MARKDOWN_SPECIAL_CHARS = "\\`*_{}[]()!"


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
        if run.status not in REPORT_SUPPORTED_RUN_STATUSES:
            raise ReportGenerationError(
                f"Analysis run must be completed before reporting; current status is {run.status}."
            )

        report_id = uuid.uuid4()
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
        content = render_markdown_report(payload)
        report_path = self._report_path(
            project_id=project.id,
            run_id=run.id,
            report_id=report_id,
        )
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(content, encoding="utf-8")
        content_bytes = content.encode("utf-8")
        sha256 = hashlib.sha256(content_bytes).hexdigest()
        return ReportRepository(self.session).create_report(
            report_id=report_id,
            project_id=project.id,
            analysis_run_id=run.id,
            kind=REPORT_KIND_TECHNICAL_MARKDOWN,
            format="markdown",
            filename=REPORT_FILENAME_TECHNICAL_MARKDOWN,
            content_type=REPORT_CONTENT_TYPE_MARKDOWN,
            path=str(report_path),
            sha256=sha256,
            size_bytes=len(content_bytes),
            metadata_json={
                "generated_at": generated_at.isoformat(),
                "project_id": str(project.id),
                "analysis_run_id": str(run.id),
                "provider_snapshot_id": str(run.provider_snapshot_id)
                if run.provider_snapshot_id is not None
                else None,
                "finding_count": len(findings),
                "format": "markdown",
                "kind": REPORT_KIND_TECHNICAL_MARKDOWN,
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
    ) -> Path:
        return (
            self.settings.report_dir_path
            / str(project_id)
            / str(run_id)
            / str(report_id)
            / REPORT_FILENAME_TECHNICAL_MARKDOWN
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


def _finding_payload(finding: Finding) -> MarkdownReportFinding:
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

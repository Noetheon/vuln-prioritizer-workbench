"""Report and evidence artifact generation for Workbench analysis runs."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Literal

from sqlalchemy.orm import Session

from vuln_prioritizer.cli_support.report_io import write_evidence_bundle
from vuln_prioritizer.db.models import EvidenceBundle, Report
from vuln_prioritizer.db.repositories import WorkbenchRepository
from vuln_prioritizer.reporter import generate_html_report
from vuln_prioritizer.reporting_payloads import generate_summary_markdown
from vuln_prioritizer.workbench_config import WorkbenchSettings

ReportFormat = Literal["json", "markdown", "html"]


class WorkbenchReportError(RuntimeError):
    """Raised when a Workbench artifact cannot be generated."""


def create_run_report(
    *,
    session: Session,
    settings: WorkbenchSettings,
    analysis_run_id: str,
    report_format: ReportFormat,
) -> Report:
    """Create a JSON, Markdown, or HTML report for a completed run."""
    repo = WorkbenchRepository(session)
    run = repo.get_analysis_run(analysis_run_id)
    if run is None:
        raise WorkbenchReportError(f"Analysis run not found: {analysis_run_id}.")
    payload = _analysis_payload(run.summary_json)
    run_dir = _run_report_dir(settings, run.id)

    if report_format == "json":
        content = json.dumps(payload, indent=2, sort_keys=True)
        output_path = run_dir / "analysis.json"
        kind = "analysis-json"
    elif report_format == "markdown":
        content = generate_summary_markdown(payload)
        output_path = run_dir / "summary.md"
        kind = "markdown-summary"
    elif report_format == "html":
        content = generate_html_report(payload)
        output_path = run_dir / "executive-report.html"
        kind = "html-report"
    else:
        raise WorkbenchReportError(f"Unsupported report format: {report_format}.")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(content, encoding="utf-8")
    report = repo.add_report(
        project_id=run.project_id,
        analysis_run_id=run.id,
        kind=kind,
        format=report_format,
        path=str(output_path),
        sha256=_sha256(output_path),
    )
    session.flush()
    return report


def create_run_evidence_bundle(
    *,
    session: Session,
    settings: WorkbenchSettings,
    analysis_run_id: str,
) -> EvidenceBundle:
    """Create an evidence ZIP bundle for a completed run."""
    repo = WorkbenchRepository(session)
    run = repo.get_analysis_run(analysis_run_id)
    if run is None:
        raise WorkbenchReportError(f"Analysis run not found: {analysis_run_id}.")

    payload = _analysis_payload(run.summary_json)
    run_dir = _run_report_dir(settings, run.id)
    analysis_path = run_dir / "analysis.json"
    if not analysis_path.exists():
        analysis_path.parent.mkdir(parents=True, exist_ok=True)
        analysis_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    bundle_path = run_dir / "evidence-bundle.zip"
    manifest = write_evidence_bundle(
        analysis_path=analysis_path,
        output_path=bundle_path,
        payload=payload,
        include_input_copy=True,
    )
    bundle = repo.add_evidence_bundle(
        project_id=run.project_id,
        analysis_run_id=run.id,
        path=str(bundle_path),
        sha256=_sha256(bundle_path),
        manifest_json=manifest.model_dump(),
    )
    session.flush()
    return bundle


def _analysis_payload(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or "metadata" not in value or "findings" not in value:
        raise WorkbenchReportError("Analysis run does not contain a report payload.")
    return value


def _run_report_dir(settings: WorkbenchSettings, run_id: str) -> Path:
    return settings.report_dir / run_id


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

"""Report and evidence artifact generation for Workbench analysis runs."""

from __future__ import annotations

import csv
import hashlib
import json
from io import StringIO
from pathlib import Path
from typing import Any, Literal

from sqlalchemy.orm import Session

from vuln_prioritizer.cli_support.report_io import verify_evidence_bundle, write_evidence_bundle
from vuln_prioritizer.db.models import EvidenceBundle, Report
from vuln_prioritizer.db.repositories import WorkbenchRepository
from vuln_prioritizer.reporter import generate_html_report
from vuln_prioritizer.reporting_payloads import generate_summary_markdown
from vuln_prioritizer.workbench_config import WorkbenchSettings

ReportFormat = Literal["json", "markdown", "html", "csv"]


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
    elif report_format == "csv":
        content = generate_findings_csv(payload)
        output_path = run_dir / "findings.csv"
        kind = "findings-csv"
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


def verify_run_evidence_bundle(
    *,
    session: Session,
    settings: WorkbenchSettings,
    bundle_id: str,
) -> dict[str, Any]:
    """Verify a stored Workbench evidence bundle and return JSON-ready results."""
    repo = WorkbenchRepository(session)
    bundle = repo.get_evidence_bundle(bundle_id)
    if bundle is None:
        raise WorkbenchReportError(f"Evidence bundle not found: {bundle_id}.")
    bundle_path = _resolve_stored_artifact(
        bundle.path,
        settings=settings,
        expected_sha256=bundle.sha256,
    )
    metadata, summary, items = verify_evidence_bundle(bundle_path)
    return {
        "metadata": metadata.model_dump(),
        "summary": summary.model_dump(),
        "items": [item.model_dump() for item in items],
    }


def generate_findings_csv(report_payload: dict[str, Any]) -> str:
    """Render a spreadsheet-safe CSV export for Workbench findings."""
    output = StringIO()
    fieldnames = [
        "cve_id",
        "priority",
        "status",
        "kev",
        "epss",
        "cvss",
        "component",
        "asset",
        "owner",
        "service",
        "vex_statuses",
        "suppressed_by_vex",
        "under_investigation",
        "waived",
        "waiver_status",
        "waiver_owner",
        "waiver_expires_on",
        "waiver_review_on",
        "attack_mapped",
        "attack_techniques",
        "recommended_action",
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames, lineterminator="\n")
    writer.writeheader()
    for finding in report_payload.get("findings", []):
        if not isinstance(finding, dict):
            continue
        raw_provenance = finding.get("provenance")
        provenance: dict[str, Any] = raw_provenance if isinstance(raw_provenance, dict) else {}
        writer.writerow(
            {
                "cve_id": _csv_safe_cell(finding.get("cve_id")),
                "priority": _csv_safe_cell(finding.get("priority_label")),
                "status": _csv_safe_cell(_finding_status_label(finding)),
                "kev": "yes" if finding.get("in_kev") else "no",
                "epss": _csv_safe_cell(finding.get("epss")),
                "cvss": _csv_safe_cell(finding.get("cvss_base_score")),
                "component": _csv_safe_cell(_first_value(provenance.get("components"))),
                "asset": _csv_safe_cell(_first_value(provenance.get("asset_ids"))),
                "owner": _csv_safe_cell(_first_occurrence_value(provenance, "asset_owner")),
                "service": _csv_safe_cell(
                    _first_occurrence_value(provenance, "asset_business_service")
                ),
                "vex_statuses": _csv_safe_cell(_vex_statuses_label(provenance)),
                "suppressed_by_vex": "yes" if finding.get("suppressed_by_vex") else "no",
                "under_investigation": "yes" if finding.get("under_investigation") else "no",
                "waived": "yes" if finding.get("waived") else "no",
                "waiver_status": _csv_safe_cell(finding.get("waiver_status")),
                "waiver_owner": _csv_safe_cell(finding.get("waiver_owner")),
                "waiver_expires_on": _csv_safe_cell(finding.get("waiver_expires_on")),
                "waiver_review_on": _csv_safe_cell(finding.get("waiver_review_on")),
                "attack_mapped": "yes" if finding.get("attack_mapped") else "no",
                "attack_techniques": _csv_safe_cell(
                    ";".join(str(item) for item in finding.get("attack_techniques", []))
                ),
                "recommended_action": _csv_safe_cell(finding.get("recommended_action")),
            }
        )
    return output.getvalue()


def _analysis_payload(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or "metadata" not in value or "findings" not in value:
        raise WorkbenchReportError("Analysis run does not contain a report payload.")
    return value


def _resolve_stored_artifact(
    value: str,
    *,
    settings: WorkbenchSettings,
    expected_sha256: str,
) -> Path:
    resolved = Path(value).resolve(strict=False)
    report_root = settings.report_dir.resolve(strict=False)
    if not resolved.is_relative_to(report_root) or not resolved.is_file():
        raise WorkbenchReportError("Evidence bundle artifact not found.")
    actual_sha256 = _sha256(resolved)
    if actual_sha256 != expected_sha256:
        raise WorkbenchReportError("Evidence bundle checksum mismatch.")
    return resolved


def _csv_safe_cell(value: object) -> str:
    text = "" if value is None else str(value)
    if text.startswith(("\t", "\r", "\n")) or text.lstrip().startswith(("=", "+", "-", "@")):
        return "'" + text
    return text


def _first_value(value: object) -> str:
    if isinstance(value, list) and value:
        return str(value[0])
    return ""


def _first_occurrence_value(provenance: dict[str, Any], field: str) -> str:
    occurrences = provenance.get("occurrences")
    if not isinstance(occurrences, list):
        return ""
    for occurrence in occurrences:
        if not isinstance(occurrence, dict):
            continue
        value = occurrence.get(field)
        if value:
            return str(value)
    return ""


def _finding_status_label(finding: dict[str, Any]) -> str:
    if finding.get("suppressed_by_vex"):
        return "suppressed"
    if finding.get("waived"):
        return "accepted"
    return "open"


def _vex_statuses_label(provenance: dict[str, Any]) -> str:
    raw_statuses = provenance.get("vex_statuses")
    if not isinstance(raw_statuses, dict):
        return ""
    return ";".join(f"{status}:{count}" for status, count in sorted(raw_statuses.items()))


def _run_report_dir(settings: WorkbenchSettings, run_id: str) -> Path:
    return settings.report_dir / run_id


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

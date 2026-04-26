"""Report and evidence artifact generation for Workbench analysis runs."""

from __future__ import annotations

import csv
import hashlib
import json
from io import StringIO
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

from sqlalchemy.orm import Session

from vuln_prioritizer.cli_support.report_io import verify_evidence_bundle, write_evidence_bundle
from vuln_prioritizer.db.models import EvidenceBundle, Report
from vuln_prioritizer.db.repositories import WorkbenchRepository
from vuln_prioritizer.reporter import generate_html_report
from vuln_prioritizer.reporting_payloads import generate_summary_markdown
from vuln_prioritizer.workbench_config import WorkbenchSettings

ReportFormat = Literal["json", "markdown", "html", "csv", "sarif"]


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
    payload = _analysis_payload_with_current_lifecycle(repo, run.summary_json, run.project_id)
    run_dir = _run_report_dir(settings, run.id)

    if report_format == "json":
        content = json.dumps(payload, indent=2, sort_keys=True)
        output_path = _unique_run_artifact_path(run_dir, "analysis", "json")
        kind = "analysis-json"
    elif report_format == "markdown":
        content = generate_summary_markdown(payload)
        output_path = _unique_run_artifact_path(run_dir, "summary", "md")
        kind = "markdown-summary"
    elif report_format == "html":
        content = generate_html_report(payload)
        output_path = _unique_run_artifact_path(run_dir, "executive-report", "html")
        kind = "html-report"
    elif report_format == "csv":
        content = generate_findings_csv(payload)
        output_path = _unique_run_artifact_path(run_dir, "findings", "csv")
        kind = "findings-csv"
    elif report_format == "sarif":
        content = generate_workbench_sarif(payload)
        output_path = _unique_run_artifact_path(run_dir, "results", "sarif")
        kind = "sarif-results"
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

    payload = _analysis_payload_with_current_lifecycle(repo, run.summary_json, run.project_id)
    run_dir = _run_report_dir(settings, run.id)
    analysis_path = _unique_run_artifact_path(run_dir, "evidence-analysis", "json")
    analysis_path.parent.mkdir(parents=True, exist_ok=True)
    analysis_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    bundle_path = _unique_run_artifact_path(run_dir, "evidence-bundle", "zip")
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
        "defensive_context_sources",
        "recommended_action",
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames, lineterminator="\n")
    writer.writeheader()
    for finding in report_payload.get("findings", []):
        if not isinstance(finding, dict):
            continue
        raw_provenance = finding.get("provenance")
        provenance: dict[str, Any] = raw_provenance if isinstance(raw_provenance, dict) else {}
        defensive_contexts = [
            item for item in finding.get("defensive_contexts", []) if isinstance(item, dict)
        ]
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
                "defensive_context_sources": _csv_safe_cell(
                    ";".join(
                        sorted(
                            {
                                str(item.get("source")).upper()
                                for item in defensive_contexts
                                if item.get("source")
                            }
                        )
                    )
                ),
                "recommended_action": _csv_safe_cell(finding.get("recommended_action")),
            }
        )
    return output.getvalue()


def generate_workbench_sarif(report_payload: dict[str, Any]) -> str:
    """Render SARIF from a stored Workbench analysis payload."""
    level_map = {
        "Critical": "error",
        "High": "error",
        "Medium": "warning",
        "Low": "note",
    }
    raw_metadata = report_payload.get("metadata")
    metadata: dict[str, Any] = raw_metadata if isinstance(raw_metadata, dict) else {}
    input_path = str(
        metadata.get("input_path") or metadata.get("input_format") or "workbench-input"
    )
    results: list[dict[str, Any]] = []
    for finding in report_payload.get("findings", []):
        if not isinstance(finding, dict):
            continue
        priority = str(finding.get("priority_label") or "Unprioritized")
        cve_id = str(finding.get("cve_id") or "CVE-UNKNOWN")
        provenance = (
            finding.get("provenance") if isinstance(finding.get("provenance"), dict) else {}
        )
        paths = provenance.get("affected_paths") if isinstance(provenance, dict) else []
        uri = str(paths[0]) if isinstance(paths, list) and paths else input_path
        defensive_contexts = [
            item for item in finding.get("defensive_contexts", []) if isinstance(item, dict)
        ]
        results.append(
            {
                "ruleId": f"vuln-prioritizer/{priority.lower()}",
                "level": level_map.get(priority, "note"),
                "message": {
                    "text": (
                        f"{cve_id}: {priority} priority based on CVSS/EPSS/KEV, "
                        "asset context, and optional Workbench governance layers."
                    )
                },
                "properties": {
                    "cve": cve_id,
                    "priority": priority,
                    "cvss": finding.get("cvss_base_score"),
                    "epss": finding.get("epss"),
                    "in_kev": bool(finding.get("in_kev")),
                    "attack_relevance": finding.get("attack_relevance"),
                    "defensive_context_sources": sorted(
                        {
                            str(item.get("source"))
                            for item in defensive_contexts
                            if item.get("source")
                        }
                    ),
                    "defensive_context_count": len(defensive_contexts),
                    "suppressed_by_vex": bool(finding.get("suppressed_by_vex")),
                    "waived": bool(finding.get("waived")),
                    "waiver_status": finding.get("waiver_status"),
                    "status": _finding_status_label(finding),
                },
                "partialFingerprints": {
                    "vuln-prioritizer-workbench/v1": _workbench_sarif_fingerprint(
                        cve_id=cve_id,
                        uri=uri,
                        finding=finding,
                    ),
                },
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}}}],
            }
        )
    payload = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "vuln-prioritizer-workbench",
                        "version": str(metadata.get("schema_version") or "1.1.0"),
                        "rules": _workbench_sarif_rules(),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def _workbench_sarif_rules() -> list[dict[str, Any]]:
    return [
        {
            "id": f"vuln-prioritizer/{priority.lower()}",
            "name": f"{priority} prioritized vulnerability",
            "shortDescription": {"text": f"{priority} Workbench prioritization result."},
            "fullDescription": {
                "text": (
                    "Known CVE prioritized from CVSS, EPSS, and CISA KEV with explicit "
                    "Workbench context for assets, VEX, waivers, remediation, and ATT&CK."
                )
            },
            "properties": {"priority": priority},
        }
        for priority in ("Critical", "High", "Medium", "Low")
    ]


def _workbench_sarif_fingerprint(
    *,
    cve_id: str,
    uri: str,
    finding: dict[str, Any],
) -> str:
    provenance = finding.get("provenance") if isinstance(finding.get("provenance"), dict) else {}
    components = provenance.get("components") if isinstance(provenance, dict) else []
    assets = provenance.get("asset_ids") if isinstance(provenance, dict) else []
    identity = "|".join(
        [
            cve_id,
            uri,
            ",".join(str(item) for item in components if item)
            if isinstance(components, list)
            else "",
            ",".join(str(item) for item in assets if item) if isinstance(assets, list) else "",
        ]
    )
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()


def _analysis_payload(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or "metadata" not in value or "findings" not in value:
        raise WorkbenchReportError("Analysis run does not contain a report payload.")
    return value


def _analysis_payload_with_current_lifecycle(
    repo: WorkbenchRepository,
    value: object,
    project_id: str,
) -> dict[str, Any]:
    payload = json.loads(json.dumps(_analysis_payload(value)))
    findings = payload.get("findings")
    if not isinstance(findings, list):
        return payload
    current_findings = repo.list_project_findings(project_id)
    current_by_id = {finding.id: finding for finding in current_findings}
    current_by_identity = {
        _finding_identity_from_model(finding): finding for finding in current_findings
    }
    for finding_payload in findings:
        if not isinstance(finding_payload, dict):
            continue
        workbench_finding_id = str(finding_payload.get("workbench_finding_id") or "")
        current = current_by_id.get(workbench_finding_id)
        if current is None:
            current = current_by_identity.get(_finding_identity_from_payload(finding_payload))
        if current is None:
            continue
        finding_payload["status"] = current.status
        finding_payload["status_history"] = [
            {
                "id": item.id,
                "finding_id": item.finding_id,
                "previous_status": item.previous_status,
                "new_status": item.new_status,
                "actor": item.actor,
                "reason": item.reason,
                "created_at": item.created_at.isoformat(),
            }
            for item in current.status_history
        ]
    return payload


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
    if finding.get("status"):
        return str(finding["status"])
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


def _unique_run_artifact_path(run_dir: Path, stem: str, suffix: str) -> Path:
    return run_dir / f"{stem}-{uuid4().hex}.{suffix}"


def _finding_identity_from_model(finding: Any) -> tuple[str, str, str, str]:
    component = finding.component
    asset = finding.asset
    return (
        str(finding.cve_id or ""),
        str(component.name if component else ""),
        str(component.version if component and component.version else ""),
        str(asset.asset_id if asset else ""),
    )


def _finding_identity_from_payload(finding: dict[str, Any]) -> tuple[str, str, str, str]:
    provenance = finding.get("provenance") if isinstance(finding.get("provenance"), dict) else {}
    components = provenance.get("components") if isinstance(provenance, dict) else []
    asset_ids = provenance.get("asset_ids") if isinstance(provenance, dict) else []
    occurrences = provenance.get("occurrences") if isinstance(provenance, dict) else []
    component_name = _first_list_item(components)
    asset_id = _first_list_item(asset_ids)
    component_version = ""
    if isinstance(occurrences, list):
        for occurrence in occurrences:
            if not isinstance(occurrence, dict):
                continue
            component_name = component_name or str(occurrence.get("component_name") or "")
            component_version = str(occurrence.get("component_version") or "")
            asset_id = asset_id or str(occurrence.get("asset_id") or "")
            break
    return (str(finding.get("cve_id") or ""), component_name, component_version, asset_id)


def _first_list_item(value: object) -> str:
    if isinstance(value, list) and value:
        return str(value[0] or "")
    return ""


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

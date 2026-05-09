"""Machine-readable Workbench report renderers."""

from __future__ import annotations

import csv
import json
from io import StringIO

from app.services.report_contracts import (
    ANALYSIS_RESULT_SCHEMA,
    ANALYSIS_RESULT_SCHEMA_VERSION,
    CSV_FINDINGS_COLUMNS,
)
from app.services.report_formatting import csv_safe_cell as _csv_safe_cell
from app.services.report_formatting import format_number as _format_number
from app.services.report_formatting import iso_datetime as _iso_datetime
from app.services.report_models import MarkdownReportPayload
from app.services.report_projection import _analysis_finding, _analysis_provider_snapshot
from app.services.report_renderer_common import (
    _boolish_signal,
    _decision_guidance_from_payload,
    _list_value,
    _priority_label,
    _redacted_bundle_payload,
    _vex_statuses_label,
)


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


__all__ = [
    "render_analysis_result_json",
    "render_findings_csv",
]

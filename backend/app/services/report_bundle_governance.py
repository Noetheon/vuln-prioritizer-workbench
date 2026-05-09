"""Governance artifacts for Workbench evidence bundles."""

from __future__ import annotations

from typing import Any

from app.services.report_bundle_archive import _json_bytes
from app.services.report_bundle_governance_rows import (
    _asset_context_rows,
    _governance_finding_row,
)
from app.services.report_contracts import (
    REPORT_FILENAME_GOVERNANCE_ASSET_CONTEXT,
    REPORT_FILENAME_GOVERNANCE_DETECTION_COVERAGE,
    REPORT_FILENAME_GOVERNANCE_ROLLUPS,
    REPORT_FILENAME_GOVERNANCE_VEX,
    REPORT_FILENAME_GOVERNANCE_WAIVERS,
    REPORT_KIND_GOVERNANCE_ASSET_CONTEXT,
    REPORT_KIND_GOVERNANCE_DETECTION_COVERAGE,
    REPORT_KIND_GOVERNANCE_ROLLUPS,
    REPORT_KIND_GOVERNANCE_VEX,
    REPORT_KIND_GOVERNANCE_WAIVERS,
)
from app.services.report_formatting import dict_value as _dict_value
from app.services.report_formatting import iso_datetime as _iso_datetime
from app.services.report_models import MarkdownReportPayload
from app.services.report_renderer_common import (
    _boolish_signal,
    _dict_list,
    _governance_vex_summary,
    _vex_statuses_label,
)


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


__all__ = [
    "_asset_context_rows",
    "_governance_asset_context_export",
    "_governance_bundle_entries",
    "_governance_detection_coverage_export",
    "_governance_finding_row",
    "_governance_rollups_export",
    "_governance_vex_export",
    "_governance_waivers_export",
]

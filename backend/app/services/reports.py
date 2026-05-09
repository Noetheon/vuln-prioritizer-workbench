"""Workbench report generation services."""

from __future__ import annotations

import json

from sqlmodel import Session

from app.core.config import Settings
from app.models import AnalysisRun, Project, Report
from app.services import report_models as _report_models
from app.services import report_renderers as _report_renderers
from app.services.report_contracts import (
    EVIDENCE_BUNDLE_MANIFEST_SCHEMA_VERSION,
    REPORT_CONTENT_TYPE_CSV,
    REPORT_CONTENT_TYPE_HTML,
    REPORT_CONTENT_TYPE_JSON,
    REPORT_CONTENT_TYPE_MARKDOWN,
    REPORT_CONTENT_TYPE_SARIF,
    REPORT_CONTENT_TYPE_ZIP,
    REPORT_FILENAME_ANALYSIS_JSON,
    REPORT_FILENAME_ATTACK_NAVIGATOR,
    REPORT_FILENAME_EVIDENCE_BUNDLE,
    REPORT_FILENAME_EXECUTIVE_HTML,
    REPORT_FILENAME_FINDINGS_CSV,
    REPORT_FILENAME_SARIF_RESULTS,
    REPORT_FILENAME_TECHNICAL_MARKDOWN,
    REPORT_KIND_ANALYSIS_JSON,
    REPORT_KIND_ATTACK_NAVIGATOR,
    REPORT_KIND_EVIDENCE_BUNDLE,
    REPORT_KIND_EXECUTIVE_HTML,
    REPORT_KIND_FINDINGS_CSV,
    REPORT_KIND_SARIF_RESULTS,
    REPORT_KIND_TECHNICAL_MARKDOWN,
)
from app.services.report_models import (
    MarkdownReportPayload as MarkdownReportPayload,
)
from app.services.report_models import (
    ReportGenerationError,
)
from app.services.report_renderers import (
    render_analysis_result_json,
    render_evidence_bundle_zip,
    render_findings_csv,
    render_html_executive_report,
    render_markdown_report,
)
from app.services.report_sarif import render_sarif_report
from app.services.report_service_attack import attack_navigator_layer, run_attack_contexts
from app.services.report_service_payload import (
    REPORT_SUPPORTED_RUN_STATUSES,
    build_report_payload,
)
from app.services.report_service_persistence import (
    persist_binary_report,
    persist_text_report,
)

MarkdownProviderSnapshot = _report_models.MarkdownProviderSnapshot
MarkdownReportFinding = _report_models.MarkdownReportFinding
ReportVerificationError = _report_models.ReportVerificationError
EXECUTIVE_REPORT_CSS: str = _report_renderers.EXECUTIVE_REPORT_CSS
verify_evidence_bundle_zip = _report_renderers.verify_evidence_bundle_zip

__all__ = [
    "EXECUTIVE_REPORT_CSS",
    "MarkdownProviderSnapshot",
    "MarkdownReportFinding",
    "MarkdownReportPayload",
    "ReportGenerationError",
    "ReportService",
    "ReportVerificationError",
    "REPORT_SUPPORTED_RUN_STATUSES",
    "render_analysis_result_json",
    "render_evidence_bundle_zip",
    "render_findings_csv",
    "render_html_executive_report",
    "render_markdown_report",
    "render_sarif_report",
    "verify_evidence_bundle_zip",
]


class ReportService:
    """Generate and persist report artifacts for Workbench analysis runs."""

    def __init__(self, session: Session, settings: Settings) -> None:
        self.session = session
        self.settings = settings

    def create_markdown_report(self, *, run: AnalysisRun, project: Project) -> Report:
        """Generate a Markdown technical report and persist its metadata."""
        payload, findings, generated_at = build_report_payload(
            self.session,
            run=run,
            project=project,
        )
        content = render_markdown_report(payload)
        return persist_text_report(
            self.session,
            self.settings,
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
        payload, findings, generated_at = build_report_payload(
            self.session,
            run=run,
            project=project,
        )
        content = render_html_executive_report(payload)
        return persist_text_report(
            self.session,
            self.settings,
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

    def create_analysis_json_export(self, *, run: AnalysisRun, project: Project) -> Report:
        """Generate a stable analysis-result.v1 JSON export and persist its metadata."""
        payload, findings, generated_at = build_report_payload(
            self.session,
            run=run,
            project=project,
        )
        content = render_analysis_result_json(payload)
        return persist_text_report(
            self.session,
            self.settings,
            run=run,
            project=project,
            generated_at=generated_at,
            finding_count=len(findings),
            provider_snapshot_id=run.provider_snapshot_id,
            content=content,
            kind=REPORT_KIND_ANALYSIS_JSON,
            report_format="json",
            filename=REPORT_FILENAME_ANALYSIS_JSON,
            content_type=REPORT_CONTENT_TYPE_JSON,
        )

    def create_findings_csv_export(self, *, run: AnalysisRun, project: Project) -> Report:
        """Generate a stable findings CSV export and persist its metadata."""
        payload, findings, generated_at = build_report_payload(
            self.session,
            run=run,
            project=project,
        )
        content = render_findings_csv(payload)
        return persist_text_report(
            self.session,
            self.settings,
            run=run,
            project=project,
            generated_at=generated_at,
            finding_count=len(findings),
            provider_snapshot_id=run.provider_snapshot_id,
            content=content,
            kind=REPORT_KIND_FINDINGS_CSV,
            report_format="csv",
            filename=REPORT_FILENAME_FINDINGS_CSV,
            content_type=REPORT_CONTENT_TYPE_CSV,
        )

    def create_attack_navigator_layer(
        self,
        *,
        run: AnalysisRun,
        project: Project,
        filter_value: str = "all",
    ) -> Report:
        """Generate an ATT&CK Navigator layer JSON report artifact."""
        _payload, findings, generated_at = build_report_payload(
            self.session,
            run=run,
            project=project,
        )
        layer = attack_navigator_layer(
            run=run,
            project=project,
            findings=findings,
            attack_contexts=run_attack_contexts(self.session, run),
            generated_at=generated_at,
            filter_value=filter_value,
            include_empty=True,
        )
        if layer is None:
            raise ReportGenerationError("ATT&CK Navigator layer generation failed.")
        content = json.dumps(layer, indent=2, sort_keys=True) + "\n"
        return persist_text_report(
            self.session,
            self.settings,
            run=run,
            project=project,
            generated_at=generated_at,
            finding_count=len(findings),
            provider_snapshot_id=run.provider_snapshot_id,
            content=content,
            kind=REPORT_KIND_ATTACK_NAVIGATOR,
            report_format="attack-navigator",
            filename=REPORT_FILENAME_ATTACK_NAVIGATOR,
            content_type=REPORT_CONTENT_TYPE_JSON,
            extra_metadata={
                "attack_filter": filter_value,
                "navigator_version": layer.get("version"),
                "technique_count": len(layer.get("techniques", [])),
            },
        )

    def create_sarif_report(self, *, run: AnalysisRun, project: Project) -> Report:
        """Generate a SARIF 2.1.0 results report and persist its metadata."""
        payload, findings, generated_at = build_report_payload(
            self.session,
            run=run,
            project=project,
        )
        sarif_payload = render_sarif_report(payload)
        content = json.dumps(sarif_payload, indent=2, sort_keys=True) + "\n"
        results = sarif_payload["runs"][0]["results"]
        rules = sarif_payload["runs"][0]["tool"]["driver"]["rules"]
        return persist_text_report(
            self.session,
            self.settings,
            run=run,
            project=project,
            generated_at=generated_at,
            finding_count=len(findings),
            provider_snapshot_id=run.provider_snapshot_id,
            content=content,
            kind=REPORT_KIND_SARIF_RESULTS,
            report_format="sarif",
            filename=REPORT_FILENAME_SARIF_RESULTS,
            content_type=REPORT_CONTENT_TYPE_SARIF,
            extra_metadata={
                "sarif_version": sarif_payload["version"],
                "rule_count": len(rules),
                "result_count": len(results),
            },
        )

    def create_evidence_bundle(self, *, run: AnalysisRun, project: Project) -> Report:
        """Generate a verifiable evidence ZIP bundle and persist its metadata."""
        payload, findings, generated_at = build_report_payload(
            self.session,
            run=run,
            project=project,
        )
        attack_layer = attack_navigator_layer(
            run=run,
            project=project,
            findings=findings,
            attack_contexts=run_attack_contexts(self.session, run),
            generated_at=generated_at,
            filter_value="all",
            include_empty=False,
        )
        bundle_bytes, manifest = render_evidence_bundle_zip(
            payload,
            attack_navigator_layer=attack_layer,
        )
        return persist_binary_report(
            self.session,
            self.settings,
            run=run,
            project=project,
            generated_at=generated_at,
            finding_count=len(findings),
            provider_snapshot_id=run.provider_snapshot_id,
            content=bundle_bytes,
            kind=REPORT_KIND_EVIDENCE_BUNDLE,
            report_format="zip",
            filename=REPORT_FILENAME_EVIDENCE_BUNDLE,
            content_type=REPORT_CONTENT_TYPE_ZIP,
            extra_metadata={
                "manifest": manifest,
                "manifest_schema_version": EVIDENCE_BUNDLE_MANIFEST_SCHEMA_VERSION,
            },
        )

"""Workbench report generation services."""

from __future__ import annotations

import json
import uuid
from collections.abc import Callable

from sqlmodel import Session

from app.core.config import Settings
from app.models import AnalysisRun, Project, Report, WorkflowRun, WorkflowRunKind, WorkflowRunStatus
from app.repositories import WorkflowRepository
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
    MarkdownProviderSnapshot,
    MarkdownReportFinding,
    MarkdownReportPayload,
    ReportGenerationError,
    ReportVerificationError,
)
from app.services.report_renderers import (
    EXECUTIVE_REPORT_CSS,
    render_analysis_result_json,
    render_evidence_bundle_zip,
    render_findings_csv,
    render_html_executive_report,
    render_markdown_report,
    verify_evidence_bundle_zip,
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
from app.services.workflow_execution import WorkflowExecutionContext

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
        """Initialize a new instance of ReportService."""
        self.session = session
        self.settings = settings

    def create_markdown_report(self, *, run: AnalysisRun, project: Project) -> Report:
        """Generate a Markdown technical report and persist its metadata."""
        return self._create_report_with_workflow(
            run=run,
            project=project,
            report_format="markdown",
            report_kind=REPORT_KIND_TECHNICAL_MARKDOWN,
            create_report=lambda: self._create_markdown_report(run=run, project=project),
        )

    def _create_markdown_report(self, *, run: AnalysisRun, project: Project) -> Report:
        """Generate a Markdown technical report without workflow bookkeeping."""
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
        return self._create_report_with_workflow(
            run=run,
            project=project,
            report_format="html",
            report_kind=REPORT_KIND_EXECUTIVE_HTML,
            create_report=lambda: self._create_html_report(run=run, project=project),
        )

    def _create_html_report(self, *, run: AnalysisRun, project: Project) -> Report:
        """Generate an HTML executive report without workflow bookkeeping."""
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
        return self._create_report_with_workflow(
            run=run,
            project=project,
            report_format="json",
            report_kind=REPORT_KIND_ANALYSIS_JSON,
            create_report=lambda: self._create_analysis_json_export(run=run, project=project),
        )

    def _create_analysis_json_export(self, *, run: AnalysisRun, project: Project) -> Report:
        """Generate an analysis-result.v1 JSON export without workflow bookkeeping."""
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
        return self._create_report_with_workflow(
            run=run,
            project=project,
            report_format="csv",
            report_kind=REPORT_KIND_FINDINGS_CSV,
            create_report=lambda: self._create_findings_csv_export(run=run, project=project),
        )

    def _create_findings_csv_export(self, *, run: AnalysisRun, project: Project) -> Report:
        """Generate a findings CSV export without workflow bookkeeping."""
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
        return self._create_report_with_workflow(
            run=run,
            project=project,
            report_format="attack-navigator",
            report_kind=REPORT_KIND_ATTACK_NAVIGATOR,
            attack_filter=filter_value,
            create_report=lambda: self._create_attack_navigator_layer(
                run=run,
                project=project,
                filter_value=filter_value,
            ),
        )

    def _create_attack_navigator_layer(
        self,
        *,
        run: AnalysisRun,
        project: Project,
        filter_value: str = "all",
    ) -> Report:
        """Generate an ATT&CK Navigator layer without workflow bookkeeping."""
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
        return self._create_report_with_workflow(
            run=run,
            project=project,
            report_format="sarif",
            report_kind=REPORT_KIND_SARIF_RESULTS,
            create_report=lambda: self._create_sarif_report(run=run, project=project),
        )

    def _create_sarif_report(self, *, run: AnalysisRun, project: Project) -> Report:
        """Generate a SARIF report without workflow bookkeeping."""
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
        return self._create_report_with_workflow(
            run=run,
            project=project,
            report_format="zip",
            report_kind=REPORT_KIND_EVIDENCE_BUNDLE,
            create_report=lambda: self._create_evidence_bundle(run=run, project=project),
        )

    def enqueue_report_generation(
        self,
        *,
        run: AnalysisRun,
        project: Project,
        report_format: str,
        attack_filter: str = "all",
        max_retries: int = 2,
    ) -> WorkflowRun:
        """Create a queued durable workflow for report generation."""
        if run.status not in REPORT_SUPPORTED_RUN_STATUSES:
            raise ReportGenerationError(
                f"Analysis run must be completed before reporting; current status is {run.status}."
            )
        report_kind, _create_report = self._report_generation_target(
            run=run,
            project=project,
            report_format=report_format,
            attack_filter=attack_filter,
        )
        metadata: dict[str, object] = {
            "report_format": report_format,
            "report_kind": report_kind,
            "analysis_run_id": str(run.id),
            "attack_filter": attack_filter,
        }
        return WorkflowRepository(self.session).create_workflow_run(
            kind=WorkflowRunKind.REPORT_GENERATION,
            title=f"Generate {report_format} report",
            handler="app.services.reports.ReportService.create_report_for_workflow",
            project_id=project.id,
            analysis_run_id=run.id,
            status=WorkflowRunStatus.PENDING,
            execution_mode="worker",
            current_stage="queued",
            progress_current=0,
            progress_total=3,
            metadata_json=metadata,
            payload_json={
                "run_id": str(run.id),
                "format": report_format,
                "attack_filter": attack_filter,
            },
            max_retries=max_retries,
        )

    def create_report_for_workflow(
        self,
        *,
        run: AnalysisRun,
        project: Project,
        workflow_id: uuid.UUID,
        report_format: str,
        attack_filter: str = "all",
        workflow_context: WorkflowExecutionContext | None = None,
    ) -> Report:
        """Generate a report using an existing queued workflow."""
        report_kind, create_report = self._report_generation_target(
            run=run,
            project=project,
            report_format=report_format,
            attack_filter=attack_filter,
        )
        return self._create_report_with_workflow(
            run=run,
            project=project,
            report_format=report_format,
            report_kind=report_kind,
            create_report=create_report,
            attack_filter=attack_filter if report_format == "attack-navigator" else None,
            workflow_id=workflow_id,
            execution_mode="worker",
            workflow_context=workflow_context,
        )

    def _create_evidence_bundle(self, *, run: AnalysisRun, project: Project) -> Report:
        """Generate an evidence ZIP bundle without workflow bookkeeping."""
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

    def _create_report_with_workflow(
        self,
        *,
        run: AnalysisRun,
        project: Project,
        report_format: str,
        report_kind: str,
        create_report: Callable[[], Report],
        attack_filter: str | None = None,
        workflow_id: uuid.UUID | None = None,
        execution_mode: str = "request",
        workflow_context: WorkflowExecutionContext | None = None,
    ) -> Report:
        """Persist durable workflow state around one report generation."""
        workflow_repo = WorkflowRepository(self.session)
        metadata: dict[str, object] = {
            "report_format": report_format,
            "report_kind": report_kind,
            "analysis_run_id": str(run.id),
        }
        if attack_filter is not None:
            metadata["attack_filter"] = attack_filter
        if workflow_id is None:
            workflow = workflow_repo.create_workflow_run(
                kind=WorkflowRunKind.REPORT_GENERATION,
                title=f"Generate {report_format} report",
                handler="app.services.reports.ReportService",
                project_id=project.id,
                analysis_run_id=run.id,
                status=WorkflowRunStatus.PENDING,
                execution_mode=execution_mode,
                current_stage="queued",
                progress_current=0,
                progress_total=3,
                metadata_json=metadata,
            )
        else:
            workflow = workflow_repo.require_workflow(workflow_id)
        context = workflow_context or WorkflowExecutionContext.for_workflow(
            workflow_repo,
            workflow.id,
        )
        workflow = context.start(
            stage="render",
            message=f"Rendering {report_format} report.",
            progress_current=1,
            progress_total=3,
        )
        try:
            report = create_report()
        except Exception as exc:
            context.fail(
                stage="failed",
                message=str(exc),
                progress_current=1,
                progress_total=3,
                diagnostics={"report_error": str(exc), "format": report_format},
                terminal_code="report_generation_failed",
            )
            raise
        context.stage(
            "persist",
            f"Persisted {report_format} report metadata.",
            progress_current=2,
            progress_total=3,
            details={"report_id": str(report.id)},
        )
        context.artifact(
            artifact_kind="report",
            artifact_id=str(report.id),
            report_id=report.id,
            details={
                "format": report.format,
                "kind": report.kind,
                "filename": report.filename,
            },
        )
        context.succeed(
            stage="succeeded",
            message=f"{report_format} report generated.",
            progress_current=3,
            progress_total=3,
            result={
                "report_id": str(report.id),
                "report_format": report.format,
                "report_kind": report.kind,
                "filename": report.filename,
                "content_type": report.content_type,
                "size_bytes": report.size_bytes,
                "sha256": report.sha256,
            },
            diagnostics={},
        )
        return report

    def _report_generation_target(
        self,
        *,
        run: AnalysisRun,
        project: Project,
        report_format: str,
        attack_filter: str = "all",
    ) -> tuple[str, Callable[[], Report]]:
        if report_format == "html":
            return REPORT_KIND_EXECUTIVE_HTML, lambda: self._create_html_report(
                run=run,
                project=project,
            )
        if report_format == "json":
            return REPORT_KIND_ANALYSIS_JSON, lambda: self._create_analysis_json_export(
                run=run,
                project=project,
            )
        if report_format == "csv":
            return REPORT_KIND_FINDINGS_CSV, lambda: self._create_findings_csv_export(
                run=run,
                project=project,
            )
        if report_format == "attack-navigator":
            return REPORT_KIND_ATTACK_NAVIGATOR, lambda: self._create_attack_navigator_layer(
                run=run,
                project=project,
                filter_value=attack_filter,
            )
        if report_format == "sarif":
            return REPORT_KIND_SARIF_RESULTS, lambda: self._create_sarif_report(
                run=run,
                project=project,
            )
        if report_format == "zip":
            return REPORT_KIND_EVIDENCE_BUNDLE, lambda: self._create_evidence_bundle(
                run=run,
                project=project,
            )
        if report_format != "markdown":
            raise ReportGenerationError(f"Unsupported report format: {report_format}")
        return REPORT_KIND_TECHNICAL_MARKDOWN, lambda: self._create_markdown_report(
            run=run,
            project=project,
        )

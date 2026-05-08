"""Workbench report generation services."""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

from sqlmodel import Session, col, select

from app.core.config import Settings
from app.models import (
    AnalysisRun,
    AnalysisRunStatus,
    Finding,
    FindingAttackContext,
    FindingOccurrence,
    Project,
    Report,
)
from app.models.base import get_datetime_utc
from app.repositories import ReportRepository, WaiverRepository
from app.services import report_models as _report_models
from app.services import report_renderers as _report_renderers
from app.services.attack import build_attack_navigator_layer_payload
from app.services.governance import build_project_governance_rollups_payload
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
    _finding_payload,
    _provider_snapshot_payload,
    render_analysis_result_json,
    render_evidence_bundle_zip,
    render_findings_csv,
    render_html_executive_report,
    render_markdown_report,
)
from app.services.report_sarif import render_sarif_report

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

REPORT_SUPPORTED_RUN_STATUSES = {
    AnalysisRunStatus.COMPLETED,
    AnalysisRunStatus.COMPLETED_WITH_ERRORS,
    AnalysisRunStatus.SUCCEEDED,
}


class ReportService:
    """Generate and persist report artifacts for Workbench analysis runs."""

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

    def create_analysis_json_export(self, *, run: AnalysisRun, project: Project) -> Report:
        """Generate a stable analysis-result.v1 JSON export and persist its metadata."""
        payload, findings, generated_at = self._report_payload(run=run, project=project)
        content = render_analysis_result_json(payload)
        return self._persist_report(
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
        payload, findings, generated_at = self._report_payload(run=run, project=project)
        content = render_findings_csv(payload)
        return self._persist_report(
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
        payload, findings, generated_at = self._report_payload(run=run, project=project)
        attack_contexts = self._run_attack_contexts(run)
        layer = self._attack_navigator_layer(
            run=run,
            project=project,
            findings=findings,
            attack_contexts=attack_contexts,
            generated_at=generated_at,
            filter_value=filter_value,
            include_empty=True,
        )
        if layer is None:
            raise ReportGenerationError("ATT&CK Navigator layer generation failed.")
        content = json.dumps(layer, indent=2, sort_keys=True) + "\n"
        return self._persist_report(
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
        payload, findings, generated_at = self._report_payload(run=run, project=project)
        sarif_payload = render_sarif_report(payload)
        content = json.dumps(sarif_payload, indent=2, sort_keys=True) + "\n"
        results = sarif_payload["runs"][0]["results"]
        rules = sarif_payload["runs"][0]["tool"]["driver"]["rules"]
        return self._persist_report(
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
        payload, findings, generated_at = self._report_payload(run=run, project=project)
        attack_layer = self._attack_navigator_layer(
            run=run,
            project=project,
            findings=findings,
            attack_contexts=self._run_attack_contexts(run),
            generated_at=generated_at,
            filter_value="all",
            include_empty=False,
        )
        bundle_bytes, manifest = render_evidence_bundle_zip(
            payload,
            attack_navigator_layer=attack_layer,
        )
        return self._persist_binary_report(
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
        run_occurrences = self._run_occurrences_by_finding(run)
        report_findings = [
            _finding_payload(
                finding,
                occurrences=run_occurrences.get(finding.id, []),
            )
            for finding in findings
        ]
        waiver_repository = WaiverRepository(self.session)
        governance_rollups = build_project_governance_rollups_payload(
            project_id=project.id,
            findings=findings,
            waivers=waiver_repository.list_project_waivers(project.id),
            waiver_repository=waiver_repository,
        )
        payload = MarkdownReportPayload(
            generated_at=generated_at,
            project_id=str(project.id),
            project_name=project.name,
            run_id=str(run.id),
            run_status=str(run.status),
            input_type=run.input_type,
            filename=run.filename,
            summary=dict(run.summary_json or {}),
            findings=report_findings,
            provider_snapshot=_provider_snapshot_payload(run.provider_snapshot),
            governance_rollups=governance_rollups.model_dump(mode="json"),
            project_description=project.description,
            project_owner_id=str(project.owner_id),
            project_created_at=project.created_at,
            project_updated_at=project.updated_at,
            run_started_at=run.started_at,
            run_finished_at=run.finished_at,
            run_error=run.error_message,
            run_errors=dict(run.error_json or {}),
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
        extra_metadata: dict[str, Any] | None = None,
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
        return self._create_report_record(
            report_id=report_id,
            run=run,
            project=project,
            generated_at=generated_at,
            finding_count=finding_count,
            provider_snapshot_id=provider_snapshot_id,
            content_bytes=content_bytes,
            report_path=report_path,
            kind=kind,
            report_format=report_format,
            filename=filename,
            content_type=content_type,
            extra_metadata=extra_metadata,
        )

    def _persist_binary_report(
        self,
        *,
        run: AnalysisRun,
        project: Project,
        generated_at: datetime,
        finding_count: int,
        provider_snapshot_id: uuid.UUID | None,
        content: bytes,
        kind: str,
        report_format: str,
        filename: str,
        content_type: str,
        extra_metadata: dict[str, Any] | None = None,
    ) -> Report:
        report_id = uuid.uuid4()
        report_path = self._report_path(
            project_id=project.id,
            run_id=run.id,
            report_id=report_id,
            filename=filename,
        )
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_bytes(content)
        return self._create_report_record(
            report_id=report_id,
            run=run,
            project=project,
            generated_at=generated_at,
            finding_count=finding_count,
            provider_snapshot_id=provider_snapshot_id,
            content_bytes=content,
            report_path=report_path,
            kind=kind,
            report_format=report_format,
            filename=filename,
            content_type=content_type,
            extra_metadata=extra_metadata,
        )

    def _create_report_record(
        self,
        *,
        report_id: uuid.UUID,
        run: AnalysisRun,
        project: Project,
        generated_at: datetime,
        finding_count: int,
        provider_snapshot_id: uuid.UUID | None,
        content_bytes: bytes,
        report_path: Path,
        kind: str,
        report_format: str,
        filename: str,
        content_type: str,
        extra_metadata: dict[str, Any] | None = None,
    ) -> Report:
        sha256 = hashlib.sha256(content_bytes).hexdigest()
        metadata_json = {
            "generated_at": generated_at.isoformat(),
            "project_id": str(project.id),
            "analysis_run_id": str(run.id),
            "provider_snapshot_id": str(provider_snapshot_id)
            if provider_snapshot_id is not None
            else None,
            "finding_count": finding_count,
            "format": report_format,
            "kind": kind,
            "service": "workbench-report-service",
        }
        if extra_metadata:
            metadata_json.update(extra_metadata)
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
            metadata_json=metadata_json,
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

    def _run_occurrences_by_finding(
        self,
        run: AnalysisRun,
    ) -> dict[uuid.UUID, list[FindingOccurrence]]:
        statement = (
            select(FindingOccurrence)
            .where(FindingOccurrence.analysis_run_id == run.id)
            .order_by(col(FindingOccurrence.id))
        )
        occurrences: dict[uuid.UUID, list[FindingOccurrence]] = {}
        for occurrence in self.session.exec(statement).all():
            occurrences.setdefault(occurrence.finding_id, []).append(occurrence)
        return occurrences

    def _run_attack_contexts(
        self,
        run: AnalysisRun,
    ) -> list[FindingAttackContext]:
        statement = (
            select(FindingAttackContext)
            .where(FindingAttackContext.analysis_run_id == run.id)
            .order_by(col(FindingAttackContext.created_at).desc())
        )
        return list(self.session.exec(statement).all())

    def _attack_navigator_layer(
        self,
        *,
        run: AnalysisRun,
        project: Project,
        findings: list[Finding],
        attack_contexts: list[FindingAttackContext],
        generated_at: datetime,
        filter_value: str,
        include_empty: bool,
    ) -> dict[str, Any] | None:
        layer = build_attack_navigator_layer_payload(
            project_id=project.id,
            project_name=project.name,
            run_id=run.id,
            findings=findings,
            attack_contexts=attack_contexts,
            filter_value=filter_value,
            generated_at=generated_at,
        )
        return layer if include_empty or layer.get("techniques") else None

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

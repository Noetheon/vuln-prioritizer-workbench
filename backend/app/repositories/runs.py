"""Run repository for Workbench persistence."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlmodel import Session, col, func, select

from app.models import (
    AnalysisRun,
    AnalysisRunStatus,
    FindingOccurrence,
    ProviderSnapshot,
    WorkflowRunStatus,
)
from app.models.base import get_datetime_utc
from vuln_prioritizer.security_redaction import redact_value


def _redacted_json_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Redacted json payload function."""
    redacted, _paths = redact_value(payload)
    return redacted if isinstance(redacted, dict) else {}


def _workflow_status_for_run(status: AnalysisRunStatus | str) -> WorkflowRunStatus:
    normalized = AnalysisRunStatus(status)
    if normalized == AnalysisRunStatus.RUNNING:
        return WorkflowRunStatus.RUNNING
    if normalized == AnalysisRunStatus.FAILED:
        return WorkflowRunStatus.FAILED
    if normalized == AnalysisRunStatus.CANCELLED:
        return WorkflowRunStatus.CANCELLED
    if normalized == AnalysisRunStatus.COMPLETED_WITH_ERRORS:
        return WorkflowRunStatus.COMPLETED_WITH_ERRORS
    if normalized in {AnalysisRunStatus.SUCCEEDED, AnalysisRunStatus.COMPLETED}:
        return WorkflowRunStatus.SUCCEEDED
    return WorkflowRunStatus.PENDING


class RunRepository:
    """Analysis run, occurrence, and provider snapshot persistence helpers."""

    def __init__(self, session: Session) -> None:
        """Initialize a new instance of RunRepository."""
        self.session = session

    def create_provider_snapshot(
        self,
        *,
        nvd_last_sync: str | None = None,
        epss_date: str | None = None,
        kev_catalog_version: str | None = None,
        content_hash: str | None = None,
        source_hashes_json: dict[str, Any] | None = None,
        source_metadata_json: dict[str, Any] | None = None,
    ) -> ProviderSnapshot:
        """Create a provider snapshot without committing the transaction."""
        snapshot = ProviderSnapshot(
            nvd_last_sync=nvd_last_sync,
            epss_date=epss_date,
            kev_catalog_version=kev_catalog_version,
            content_hash=content_hash,
            source_hashes_json=source_hashes_json or {},
            source_metadata_json=_redacted_json_payload(source_metadata_json or {}),
        )
        self.session.add(snapshot)
        self.session.flush()
        return snapshot

    def get_provider_snapshot_by_hash(self, content_hash: str) -> ProviderSnapshot | None:
        """Return a provider snapshot by content hash."""
        statement = select(ProviderSnapshot).where(ProviderSnapshot.content_hash == content_hash)
        return self.session.exec(statement).first()

    def get_latest_provider_snapshot(self) -> ProviderSnapshot | None:
        """Return the newest provider snapshot for global provider status."""
        statement = select(ProviderSnapshot).order_by(col(ProviderSnapshot.created_at).desc())
        return self.session.exec(statement).first()

    def get_or_create_provider_snapshot(
        self,
        *,
        content_hash: str,
        nvd_last_sync: str | None = None,
        epss_date: str | None = None,
        kev_catalog_version: str | None = None,
        source_hashes_json: dict[str, Any] | None = None,
        source_metadata_json: dict[str, Any] | None = None,
    ) -> ProviderSnapshot:
        """Return an existing snapshot for a hash, or create one."""
        snapshot = self.get_provider_snapshot_by_hash(content_hash)
        if snapshot is not None:
            self._refresh_provider_snapshot(
                snapshot,
                nvd_last_sync=nvd_last_sync,
                epss_date=epss_date,
                kev_catalog_version=kev_catalog_version,
                source_hashes_json=source_hashes_json,
                source_metadata_json=source_metadata_json,
            )
            return snapshot
        return self.create_provider_snapshot(
            content_hash=content_hash,
            nvd_last_sync=nvd_last_sync,
            epss_date=epss_date,
            kev_catalog_version=kev_catalog_version,
            source_hashes_json=source_hashes_json,
            source_metadata_json=source_metadata_json,
        )

    def _refresh_provider_snapshot(
        self,
        snapshot: ProviderSnapshot,
        *,
        nvd_last_sync: str | None,
        epss_date: str | None,
        kev_catalog_version: str | None,
        source_hashes_json: dict[str, Any] | None,
        source_metadata_json: dict[str, Any] | None,
    ) -> None:
        """Refresh replay metadata when the same snapshot content is reused."""
        changed = False
        if nvd_last_sync is not None and snapshot.nvd_last_sync != nvd_last_sync:
            snapshot.nvd_last_sync = nvd_last_sync
            changed = True
        if epss_date is not None and snapshot.epss_date != epss_date:
            snapshot.epss_date = epss_date
            changed = True
        if kev_catalog_version is not None and snapshot.kev_catalog_version != kev_catalog_version:
            snapshot.kev_catalog_version = kev_catalog_version
            changed = True
        if source_hashes_json is not None and snapshot.source_hashes_json != source_hashes_json:
            snapshot.source_hashes_json = source_hashes_json
            changed = True
        if source_metadata_json is not None:
            redacted_metadata = _redacted_json_payload(source_metadata_json)
            if snapshot.source_metadata_json != redacted_metadata:
                snapshot.source_metadata_json = redacted_metadata
                changed = True
        if changed:
            self.session.add(snapshot)
            self.session.flush()

    def create_analysis_run(
        self,
        *,
        project_id: uuid.UUID,
        input_type: str,
        filename: str | None = None,
        status: AnalysisRunStatus | str = AnalysisRunStatus.PENDING,
        provider_snapshot_id: uuid.UUID | None = None,
        result_json: dict[str, Any] | None = None,
        diagnostics_json: dict[str, Any] | None = None,
    ) -> AnalysisRun:
        """Create an analysis run without committing the transaction."""
        run = AnalysisRun(
            project_id=project_id,
            input_type=input_type,
            filename=filename,
            status=AnalysisRunStatus(status),
            provider_snapshot_id=provider_snapshot_id,
        )
        self.session.add(run)
        self.session.flush()
        self._project_workflow_payloads(
            run,
            result_json=result_json,
            diagnostics_json=diagnostics_json,
        )
        return run

    def finish_analysis_run(
        self,
        run_id: uuid.UUID,
        *,
        status: AnalysisRunStatus | str = AnalysisRunStatus.COMPLETED,
        finished_at: datetime | None = None,
        error_message: str | None = None,
        result_json: dict[str, Any] | None = None,
        diagnostics_json: dict[str, Any] | None = None,
    ) -> AnalysisRun:
        """Mark a run terminal and flush the transaction."""
        run = self.session.get(AnalysisRun, run_id)
        if run is None:
            raise LookupError(f"AnalysisRun not found: {run_id}")

        run.status = AnalysisRunStatus(status)
        run.finished_at = finished_at or get_datetime_utc()
        run.error_message = error_message
        self.session.flush()
        self._project_workflow_payloads(
            run,
            result_json=result_json,
            diagnostics_json=diagnostics_json,
        )
        return run

    def _project_workflow_payloads(
        self,
        run: AnalysisRun,
        *,
        result_json: dict[str, Any] | None = None,
        diagnostics_json: dict[str, Any] | None = None,
    ) -> None:
        """Project repository payload arguments into workflow v2 fields."""
        if result_json is None and diagnostics_json is None:
            return
        from app.models import WorkflowRunKind, WorkflowRunStatus
        from app.repositories.workflows import WorkflowRepository

        kind = (
            WorkflowRunKind.PROVIDER_UPDATE
            if run.input_type == "provider_update"
            else WorkflowRunKind.IMPORT
        )
        workflow_repository = WorkflowRepository(self.session)
        workflow = workflow_repository.ensure_analysis_workflow(
            kind=kind,
            analysis_run_id=run.id,
            project_id=run.project_id,
            title="Provider snapshot refresh"
            if kind == WorkflowRunKind.PROVIDER_UPDATE
            else f"Import {run.input_type}",
            handler="app.repositories.runs.deprecated_payload_projection",
            status=_workflow_status_for_run(run.status),
            execution_mode="worker",
            current_stage="projected",
        )
        if result_json is not None:
            workflow.result_json = dict(result_json)
        if diagnostics_json is not None:
            workflow.diagnostics_json = dict(diagnostics_json)
            workflow.error_details_json = dict(diagnostics_json)
        if workflow.status == WorkflowRunStatus.FAILED and run.error_message:
            workflow.error_message = run.error_message
        self.session.add(workflow)
        self.session.flush()

    def add_finding_occurrence(
        self,
        *,
        finding_id: uuid.UUID,
        analysis_run_id: uuid.UUID,
        source: str | None = None,
        scanner: str | None = None,
        raw_reference: str | None = None,
        fix_version: str | None = None,
        evidence_json: dict[str, Any] | None = None,
        flush: bool = True,
    ) -> FindingOccurrence:
        """Attach source evidence for a finding produced by a run."""
        occurrence = FindingOccurrence(
            finding_id=finding_id,
            analysis_run_id=analysis_run_id,
            source=source,
            scanner=scanner,
            raw_reference=raw_reference,
            fix_version=fix_version,
            evidence_json=evidence_json or {},
        )
        self.session.add(occurrence)
        if flush:
            self.session.flush()
        return occurrence

    def list_analysis_runs(
        self,
        project_id: uuid.UUID,
        *,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[AnalysisRun]:
        """Return a bounded run page for a project newest first."""
        statement = (
            select(AnalysisRun)
            .where(AnalysisRun.project_id == project_id)
            .order_by(col(AnalysisRun.started_at).desc())
            .offset(offset)
        )
        if limit is not None:
            statement = statement.limit(limit)
        return list(self.session.exec(statement).all())

    def list_analysis_runs_page(
        self,
        project_id: uuid.UUID,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[list[AnalysisRun], int]:
        """Return a bounded run page and total count for a project."""
        count_statement = (
            select(func.count())
            .select_from(AnalysisRun)
            .where(AnalysisRun.project_id == project_id)
        )
        count = int(self.session.exec(count_statement).one())
        return self.list_analysis_runs(project_id, limit=limit, offset=offset), count

    def get_latest_analysis_run(self, project_id: uuid.UUID) -> AnalysisRun | None:
        """Return the newest analysis run for a project."""
        statement = (
            select(AnalysisRun)
            .where(AnalysisRun.project_id == project_id)
            .order_by(col(AnalysisRun.started_at).desc())
        )
        return self.session.exec(statement).first()

    def get_analysis_run(self, run_id: uuid.UUID) -> AnalysisRun | None:
        """Return an analysis run by primary key."""
        return self.session.get(AnalysisRun, run_id)

    def list_active_analysis_runs_started_before(
        self,
        started_before: datetime,
    ) -> list[AnalysisRun]:
        """Return non-terminal analysis runs older than a cutoff."""
        statement = (
            select(AnalysisRun)
            .where(
                col(AnalysisRun.status).in_([AnalysisRunStatus.PENDING, AnalysisRunStatus.RUNNING]),
                AnalysisRun.started_at < started_before,
            )
            .order_by(col(AnalysisRun.started_at).asc())
        )
        return list(self.session.exec(statement).all())

    def get_latest_failed_provider_update_run(self) -> AnalysisRun | None:
        """Return the newest failed provider-update run, if the Workbench shell recorded one."""
        statement = (
            select(AnalysisRun)
            .where(
                AnalysisRun.input_type == "provider_update",
                AnalysisRun.status == AnalysisRunStatus.FAILED,
            )
            .order_by(col(AnalysisRun.started_at).desc())
        )
        return self.session.exec(statement).first()

    def get_latest_provider_update_run(self) -> AnalysisRun | None:
        """Return the newest provider-update run, regardless of terminal status."""
        statement = (
            select(AnalysisRun)
            .where(AnalysisRun.input_type == "provider_update")
            .order_by(col(AnalysisRun.started_at).desc())
        )
        return self.session.exec(statement).first()

    def get_running_provider_update_run(self) -> AnalysisRun | None:
        """Return an in-progress provider-update run, if one is active."""
        statement = (
            select(AnalysisRun)
            .where(
                AnalysisRun.input_type == "provider_update",
                col(AnalysisRun.status).in_([AnalysisRunStatus.PENDING, AnalysisRunStatus.RUNNING]),
            )
            .order_by(col(AnalysisRun.started_at).desc())
        )
        return self.session.exec(statement).first()

    def list_provider_update_runs(self, *, limit: int = 50) -> list[AnalysisRun]:
        """Return provider-update runs newest first."""
        statement = (
            select(AnalysisRun)
            .where(AnalysisRun.input_type == "provider_update")
            .order_by(col(AnalysisRun.started_at).desc())
            .limit(limit)
        )
        return list(self.session.exec(statement).all())

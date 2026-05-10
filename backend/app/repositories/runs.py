"""Run repository for Workbench persistence."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlmodel import Session, col, select

from app.models import (
    AnalysisRun,
    AnalysisRunStatus,
    FindingOccurrence,
    ProviderSnapshot,
)
from app.models.base import get_datetime_utc
from vuln_prioritizer.security_redaction import redact_value


def _redacted_json_payload(payload: dict[str, Any]) -> dict[str, Any]:
    redacted, _paths = redact_value(payload)
    return redacted if isinstance(redacted, dict) else {}


class RunRepository:
    """Analysis run, occurrence, and provider snapshot persistence helpers."""

    def __init__(self, session: Session) -> None:
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
            return snapshot
        return self.create_provider_snapshot(
            content_hash=content_hash,
            nvd_last_sync=nvd_last_sync,
            epss_date=epss_date,
            kev_catalog_version=kev_catalog_version,
            source_hashes_json=source_hashes_json,
            source_metadata_json=source_metadata_json,
        )

    def create_analysis_run(
        self,
        *,
        project_id: uuid.UUID,
        input_type: str,
        filename: str | None = None,
        status: AnalysisRunStatus | str = AnalysisRunStatus.PENDING,
        provider_snapshot_id: uuid.UUID | None = None,
        summary_json: dict[str, Any] | None = None,
        error_json: dict[str, Any] | None = None,
    ) -> AnalysisRun:
        """Create an analysis run without committing the transaction."""
        run = AnalysisRun(
            project_id=project_id,
            input_type=input_type,
            filename=filename,
            status=AnalysisRunStatus(status),
            provider_snapshot_id=provider_snapshot_id,
            summary_json=summary_json or {},
            error_json=error_json or {},
        )
        self.session.add(run)
        self.session.flush()
        return run

    def finish_analysis_run(
        self,
        run_id: uuid.UUID,
        *,
        status: AnalysisRunStatus | str = AnalysisRunStatus.COMPLETED,
        finished_at: datetime | None = None,
        error_message: str | None = None,
        error_json: dict[str, Any] | None = None,
        summary_json: dict[str, Any] | None = None,
    ) -> AnalysisRun:
        """Mark a run terminal and flush the transaction."""
        run = self.session.get(AnalysisRun, run_id)
        if run is None:
            raise LookupError(f"AnalysisRun not found: {run_id}")

        run.status = AnalysisRunStatus(status)
        run.finished_at = finished_at or get_datetime_utc()
        run.error_message = error_message
        if error_json is not None:
            run.error_json = error_json
        if summary_json is not None:
            run.summary_json = summary_json
        self.session.flush()
        return run

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

    def list_analysis_runs(self, project_id: uuid.UUID) -> list[AnalysisRun]:
        """Return runs for a project newest first."""
        statement = (
            select(AnalysisRun)
            .where(AnalysisRun.project_id == project_id)
            .order_by(col(AnalysisRun.started_at).desc())
        )
        return list(self.session.exec(statement).all())

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

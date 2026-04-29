"""Provider snapshot persistence helpers for Workbench repositories."""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from vuln_prioritizer.db.models import ProviderSnapshot, ProviderUpdateJob, utc_now


class ProviderSnapshotRepositoryMixin:
    """Provider snapshot and update-job persistence methods."""

    session: Session

    def create_provider_snapshot(
        self,
        *,
        content_hash: str | None = None,
        nvd_last_sync: str | None = None,
        epss_date: str | None = None,
        kev_catalog_version: str | None = None,
        metadata_json: dict | None = None,
    ) -> ProviderSnapshot:
        snapshot = ProviderSnapshot(
            content_hash=content_hash,
            nvd_last_sync=nvd_last_sync,
            epss_date=epss_date,
            kev_catalog_version=kev_catalog_version,
            metadata_json=metadata_json or {},
        )
        self.session.add(snapshot)
        self.session.flush()
        return snapshot

    def get_provider_snapshot_by_hash(self, content_hash: str) -> ProviderSnapshot | None:
        return self.session.scalar(
            select(ProviderSnapshot).where(ProviderSnapshot.content_hash == content_hash)
        )

    def get_or_create_provider_snapshot(
        self,
        *,
        content_hash: str,
        nvd_last_sync: str | None = None,
        epss_date: str | None = None,
        kev_catalog_version: str | None = None,
        metadata_json: dict | None = None,
    ) -> ProviderSnapshot:
        snapshot = self.get_provider_snapshot_by_hash(content_hash)
        if snapshot is not None:
            if nvd_last_sync is not None:
                snapshot.nvd_last_sync = nvd_last_sync
            if epss_date is not None:
                snapshot.epss_date = epss_date
            if kev_catalog_version is not None:
                snapshot.kev_catalog_version = kev_catalog_version
            if metadata_json is not None:
                snapshot.metadata_json = metadata_json
            self.session.flush()
            return snapshot
        return self.create_provider_snapshot(
            content_hash=content_hash,
            nvd_last_sync=nvd_last_sync,
            epss_date=epss_date,
            kev_catalog_version=kev_catalog_version,
            metadata_json=metadata_json,
        )

    def list_provider_snapshots(self) -> list[ProviderSnapshot]:
        statement = select(ProviderSnapshot).order_by(ProviderSnapshot.created_at.desc())
        return list(self.session.scalars(statement))

    def get_latest_provider_snapshot(self) -> ProviderSnapshot | None:
        statement = select(ProviderSnapshot).order_by(ProviderSnapshot.created_at.desc()).limit(1)
        return self.session.scalar(statement)

    def create_provider_update_job(
        self,
        *,
        status: str,
        requested_sources_json: list[str],
        metadata_json: dict[str, Any] | None = None,
        error_message: str | None = None,
    ) -> ProviderUpdateJob:
        job = ProviderUpdateJob(
            status=status,
            requested_sources_json=requested_sources_json,
            metadata_json=metadata_json or {},
            error_message=error_message,
            finished_at=utc_now() if status in {"completed", "failed"} else None,
        )
        self.session.add(job)
        self.session.flush()
        return job

    def list_provider_update_jobs(self) -> list[ProviderUpdateJob]:
        statement = select(ProviderUpdateJob).order_by(ProviderUpdateJob.started_at.desc())
        return list(self.session.scalars(statement))

"""Workbench job and artifact-retention persistence helpers."""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from vuln_prioritizer.db.models import ProjectArtifactRetention, WorkbenchJob, utc_now


class WorkbenchJobRepositoryMixin:
    """WorkbenchJob repository methods."""

    session: Session

    def enqueue_workbench_job(
        self,
        *,
        kind: str,
        project_id: str | None = None,
        target_type: str | None = None,
        target_id: str | None = None,
        payload_json: dict[str, Any] | None = None,
        idempotency_key: str | None = None,
        priority: int = 100,
        max_attempts: int = 3,
    ) -> WorkbenchJob:
        if idempotency_key:
            existing = self.session.scalar(
                select(WorkbenchJob).where(WorkbenchJob.idempotency_key == idempotency_key)
            )
            if existing is not None:
                return existing
        job = WorkbenchJob(
            kind=kind,
            project_id=project_id,
            target_type=target_type,
            target_id=target_id,
            payload_json=payload_json or {},
            idempotency_key=idempotency_key,
            priority=priority,
            max_attempts=max_attempts,
            logs_json=[],
            result_json={},
        )
        self.session.add(job)
        self.session.flush()
        return job

    def get_workbench_job(self, job_id: str) -> WorkbenchJob | None:
        return self.session.get(WorkbenchJob, job_id)

    def list_workbench_jobs(
        self,
        *,
        project_id: str | None = None,
        status: str | None = None,
        kind: str | None = None,
        limit: int = 100,
    ) -> list[WorkbenchJob]:
        statement = select(WorkbenchJob)
        if project_id is not None:
            statement = statement.where(WorkbenchJob.project_id == project_id)
        if status is not None:
            statement = statement.where(WorkbenchJob.status == status)
        if kind is not None:
            statement = statement.where(WorkbenchJob.kind == kind)
        statement = statement.order_by(WorkbenchJob.created_at.desc()).limit(limit)
        return list(self.session.scalars(statement))

    def start_workbench_job(self, job: WorkbenchJob, *, worker_id: str = "sync") -> WorkbenchJob:
        job.status = "running"
        job.attempts += 1
        job.started_at = utc_now()
        job.heartbeat_at = job.started_at
        job.lease_owner = worker_id
        job.error_message = None
        job.logs_json = [*_job_logs(job), _job_log_entry("started", progress=job.progress)]
        self.session.flush()
        return job

    def update_workbench_job_progress(
        self,
        job: WorkbenchJob,
        *,
        progress: int,
        message: str | None = None,
    ) -> WorkbenchJob:
        job.progress = max(0, min(100, progress))
        job.heartbeat_at = utc_now()
        logs = _job_logs(job)
        if message:
            logs.append(_job_log_entry(message, progress=job.progress))
        job.logs_json = logs
        self.session.flush()
        return job

    def complete_workbench_job(
        self,
        job: WorkbenchJob,
        *,
        result_json: dict[str, Any] | None = None,
        message: str = "completed",
    ) -> WorkbenchJob:
        job.status = "completed"
        job.progress = 100
        job.result_json = result_json or {}
        job.finished_at = utc_now()
        job.heartbeat_at = job.finished_at
        job.lease_owner = None
        job.lease_expires_at = None
        job.logs_json = [*_job_logs(job), _job_log_entry(message, progress=100)]
        self.session.flush()
        return job

    def fail_workbench_job(
        self,
        job: WorkbenchJob,
        *,
        error_message: str,
        retryable: bool = True,
    ) -> WorkbenchJob:
        job.status = "queued" if retryable and job.attempts < job.max_attempts else "failed"
        job.error_message = error_message
        job.finished_at = utc_now() if job.status == "failed" else None
        job.heartbeat_at = utc_now()
        job.lease_owner = None
        job.lease_expires_at = None
        job.logs_json = [*_job_logs(job), _job_log_entry(error_message, progress=job.progress)]
        self.session.flush()
        return job

    def retry_workbench_job(self, job: WorkbenchJob) -> WorkbenchJob:
        if job.status not in {"failed", "completed"}:
            return job
        job.status = "queued"
        job.progress = 0
        job.error_message = None
        job.finished_at = None
        job.queued_at = utc_now()
        job.logs_json = [*_job_logs(job), _job_log_entry("retry queued", progress=0)]
        self.session.flush()
        return job

    def get_project_artifact_retention(self, project_id: str) -> ProjectArtifactRetention | None:
        return self.session.scalar(
            select(ProjectArtifactRetention).where(
                ProjectArtifactRetention.project_id == project_id
            )
        )

    def upsert_project_artifact_retention(
        self,
        *,
        project_id: str,
        report_retention_days: int | None = None,
        evidence_retention_days: int | None = None,
        max_disk_usage_mb: int | None = None,
    ) -> ProjectArtifactRetention:
        retention = self.get_project_artifact_retention(project_id)
        if retention is None:
            retention = ProjectArtifactRetention(project_id=project_id)
            self.session.add(retention)
        retention.report_retention_days = report_retention_days
        retention.evidence_retention_days = evidence_retention_days
        retention.max_disk_usage_mb = max_disk_usage_mb
        self.session.flush()
        return retention


def _job_logs(job: WorkbenchJob) -> list[dict[str, Any]]:
    return list(job.logs_json) if isinstance(job.logs_json, list) else []


def _job_log_entry(message: str, *, progress: int) -> dict[str, Any]:
    return {"created_at": utc_now().isoformat(), "message": message, "progress": progress}

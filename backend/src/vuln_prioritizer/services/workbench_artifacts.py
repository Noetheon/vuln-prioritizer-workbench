"""Workbench report/evidence retention and cleanup helpers."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy.orm import Session

from vuln_prioritizer.db.models import EvidenceBundle, Report
from vuln_prioritizer.db.repositories import WorkbenchRepository
from vuln_prioritizer.workbench_config import WorkbenchSettings


@dataclass(slots=True)
class ArtifactCleanupResult:
    deleted_files: list[str] = field(default_factory=list)
    orphan_files: list[str] = field(default_factory=list)
    expired_reports: int = 0
    expired_evidence_bundles: int = 0
    bytes_removed: int = 0
    dry_run: bool = True

    def to_dict(self) -> dict[str, object]:
        return {
            "deleted_files": self.deleted_files,
            "orphan_files": self.orphan_files,
            "expired_reports": self.expired_reports,
            "expired_evidence_bundles": self.expired_evidence_bundles,
            "bytes_removed": self.bytes_removed,
            "dry_run": self.dry_run,
        }


def cleanup_project_artifacts(
    *,
    session: Session,
    settings: WorkbenchSettings,
    project_id: str | None = None,
    dry_run: bool = True,
) -> ArtifactCleanupResult:
    """Apply project retention settings and report orphan files under the report root."""
    repo = WorkbenchRepository(session)
    result = ArtifactCleanupResult(dry_run=dry_run)
    projects = [repo.get_project(project_id)] if project_id is not None else repo.list_projects()
    active_projects = [item for item in projects if item is not None]
    known_paths: set[Path] = set()
    scan_roots: set[Path] = set()
    removed_paths: set[Path] = set()
    now = datetime.now(UTC)
    for project in active_projects:
        retention = repo.get_project_artifact_retention(project.id)
        report_cutoff = _cutoff(now, retention.report_retention_days if retention else None)
        evidence_cutoff = _cutoff(now, retention.evidence_retention_days if retention else None)
        for run in repo.list_analysis_runs(project.id):
            scan_roots.add(settings.report_dir.resolve(strict=False) / run.id)
        for report in list(repo.list_project_reports(project.id)):
            path = Path(report.path).resolve(strict=False)
            known_paths.add(path)
            if report_cutoff is not None and _aware(report.created_at) < report_cutoff:
                result.expired_reports += 1
                result.bytes_removed += _delete_artifact(path, dry_run=dry_run, result=result)
                removed_paths.add(path)
                if not dry_run:
                    repo.delete_report(report)
        for bundle in list(repo.list_project_evidence_bundles(project.id)):
            path = Path(bundle.path).resolve(strict=False)
            known_paths.add(path)
            if evidence_cutoff is not None and _aware(bundle.created_at) < evidence_cutoff:
                result.expired_evidence_bundles += 1
                result.bytes_removed += _delete_artifact(path, dry_run=dry_run, result=result)
                removed_paths.add(path)
                if not dry_run:
                    repo.delete_evidence_bundle(bundle)
        if retention and retention.max_disk_usage_mb is not None:
            _enforce_project_disk_cap(
                repo=repo,
                project_id=project.id,
                max_bytes=retention.max_disk_usage_mb * 1024 * 1024,
                removed_paths=removed_paths,
                dry_run=dry_run,
                result=result,
            )

    report_root = settings.report_dir.resolve(strict=False)
    roots_to_scan = [report_root] if project_id is None else sorted(scan_roots)
    for root in roots_to_scan:
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if path.is_file() and path.resolve(strict=False) not in known_paths:
                result.orphan_files.append(str(path))
                result.bytes_removed += _delete_artifact(path, dry_run=dry_run, result=result)
    session.flush()
    return result


def _cutoff(now: datetime, days: int | None) -> datetime | None:
    if days is None:
        return None
    return now - timedelta(days=days)


def _aware(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value


def _delete_artifact(path: Path, *, dry_run: bool, result: ArtifactCleanupResult) -> int:
    if not path.is_file():
        return 0
    size = path.stat().st_size
    if not dry_run:
        path.unlink()
    result.deleted_files.append(str(path))
    return size


def _enforce_project_disk_cap(
    *,
    repo: WorkbenchRepository,
    project_id: str,
    max_bytes: int,
    removed_paths: set[Path],
    dry_run: bool,
    result: ArtifactCleanupResult,
) -> None:
    artifacts: list[tuple[datetime, str, Report | EvidenceBundle, Path, int]] = []
    for report in repo.list_project_reports(project_id):
        path = Path(report.path).resolve(strict=False)
        if path in removed_paths:
            continue
        artifacts.append((_aware(report.created_at), "report", report, path, _file_size(path)))
    for bundle in repo.list_project_evidence_bundles(project_id):
        path = Path(bundle.path).resolve(strict=False)
        if path in removed_paths:
            continue
        artifacts.append((_aware(bundle.created_at), "evidence", bundle, path, _file_size(path)))

    total = sum(size for *_, size in artifacts)
    if total <= max_bytes:
        return

    for _, _, model, path, size in sorted(artifacts, key=lambda item: (item[0], str(item[3]))):
        if total <= max_bytes:
            break
        result.bytes_removed += _delete_artifact(path, dry_run=dry_run, result=result)
        removed_paths.add(path)
        total -= size
        if not dry_run:
            if isinstance(model, Report):
                repo.delete_report(model)
            else:
                repo.delete_evidence_bundle(model)


def _file_size(path: Path) -> int:
    return path.stat().st_size if path.is_file() else 0

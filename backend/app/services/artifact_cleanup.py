"""Rooted cleanup helpers for Workbench-managed artifact directories."""

from __future__ import annotations

import shutil
import uuid
from dataclasses import dataclass
from pathlib import Path

from app.core.config import Settings


@dataclass(frozen=True)
class ProjectArtifactCleanupResult:
    """Summary of project artifact cleanup work."""

    removed_paths: tuple[str, ...]
    missing_paths: tuple[str, ...]


def cleanup_project_artifacts(
    *,
    settings: Settings,
    project_id: uuid.UUID,
    dry_run: bool = False,
) -> ProjectArtifactCleanupResult:
    """Remove upload and report artifact trees for a project from managed roots."""
    removed: list[str] = []
    missing: list[str] = []
    for root in (settings.import_upload_dir_path, settings.report_dir_path):
        target = _managed_project_path(root, project_id)
        if not target.exists():
            missing.append(str(target))
            continue
        removed.append(str(target))
        if not dry_run:
            shutil.rmtree(target)
    return ProjectArtifactCleanupResult(
        removed_paths=tuple(removed),
        missing_paths=tuple(missing),
    )


def _managed_project_path(root: Path, project_id: uuid.UUID) -> Path:
    resolved_root = root.resolve(strict=False)
    target = (resolved_root / str(project_id)).resolve(strict=False)
    if not target.is_relative_to(resolved_root):
        raise ValueError("Project artifact path escapes the configured root.")
    return target

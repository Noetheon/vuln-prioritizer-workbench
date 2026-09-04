"""Cross-process serialization for one project's artifact lifecycle."""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from filelock import FileLock, Timeout

from app.core.config import Settings


class ProjectLifecycleBusyError(RuntimeError):
    """Raised when another process is mutating the same project lifecycle."""


@dataclass(frozen=True, slots=True)
class ProjectLifecycleLease:
    """Proof that the caller owns one concrete project lifecycle lock."""

    project_id: uuid.UUID
    lock_path: Path


@contextmanager
def lock_project_lifecycle(
    settings: Settings,
    project_id: uuid.UUID,
) -> Iterator[ProjectLifecycleLease]:
    """
    Hold a non-blocking process lock for one project ID.

    Explicit leases let nested service calls share ownership without relying on
    thread-based re-entrancy. The lock spans database commits and artifact cleanup.
    Keeping the lock file below the report root makes the boundary work across
    application processes that share the same managed artifact storage. Lock
    files are intentionally retained: unlinking one while a waiter has it open could split the lock
    across two filesystem inodes.
    """
    lock_path = project_lifecycle_lock_path(settings, project_id)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    # A fresh FileLock per acquisition is intentional. FileLock's built-in
    # re-entrancy is based on a context counter, which cannot distinguish two
    # asyncio tasks running on the same OS thread. Nested service calls pass the
    # explicit lease instead of acquiring the OS lock again.
    file_lock = FileLock(lock_path)
    try:
        with file_lock.acquire(timeout=0):
            yield ProjectLifecycleLease(project_id=project_id, lock_path=lock_path)
    except Timeout as exc:
        raise ProjectLifecycleBusyError(
            f"Project {project_id} is being created, reset, or deleted by another request."
        ) from exc


def project_lifecycle_lock_path(settings: Settings, project_id: uuid.UUID) -> Path:
    """Return a rooted lock path whose filename cannot escape its directory."""
    report_root = settings.report_dir_path.resolve(strict=False)
    lock_root = (report_root / ".project-lifecycle-locks").resolve(strict=False)
    if not lock_root.is_relative_to(report_root):
        raise ValueError("Project lifecycle lock path escapes the configured report root.")
    return lock_root / f"{project_id}.lock"


def validate_project_lifecycle_lease(
    lease: ProjectLifecycleLease,
    *,
    settings: Settings,
    project_id: uuid.UUID,
) -> None:
    """Reject a lease for another project or artifact-storage configuration."""
    expected_path = project_lifecycle_lock_path(settings, project_id)
    if lease.project_id != project_id or lease.lock_path != expected_path:
        raise ValueError("Project lifecycle lease does not match the requested project.")


__all__ = [
    "ProjectLifecycleBusyError",
    "ProjectLifecycleLease",
    "lock_project_lifecycle",
    "validate_project_lifecycle_lease",
]

"""Bind report file cleanup to the transaction that publishes its metadata."""

from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from pathlib import Path

from sqlalchemy import event
from sqlalchemy.orm import SessionTransaction
from sqlmodel import Session

from app.core.config import Settings

_SESSION_KEY = "workbench_report_artifact_changes"


@dataclass(slots=True)
class _ArtifactChanges:
    created: set[Path] = field(default_factory=set)
    retired: set[Path] = field(default_factory=set)
    committed: bool = False


def track_report_artifact_creation(session: Session, settings: Settings, path: Path) -> None:
    """Remove an unpublished new file when its transaction rolls back or closes."""
    directory = _managed_artifact_directory(settings, path)
    if directory is not None:
        _transaction_changes(session).created.add(directory)


def schedule_report_artifact_deletion(session: Session, settings: Settings, path: Path) -> bool:
    """Remove a retired file only after the metadata deletion commits."""
    directory = _managed_artifact_directory(settings, path)
    if directory is None:
        return False
    _transaction_changes(session).retired.add(directory)
    return True


def _transaction_changes(session: Session) -> _ArtifactChanges:
    changes = session.info.get(_SESSION_KEY)
    if changes is None:
        changes = session.info[_SESSION_KEY] = {}
        event.listen(session, "after_commit", _mark_committed)
        event.listen(session, "after_transaction_end", _finish_transaction)
    transaction = session.get_nested_transaction() or session.get_transaction() or session.begin()
    return changes.setdefault(transaction, _ArtifactChanges())


def _mark_committed(session: Session) -> None:
    transaction = session.get_nested_transaction() or session.get_transaction()
    change = session.info[_SESSION_KEY].get(transaction)
    if change is not None:
        change.committed = True


def _finish_transaction(session: Session, transaction: SessionTransaction) -> None:
    changes: dict[SessionTransaction, _ArtifactChanges] = session.info[_SESSION_KEY]
    change = changes.pop(transaction, None)
    if change is None:
        return
    if change.committed and transaction.nested and transaction.parent is not None:
        # Releasing a savepoint does not publish its files. The outer transaction
        # still decides whether new files survive and retired files are removed.
        parent = changes.setdefault(transaction.parent, _ArtifactChanges())
        parent.created.update(change.created)
        parent.retired.update(change.retired)
        return
    for directory in change.retired if change.committed else change.created:
        shutil.rmtree(directory, ignore_errors=True)


def _managed_artifact_directory(settings: Settings, path: Path) -> Path | None:
    root = settings.report_dir_path.resolve(strict=False)
    try:
        directory = path.resolve(strict=False).parent
    except OSError:
        return None
    if directory == root or not directory.is_relative_to(root):
        return None
    return directory

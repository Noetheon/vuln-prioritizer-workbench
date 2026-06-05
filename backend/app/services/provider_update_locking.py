"""Provider update file-lock helpers."""

from __future__ import annotations

import json
import os
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from app.domain.engine.utils import iso_utc_now
from app.services.provider_update_constants import (
    PROVIDER_UPDATE_LOCK_FILE,
    PROVIDER_UPDATE_LOCK_STALE_SECONDS,
)
from app.services.provider_update_errors import (
    ProviderUpdateConflict,
    ProviderUpdateValidationError,
)


@contextmanager
def _provider_update_lock(snapshot_root: Path) -> Iterator[Path]:
    """Acquire a local lock around snapshot writes."""
    snapshot_root.mkdir(parents=True, exist_ok=True)
    lock_path = snapshot_root / PROVIDER_UPDATE_LOCK_FILE
    descriptor: int | None = None
    try:
        descriptor = _open_provider_update_lock(lock_path)
        os.write(
            descriptor,
            json.dumps(
                {
                    "pid": os.getpid(),
                    "created_at": iso_utc_now(),
                    "stale_after_seconds": PROVIDER_UPDATE_LOCK_STALE_SECONDS,
                },
                sort_keys=True,
            ).encode("utf-8"),
        )
        yield lock_path
    finally:
        if descriptor is not None:
            os.close(descriptor)
            lock_path.unlink(missing_ok=True)


def _reject_active_provider_update_lock(snapshot_root: Path) -> None:
    try:
        snapshot_root.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise ProviderUpdateValidationError("Provider snapshot directory is not writable.") from exc
    lock_path = snapshot_root / PROVIDER_UPDATE_LOCK_FILE
    if not lock_path.exists():
        return
    if _provider_update_lock_is_stale(lock_path):
        lock_path.unlink(missing_ok=True)
        return
    raise ProviderUpdateConflict(
        "Provider update already running; retry after the active job finishes."
    )


def _open_provider_update_lock(lock_path: Path) -> int:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    try:
        return os.open(lock_path, flags, 0o600)
    except FileExistsError as exc:
        if _provider_update_lock_is_stale(lock_path):
            lock_path.unlink(missing_ok=True)
            try:
                return os.open(lock_path, flags, 0o600)
            except FileExistsError:
                pass
        raise ProviderUpdateConflict(
            "Provider update already running; retry after the active job finishes."
        ) from exc


def _provider_update_lock_is_stale(lock_path: Path) -> bool:
    try:
        return time.time() - lock_path.stat().st_mtime > PROVIDER_UPDATE_LOCK_STALE_SECONDS
    except OSError:
        return False


__all__ = [
    "_provider_update_lock",
    "_reject_active_provider_update_lock",
    "_open_provider_update_lock",
    "_provider_update_lock_is_stale",
]

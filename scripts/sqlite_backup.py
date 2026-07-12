"""Create or restore an integrity-checked SQLite backup, including WAL state."""

from __future__ import annotations

import argparse
import os
import sqlite3
import uuid
from collections.abc import Sequence
from contextlib import closing
from pathlib import Path


def main(argv: Sequence[str] | None = None) -> int:
    """Run an atomic SQLite backup or restore operation."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("backup", "restore"))
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args(argv)
    source = args.source.expanduser().resolve(strict=True)
    destination = args.destination.expanduser().resolve(strict=False)
    if source == destination:
        raise SystemExit("SQLite backup source and destination must differ.")
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if args.action == "restore":
        _assert_restore_destination_is_offline(destination)
    _copy_database(source, destination)
    print(f"SQLite {args.action} verified: {destination}")
    return 0


def _copy_database(source: Path, destination: Path) -> None:
    temporary = destination.with_name(f".{destination.name}.{uuid.uuid4().hex}.tmp")
    temporary.unlink(missing_ok=True)
    source_uri = f"{source.as_uri()}?mode=ro"
    try:
        with (
            closing(sqlite3.connect(source_uri, uri=True, timeout=30)) as source_connection,
            closing(sqlite3.connect(temporary, timeout=30)) as target_connection,
        ):
            source_connection.backup(target_connection, pages=1024)
            target_connection.commit()
            integrity = target_connection.execute("PRAGMA integrity_check").fetchone()
            if integrity != ("ok",):
                raise RuntimeError(f"SQLite integrity check failed: {integrity!r}")
        if os.name != "nt":
            temporary.chmod(0o600)
        temporary.replace(destination)
    except (OSError, sqlite3.Error, RuntimeError) as exc:
        temporary.unlink(missing_ok=True)
        raise SystemExit(f"SQLite backup operation failed: {exc}") from exc


def _assert_restore_destination_is_offline(destination: Path) -> None:
    sidecars = [
        path
        for path in (
            destination.with_name(f"{destination.name}-wal"),
            destination.with_name(f"{destination.name}-shm"),
        )
        if path.exists()
    ]
    if sidecars:
        names = ", ".join(path.name for path in sidecars)
        raise SystemExit(
            "Refusing to restore over a SQLite destination with WAL sidecars "
            f"({names}). Stop vpw serve and preserve the complete data directory first."
        )
    if not destination.exists():
        return
    try:
        with closing(sqlite3.connect(destination, timeout=0.1)) as connection:
            connection.execute("BEGIN EXCLUSIVE")
            connection.rollback()
    except sqlite3.Error as exc:
        raise SystemExit(
            "Refusing to restore over a SQLite destination that cannot be locked "
            f"exclusively. Stop vpw serve first: {exc}"
        ) from exc


if __name__ == "__main__":
    raise SystemExit(main())

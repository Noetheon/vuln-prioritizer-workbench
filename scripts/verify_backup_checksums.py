"""Create and verify private SHA-256 checksums for Workbench backup files."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path

SCHEMA = "vpw-backup-checksums.v1"
BACKUP_NAMES = {"workbench.db", "workbench.dump", "artifacts.tar", "backup-manifest.json"}
CHECKSUM_NAME = "backup-checksums.json"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _files(directory: Path) -> set[str]:
    if (directory / CHECKSUM_NAME).is_symlink():
        raise ValueError("Backup checksum file must not be a symlink.")
    for name in BACKUP_NAMES:
        if (directory / name).is_symlink():
            raise ValueError("Backup file must not be a symlink.")
    return {name for name in BACKUP_NAMES if (directory / name).is_file()}


def _create(directory: Path) -> None:
    files = _files(directory)
    if not files.intersection({"workbench.db", "workbench.dump"}):
        raise ValueError("Backup has no database file.")
    output = directory / CHECKSUM_NAME
    payload = {
        "schema": SCHEMA,
        "sha256": {name: _sha256(directory / name) for name in sorted(files)},
    }
    output.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")
    if os.name != "nt":
        output.chmod(0o600)


def _verify(directory: Path) -> None:
    payload = json.loads((directory / CHECKSUM_NAME).read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or payload.get("schema") != SCHEMA:
        raise ValueError("Unsupported backup checksum file.")
    recorded = payload.get("sha256")
    if not isinstance(recorded, dict) or not recorded:
        raise ValueError("Backup checksum list is empty or malformed.")
    files = _files(directory)
    if set(recorded) != files or not files.intersection({"workbench.db", "workbench.dump"}):
        raise ValueError("Backup files differ from the checksum list.")
    for name, expected in recorded.items():
        if (
            not isinstance(expected, str)
            or len(expected) != 64
            or _sha256(directory / name) != expected
        ):
            raise ValueError(f"Backup checksum mismatch: {name}.")


def main() -> int:
    """Create or verify checksums without exposing backup content."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("create", "verify"))
    parser.add_argument("backup_dir", type=Path)
    args = parser.parse_args()
    directory = args.backup_dir.expanduser().resolve(strict=True)
    try:
        if args.action == "create":
            _create(directory)
        else:
            _verify(directory)
    except (OSError, ValueError) as exc:
        raise SystemExit(f"Backup checksum verification failed: {exc}") from exc
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Verified backups of a local ``vpw serve`` data directory."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import stat
import uuid
import zipfile
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from tempfile import TemporaryDirectory
from typing import TYPE_CHECKING, Any

from sqlmodel import Session, select

from app.models import Report

if TYPE_CHECKING:
    # Imported for typing only: loading app.core.config reads the process
    # environment, which ``vpw restore`` prepares only after unpacking.
    from app.core.config import Settings

BACKUP_FORMAT = "vpw-backup.v1"
MANIFEST_NAME = "backup-manifest.json"
DATABASE_NAME = "workbench.db"
ARTIFACT_DIRECTORIES = ("imports", "reports", "provider-snapshots")
CACHE_DIRECTORY = "provider-cache"
_RESTORABLE_DIRECTORIES = frozenset((*ARTIFACT_DIRECTORIES, CACHE_DIRECTORY))
_CHUNK_SIZE = 1024 * 1024


class BackupError(ValueError):
    """Raised when a backup cannot be written or an archive cannot be trusted."""


@dataclass(frozen=True, slots=True)
class BackupResult:
    """Summary of a written or restored backup."""

    path: Path
    files: int
    bytes: int
    database_revision: str | None


def create_backup(
    data_root: Path,
    output: Path,
    *,
    package_version: str,
    include_cache: bool = False,
    created_at: datetime | None = None,
) -> BackupResult:
    """
    Write a zip archive with a consistent database copy and the local artifacts.

    The database is copied with SQLite's online backup API, so a running
    Workbench keeps serving while the copy stays transactionally consistent.
    """
    database = data_root / DATABASE_NAME
    if not database.is_file():
        raise BackupError(f"No Workbench database found at {database}.")
    if output.exists():
        raise BackupError(f"Refusing to overwrite an existing file: {output}.")
    output.parent.mkdir(parents=True, exist_ok=True)
    directories = (*ARTIFACT_DIRECTORIES, *((CACHE_DIRECTORY,) if include_cache else ()))
    with TemporaryDirectory(dir=output.parent, prefix=".vpw-backup-") as staging:
        snapshot = Path(staging) / DATABASE_NAME
        _copy_database(database, snapshot)
        revision = database_revision(snapshot)
        entries = [(DATABASE_NAME, snapshot), *_artifact_entries(data_root, directories)]
        files: list[dict[str, Any]] = []
        total_bytes = 0
        partial = Path(staging) / "archive.zip"
        with zipfile.ZipFile(partial, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
            for name, path in entries:
                # Hash what is archived, so a file changing mid-backup cannot
                # leave the manifest disagreeing with the archive.
                digest, size = _write_entry(bundle, name, path)
                files.append({"path": name, "sha256": digest, "size": size})
                total_bytes += size
            manifest = {
                "format": BACKUP_FORMAT,
                "created_at": (created_at or datetime.now(UTC)).isoformat(),
                "package_version": package_version,
                "database_revision": revision,
                "data_root": str(data_root),
                "includes_provider_cache": include_cache,
                "files": files,
            }
            bundle.writestr(MANIFEST_NAME, json.dumps(manifest, indent=2, sort_keys=True))
        _restrict(partial, 0o600)
        os.replace(partial, output)
    return BackupResult(
        path=output,
        files=len(files),
        bytes=total_bytes,
        database_revision=revision,
    )


def read_manifest(archive: Path) -> dict[str, Any]:
    """Return the validated manifest of a backup archive."""
    with zipfile.ZipFile(archive) as bundle:
        return _validated_manifest(bundle)


def restore_backup(archive: Path, target_root: Path) -> BackupResult:
    """
    Unpack a verified archive into a new or empty data directory.

    Every entry must be listed in the manifest with a matching checksum, stay
    inside the known data directory layout, and be a regular file. Nothing is
    moved into place until every file has been verified.
    """
    if target_root.exists() and any(target_root.iterdir()):
        raise BackupError(f"Restore target must be a new or empty directory: {target_root}.")
    target_existed = target_root.exists()
    with zipfile.ZipFile(archive) as bundle:
        manifest = _validated_manifest(bundle)
        expected = {str(item["path"]): item for item in manifest["files"]}
        target_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        staging = target_root / f".vpw-restore-{uuid.uuid4().hex}"
        try:
            for name, item in sorted(expected.items()):
                destination = staging.joinpath(*PurePosixPath(name).parts)
                destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                digest = _extract_verified(bundle, name, destination, int(item["size"]))
                if digest != item["sha256"]:
                    raise BackupError(f"Checksum mismatch for {name}; the archive is damaged.")
                _restrict(destination, 0o600)
            for child in sorted(staging.iterdir()):
                os.replace(child, target_root / child.name)
        except BaseException:
            shutil.rmtree(staging, ignore_errors=True)
            _discard_restored_entries(target_root, remove_root=not target_existed)
            raise
        staging.rmdir()
    return BackupResult(
        path=target_root,
        files=len(expected),
        bytes=sum(int(item["size"]) for item in expected.values()),
        database_revision=manifest.get("database_revision"),
    )


def rebase_report_paths(
    session: Session,
    settings: Settings,
    *,
    previous_root: str | None,
) -> int:
    """
    Point stored report paths at this data directory after a restore.

    Report rows record absolute artifact paths, so a backup restored into
    another directory would otherwise lose its report downloads. Returns the
    number of updated rows; the caller commits.
    """
    if not previous_root:
        return 0
    old_root = Path(previous_root) / "reports"
    new_root = settings.report_dir_path.resolve(strict=False)
    if old_root == new_root:
        return 0
    updated = 0
    for report in session.exec(select(Report)).all():
        path = Path(report.path)
        if path.is_absolute() and path.is_relative_to(old_root):
            report.path = str(new_root / path.relative_to(old_root))
            session.add(report)
            updated += 1
    return updated


def database_revision(database: Path) -> str | None:
    """Return the Alembic revision recorded in a SQLite database, if any."""
    connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
    try:
        row = connection.execute("SELECT version_num FROM alembic_version").fetchone()
    except sqlite3.Error:
        return None
    finally:
        connection.close()
    return str(row[0]) if row else None


def database_integrity_ok(database: Path) -> bool:
    """Return whether SQLite reports the database as intact."""
    connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
    try:
        row = connection.execute("PRAGMA integrity_check").fetchone()
    finally:
        connection.close()
    return bool(row) and row[0] == "ok"


def _copy_database(source: Path, target: Path) -> None:
    source_connection = sqlite3.connect(source)
    target_connection = sqlite3.connect(target)
    try:
        with target_connection:
            source_connection.backup(target_connection)
    finally:
        target_connection.close()
        source_connection.close()
    _restrict(target, 0o600)


def _artifact_entries(data_root: Path, directories: tuple[str, ...]) -> Iterator[tuple[str, Path]]:
    for directory in directories:
        root = data_root / directory
        if not root.is_dir() or root.is_symlink():
            continue
        for path in sorted(root.rglob("*")):
            if path.is_symlink() or not path.is_file():
                continue
            yield path.relative_to(data_root).as_posix(), path


def _validated_manifest(bundle: zipfile.ZipFile) -> dict[str, Any]:
    try:
        manifest = json.loads(bundle.read(MANIFEST_NAME))
    except KeyError as exc:
        raise BackupError("The archive has no backup manifest.") from exc
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise BackupError("The backup manifest is not valid JSON.") from exc
    if not isinstance(manifest, dict) or manifest.get("format") != BACKUP_FORMAT:
        raise BackupError(f"Unsupported backup format; expected {BACKUP_FORMAT}.")
    files = manifest.get("files")
    if not isinstance(files, list) or not all(isinstance(item, dict) for item in files):
        raise BackupError("The backup manifest does not list its files.")
    listed: set[str] = set()
    for item in files:
        name = item.get("path")
        if not isinstance(name, str) or not _safe_entry_name(name) or name in listed:
            raise BackupError(f"Unsafe or duplicate path in backup manifest: {name!r}.")
        if not isinstance(item.get("sha256"), str) or not isinstance(item.get("size"), int):
            raise BackupError(f"Incomplete manifest entry for {name}.")
        listed.add(name)
    if DATABASE_NAME not in listed:
        raise BackupError("The backup does not contain a Workbench database.")
    entries: set[str] = set()
    for info in bundle.infolist():
        if info.filename == MANIFEST_NAME:
            continue
        if info.is_dir():
            continue
        mode = (info.external_attr >> 16) & 0o170000
        if mode and not stat.S_ISREG(mode):
            raise BackupError(f"Backup entry is not a regular file: {info.filename}.")
        entries.add(info.filename)
    if entries != listed:
        raise BackupError("Backup entries do not match the manifest.")
    return manifest


def _safe_entry_name(name: str) -> bool:
    if not name or "\\" in name or name.startswith("/") or ":" in name:
        return False
    parts = PurePosixPath(name).parts
    if any(part in {"", ".", ".."} for part in parts):
        return False
    if parts == (DATABASE_NAME,):
        return True
    return len(parts) >= 2 and parts[0] in _RESTORABLE_DIRECTORIES


def _extract_verified(
    bundle: zipfile.ZipFile,
    name: str,
    destination: Path,
    expected_size: int,
) -> str:
    digest = hashlib.sha256()
    written = 0
    with bundle.open(name) as source, destination.open("xb") as target:
        while chunk := source.read(_CHUNK_SIZE):
            written += len(chunk)
            if written > expected_size:
                raise BackupError(f"{name} is larger than its manifest entry.")
            digest.update(chunk)
            target.write(chunk)
    if written != expected_size:
        raise BackupError(f"{name} does not match its manifest size.")
    return digest.hexdigest()


def _discard_restored_entries(target_root: Path, *, remove_root: bool) -> None:
    if remove_root:
        shutil.rmtree(target_root, ignore_errors=True)
        return
    for child in target_root.iterdir():
        if child.is_dir() and not child.is_symlink():
            shutil.rmtree(child, ignore_errors=True)
        else:
            child.unlink(missing_ok=True)


def _write_entry(bundle: zipfile.ZipFile, name: str, path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    info = zipfile.ZipInfo.from_file(path, arcname=name)
    info.compress_type = zipfile.ZIP_DEFLATED
    with path.open("rb") as source, bundle.open(info, "w", force_zip64=True) as target:
        while chunk := source.read(_CHUNK_SIZE):
            digest.update(chunk)
            size += len(chunk)
            target.write(chunk)
    return digest.hexdigest(), size


def _restrict(path: Path, mode: int) -> None:
    if os.name != "nt":
        path.chmod(mode)

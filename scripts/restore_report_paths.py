"""
Verify backed-up reports and prepare a relocatable SQLite restore copy.

The backup manifest is private metadata. It records the report root needed to
translate absolute report paths when a Workbench data directory is restored at
a different location. No database rows or artifact contents are written to it.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import tarfile
from contextlib import closing
from pathlib import Path, PurePosixPath

MANIFEST_SCHEMA = "vpw-sqlite-backup.v1"
REPORT_ROOT_NAMES = ("reports", "workbench-reports")
UPLOAD_ROOT_NAMES = ("imports", "workbench-import-uploads")


def _sha256_stream(source: object) -> str:
    digest = hashlib.sha256()
    for chunk in iter(lambda: source.read(1024 * 1024), b""):  # type: ignore[attr-defined]
        digest.update(chunk)
    return digest.hexdigest()


def _manifest(report_root: Path, output: Path, upload_root: Path | None = None) -> None:
    root = report_root.expanduser().resolve(strict=False)
    if root.name not in REPORT_ROOT_NAMES:
        raise ValueError("An absolute managed reports root is required.")
    upload = (upload_root or root.parent / "imports").expanduser().resolve(strict=False)
    if upload.name not in UPLOAD_ROOT_NAMES:
        raise ValueError("An absolute managed imports root is required.")
    payload = {
        "schema": MANIFEST_SCHEMA,
        "report_root": str(root),
        "report_archive_root": root.name,
        "upload_archive_root": upload.name,
    }
    output.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")
    if os.name != "nt":
        output.chmod(0o600)


def _roots(
    manifest: Path | None,
    destination_root: Path,
    rows: list[tuple[str, str, str, int]],
) -> tuple[Path, Path, str, str]:
    if manifest is None or not manifest.is_file():
        for name in REPORT_ROOT_NAMES:
            candidate = destination_root / name
            if all(
                Path(raw_path).is_absolute()
                and Path(raw_path).resolve(strict=False).is_relative_to(candidate)
                for _, raw_path, _, _ in rows
            ):
                return candidate, candidate, name, "imports"
        raise ValueError("Legacy backup report root differs from restore root.")
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or payload.get("schema") != MANIFEST_SCHEMA:
        raise ValueError("Unsupported SQLite backup manifest.")
    raw_root = payload.get("report_root")
    if not isinstance(raw_root, str) or not Path(raw_root).is_absolute():
        raise ValueError("SQLite backup manifest has no absolute report root.")
    root = Path(raw_root).resolve(strict=False)
    report_name = payload.get("report_archive_root", root.name)
    upload_name = payload.get("upload_archive_root", "imports")
    if (
        root.name not in REPORT_ROOT_NAMES
        or report_name != root.name
        or upload_name not in UPLOAD_ROOT_NAMES
    ):
        raise ValueError("SQLite backup manifest has an unexpected report root.")
    return root, destination_root / report_name, report_name, upload_name


def _report_rows(connection: sqlite3.Connection) -> list[tuple[str, str, str, int]]:
    exists = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='report'"
    ).fetchone()
    if not exists:
        return []
    return list(connection.execute("SELECT id, path, sha256, size_bytes FROM report"))


def _archive_members(archive_path: Path) -> dict[PurePosixPath, tarfile.TarInfo]:
    members: dict[PurePosixPath, tarfile.TarInfo] = {}
    with tarfile.open(archive_path, "r:*") as archive:
        for member in archive:
            relative = PurePosixPath(member.name)
            if relative.is_absolute() or ".." in relative.parts or "\\" in member.name:
                raise ValueError("Artifact archive has an unsafe member path.")
            if not relative.parts:
                continue
            if relative in members:
                raise ValueError("Artifact archive has a duplicate member.")
            members[relative] = member
    return members


def _upload_rows(connection: sqlite3.Connection) -> list[dict[str, object]]:
    exists = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='analysis_evidence'"
    ).fetchone()
    if not exists:
        return []
    uploads: list[dict[str, object]] = []
    for (raw,) in connection.execute("SELECT payload_json FROM analysis_evidence"):
        payload = json.loads(raw) if isinstance(raw, str) else raw
        if not isinstance(payload, dict):
            raise ValueError("Analysis evidence payload is malformed.")
        entries = payload.get("uploads") or {}
        if not isinstance(entries, dict):
            raise ValueError("Analysis evidence uploads are malformed.")
        uploads.extend(
            item
            for item in entries.values()
            if isinstance(item, dict) and (item.get("storage_ref") or item.get("path"))
        )
    return uploads


def _verified_member(
    archive: tarfile.TarFile,
    members: dict[PurePosixPath, tarfile.TarInfo],
    relative: PurePosixPath,
    *,
    size: int | None,
    sha256: str | None,
) -> None:
    member = members.get(relative)
    if member is None or not member.isfile():
        raise ValueError("Referenced artifact is missing from the backup archive.")
    if size is not None and member.size != size:
        raise ValueError("Archived artifact size differs from database metadata.")
    if sha256 is not None:
        content = archive.extractfile(member)
        if content is None:
            raise ValueError("Archived artifact could not be read.")
        with content:
            if _sha256_stream(content) != sha256:
                raise ValueError("Archived artifact hash differs from database metadata.")


def _prepare(
    database: Path,
    archive_path: Path | None,
    manifest: Path | None,
    destination_root: Path,
    output: Path,
) -> tuple[int, int]:
    if output.exists():
        raise ValueError("Prepared SQLite destination already exists.")
    destination_root = destination_root.expanduser().resolve(strict=False)
    backup_uri = f"{database.expanduser().resolve(strict=True).as_uri()}?mode=ro"
    try:
        with (
            closing(sqlite3.connect(backup_uri, uri=True)) as source,
            closing(sqlite3.connect(output)) as staged,
        ):
            source.backup(staged)
            rows = _report_rows(staged)
            uploads = _upload_rows(staged)
            source_report_root, target_report_root, report_name, upload_name = _roots(
                manifest, destination_root, rows
            )
            if (rows or uploads) and (archive_path is None or not archive_path.is_file()):
                raise ValueError("Backup has managed artifact references but no archive.")
            if rows or uploads:
                assert archive_path is not None
                members = _archive_members(archive_path)
                with tarfile.open(archive_path, "r:*") as archive:
                    staged.execute("BEGIN IMMEDIATE")
                    for report_id, raw_path, expected_sha, expected_size in rows:
                        path = Path(raw_path)
                        if not path.is_absolute() or ".." in path.parts:
                            raise ValueError("Backup has a non-absolute or unsafe report path.")
                        try:
                            relative = path.resolve(strict=False).relative_to(source_report_root)
                        except ValueError as exc:
                            raise ValueError(
                                "Backup report path is outside its recorded root."
                            ) from exc
                        if not relative.parts:
                            raise ValueError("Backup report path names a directory.")
                        _verified_member(
                            archive,
                            members,
                            PurePosixPath(report_name, *relative.parts),
                            size=expected_size,
                            sha256=expected_sha,
                        )
                        target = target_report_root.joinpath(*relative.parts).resolve(strict=False)
                        if not target.is_relative_to(target_report_root):
                            raise ValueError("Relocated report path escapes its destination root.")
                        changed = staged.execute(
                            "UPDATE report SET path=? WHERE id=? AND path=?",
                            (str(target), report_id, raw_path),
                        ).rowcount
                        if changed != 1:
                            raise ValueError("Report path update did not affect exactly one row.")
                    for upload in uploads:
                        raw_ref = upload.get("storage_ref") or upload.get("path")
                        if not isinstance(raw_ref, str) or "\\" in raw_ref:
                            raise ValueError("Managed upload has a non-portable reference.")
                        reference = PurePosixPath(raw_ref)
                        if (
                            reference.is_absolute()
                            or ".." in reference.parts
                            or not reference.parts
                        ):
                            raise ValueError("Managed upload has an unsafe reference.")
                        size = upload.get("size_bytes")
                        sha256 = upload.get("sha256")
                        _verified_member(
                            archive,
                            members,
                            PurePosixPath(upload_name, *reference.parts),
                            size=size
                            if isinstance(size, int) and not isinstance(size, bool)
                            else None,
                            sha256=sha256 if isinstance(sha256, str) and sha256 else None,
                        )
                    staged.commit()
            if staged.execute("PRAGMA integrity_check").fetchone() != ("ok",):
                raise ValueError("Prepared SQLite database failed integrity_check.")
            if staged.execute("PRAGMA foreign_key_check").fetchone() is not None:
                raise ValueError("Prepared SQLite database failed foreign_key_check.")
            return len(rows), len(uploads)
    except (OSError, sqlite3.Error, tarfile.TarError, ValueError):
        output.unlink(missing_ok=True)
        raise


def main() -> int:
    """Write a backup manifest or prepare a verified SQLite restore copy."""
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    manifest = commands.add_parser("manifest")
    manifest.add_argument("report_root", type=Path)
    manifest.add_argument("output", type=Path)
    manifest.add_argument("--upload-root", type=Path)
    prepare = commands.add_parser("prepare")
    prepare.add_argument("database", type=Path)
    prepare.add_argument("destination_root", type=Path)
    prepare.add_argument("output", type=Path)
    prepare.add_argument("--archive", type=Path)
    prepare.add_argument("--manifest", type=Path)
    args = parser.parse_args()
    try:
        if args.action == "manifest":
            _manifest(args.report_root, args.output, args.upload_root)
        else:
            reports, uploads = _prepare(
                args.database, args.archive, args.manifest, args.destination_root, args.output
            )
            print(
                f"Verified {reports} archived report and {uploads} managed upload "
                "reference(s) for SQLite restore."
            )
    except (OSError, sqlite3.Error, tarfile.TarError, ValueError) as exc:
        raise SystemExit(f"Report restore preparation failed: {exc}") from exc
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

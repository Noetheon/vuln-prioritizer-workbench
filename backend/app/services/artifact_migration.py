"""Safe artifact staging and verification for Compose-to-local migrations."""

from __future__ import annotations

import hashlib
import shutil
import tarfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from sqlalchemy import Engine
from sqlmodel import Session, select

from app.models import AnalysisEvidence, Report

COMPOSE_ARTIFACT_ROOTS = {
    "workbench-import-uploads": "imports",
    "workbench-reports": "reports",
    "provider-snapshots": "provider-snapshots",
    "workbench-provider-cache": "provider-cache",
}
MAX_ARCHIVE_MEMBERS = 100_000
MAX_ARCHIVE_BYTES = 1 << 40


class ArtifactMigrationInvariantError(RuntimeError):
    """Raised when migrated artifacts are unsafe, missing, or inconsistent."""


@dataclass(frozen=True, slots=True)
class ArtifactMigrationResult:
    """Verified staged-artifact summary."""

    files: int
    bytes: int
    verified_reports: int
    verified_uploads: int


def required_artifact_references(engine: Engine) -> int:
    """Return the number of persisted report and managed-upload references."""
    with Session(engine) as session:
        reports = list(session.exec(select(Report)).all())
        evidence_rows = list(session.exec(select(AnalysisEvidence)).all())
    return len(reports) + sum(_upload_refs(row.payload_json) for row in evidence_rows)


def stage_and_verify_compose_artifacts(
    archive_path: Path,
    staging_root: Path,
    *,
    target_engine: Engine,
    final_data_root: Path,
) -> ArtifactMigrationResult:
    """Extract a Compose backup safely and verify every persisted artifact reference."""
    archive = archive_path.expanduser().resolve(strict=True)
    staging = staging_root.resolve(strict=False)
    if staging.exists():
        raise ArtifactMigrationInvariantError(f"Artifact staging path already exists: {staging}.")
    for target_name in COMPOSE_ARTIFACT_ROOTS.values():
        (staging / target_name).mkdir(mode=0o700, parents=True, exist_ok=True)

    files = 0
    total_bytes = 0
    seen: set[PurePosixPath] = set()
    try:
        with tarfile.open(archive, mode="r:*") as bundle:
            members = bundle.getmembers()
            if len(members) > MAX_ARCHIVE_MEMBERS:
                raise ArtifactMigrationInvariantError(
                    f"Artifact archive exceeds {MAX_ARCHIVE_MEMBERS} members."
                )
            for member in members:
                relative = _validated_member_path(member)
                if relative is None:
                    continue
                if relative in seen:
                    raise ArtifactMigrationInvariantError(
                        f"Artifact archive repeats member {relative.as_posix()}."
                    )
                seen.add(relative)
                mapped = _mapped_staging_path(staging, relative)
                if member.isdir():
                    mapped.mkdir(mode=0o700, parents=True, exist_ok=True)
                    continue
                if not member.isfile():
                    raise ArtifactMigrationInvariantError(
                        f"Artifact archive member is not a regular file: {member.name}."
                    )
                total_bytes += member.size
                if total_bytes > MAX_ARCHIVE_BYTES:
                    raise ArtifactMigrationInvariantError("Artifact archive is too large.")
                mapped.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                source = bundle.extractfile(member)
                if source is None:
                    raise ArtifactMigrationInvariantError(
                        f"Artifact archive member could not be read: {member.name}."
                    )
                with source, mapped.open("xb") as destination:
                    shutil.copyfileobj(source, destination, length=1024 * 1024)
                mapped.chmod(0o600)
                files += 1
    except (OSError, tarfile.TarError) as exc:
        raise ArtifactMigrationInvariantError(
            f"Artifact archive could not be staged: {exc}."
        ) from exc

    reports, uploads = _verify_persisted_artifacts(
        target_engine,
        staging,
        final_data_root=final_data_root.resolve(strict=False),
    )
    return ArtifactMigrationResult(
        files=files,
        bytes=total_bytes,
        verified_reports=reports,
        verified_uploads=uploads,
    )


def activate_staged_artifacts(staging_root: Path, final_data_root: Path) -> None:
    """Move verified artifact directories into a new local runtime directory."""
    staging = staging_root.resolve(strict=True)
    destination_root = final_data_root.resolve(strict=False)
    for target_name in COMPOSE_ARTIFACT_ROOTS.values():
        source = staging / target_name
        destination = destination_root / target_name
        if destination.exists():
            shutil.rmtree(destination)
        source.replace(destination)
    staging.rmdir()


def _validated_member_path(member: tarfile.TarInfo) -> PurePosixPath | None:
    normalized = member.name.removeprefix("./")
    if normalized in {"", "."}:
        return None
    if "\\" in normalized:
        raise ArtifactMigrationInvariantError(
            f"Artifact archive has a non-portable member path: {member.name}."
        )
    path = PurePosixPath(normalized)
    if path.is_absolute() or ".." in path.parts:
        raise ArtifactMigrationInvariantError(
            f"Artifact archive has an unsafe member path: {member.name}."
        )
    if not path.parts or path.parts[0] not in COMPOSE_ARTIFACT_ROOTS:
        raise ArtifactMigrationInvariantError(
            f"Artifact archive has an unexpected root: {member.name}."
        )
    if member.issym() or member.islnk():
        raise ArtifactMigrationInvariantError(
            f"Artifact archive links are not allowed: {member.name}."
        )
    return path


def _mapped_staging_path(staging_root: Path, path: PurePosixPath) -> Path:
    target_root = staging_root / COMPOSE_ARTIFACT_ROOTS[path.parts[0]]
    mapped = target_root.joinpath(*path.parts[1:]).resolve(strict=False)
    if not mapped.is_relative_to(target_root.resolve(strict=False)):
        raise ArtifactMigrationInvariantError(
            f"Artifact path escaped its target root: {path.as_posix()}."
        )
    return mapped


def _verify_persisted_artifacts(
    engine: Engine,
    staging_root: Path,
    *,
    final_data_root: Path,
) -> tuple[int, int]:
    verified_reports = 0
    verified_uploads = 0
    final_report_root = (final_data_root / "reports").resolve(strict=False)
    staged_report_root = (staging_root / "reports").resolve(strict=True)
    staged_upload_root = (staging_root / "imports").resolve(strict=True)
    with Session(engine) as session:
        for report in session.exec(select(Report)).all():
            final_path = Path(report.path).resolve(strict=False)
            if not final_path.is_relative_to(final_report_root):
                raise ArtifactMigrationInvariantError(
                    f"Migrated report path is outside the target root: {report.id}."
                )
            staged_path = staged_report_root / final_path.relative_to(final_report_root)
            _verify_file(staged_path, size=report.size_bytes, sha256=report.sha256)
            verified_reports += 1
        for evidence in session.exec(select(AnalysisEvidence)).all():
            uploads = dict(evidence.payload_json.get("uploads") or {})
            for raw_upload in uploads.values():
                if not isinstance(raw_upload, dict):
                    continue
                reference = raw_upload.get("storage_ref") or raw_upload.get("path")
                if not isinstance(reference, str) or not reference:
                    continue
                if "\\" in reference:
                    raise ArtifactMigrationInvariantError(
                        f"Managed upload reference is non-portable: {reference}."
                    )
                relative = PurePosixPath(reference)
                if relative.is_absolute() or ".." in relative.parts:
                    raise ArtifactMigrationInvariantError(
                        f"Managed upload reference is unsafe: {reference}."
                    )
                staged_path = staged_upload_root.joinpath(*relative.parts).resolve(strict=False)
                if not staged_path.is_relative_to(staged_upload_root):
                    raise ArtifactMigrationInvariantError(
                        f"Managed upload escaped the target root: {reference}."
                    )
                _verify_file(
                    staged_path,
                    size=_optional_int(raw_upload.get("size_bytes")),
                    sha256=_optional_str(raw_upload.get("sha256")),
                )
                verified_uploads += 1
    return verified_reports, verified_uploads


def _verify_file(path: Path, *, size: int | None, sha256: str | None) -> None:
    if not path.is_file():
        raise ArtifactMigrationInvariantError(f"Required artifact is missing: {path}.")
    if size is not None and path.stat().st_size != size:
        raise ArtifactMigrationInvariantError(f"Artifact size mismatch: {path}.")
    if sha256 is not None and _file_sha256(path) != sha256:
        raise ArtifactMigrationInvariantError(f"Artifact checksum mismatch: {path}.")


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _upload_refs(payload: dict[str, Any]) -> int:
    uploads = dict(payload.get("uploads") or {})
    return sum(
        1
        for item in uploads.values()
        if isinstance(item, dict) and (item.get("storage_ref") or item.get("path"))
    )


def _optional_int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _optional_str(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None

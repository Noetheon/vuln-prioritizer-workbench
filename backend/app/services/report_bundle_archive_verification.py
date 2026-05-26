"""Evidence bundle verification helpers."""
# ruff: noqa: F401,F403,F405,I001,E501

from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path

from pydantic import ValidationError

from vuln_prioritizer.models import (
    EvidenceBundleFile,
    EvidenceBundleManifest,
    EvidenceBundleVerificationItem,
    EvidenceBundleVerificationMetadata,
    EvidenceBundleVerificationSummary,
)
from vuln_prioritizer.utils import iso_utc_now

DETERMINISTIC_ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
DETERMINISTIC_ZIP_FILE_MODE = 0o644 << 16
DETECTION_COVERAGE_BUNDLE_PATH = "governance/detection-coverage.json"
DETECTION_COVERAGE_BUNDLE_KIND = "governance-detection-coverage"
MAX_EVIDENCE_BUNDLE_MEMBERS = 100
MAX_EVIDENCE_BUNDLE_MANIFEST_BYTES = 1024 * 1024
MAX_EVIDENCE_BUNDLE_MEMBER_BYTES = 50 * 1024 * 1024
MAX_EVIDENCE_BUNDLE_TOTAL_BYTES = 200 * 1024 * 1024
_HASH_CHUNK_BYTES = 1024 * 1024


def verify_evidence_bundle(
    bundle_path: Path,
) -> tuple[
    EvidenceBundleVerificationMetadata,
    EvidenceBundleVerificationSummary,
    list[EvidenceBundleVerificationItem],
]:
    """Verify evidence bundle function."""
    try:
        with zipfile.ZipFile(bundle_path, "r") as archive:
            member_infos = [info for info in archive.infolist() if not info.is_dir()]
            member_paths = sorted(info.filename for info in member_infos)
            metadata = EvidenceBundleVerificationMetadata(
                generated_at=iso_utc_now(),
                bundle_path=str(bundle_path),
            )
            archive_limit_errors = _archive_limit_errors(member_infos)
            if archive_limit_errors:
                summary = EvidenceBundleVerificationSummary(
                    ok=False,
                    total_members=len(member_paths),
                    manifest_errors=len(archive_limit_errors),
                )
                return metadata, summary, archive_limit_errors

            if "manifest.json" not in member_paths:
                items = [
                    EvidenceBundleVerificationItem(
                        path="manifest.json",
                        status="missing",
                        detail="Bundle does not contain manifest.json.",
                    )
                ]
                summary = EvidenceBundleVerificationSummary(
                    ok=False,
                    total_members=len(member_paths),
                    manifest_errors=1,
                    missing_files=1,
                )
                return metadata, summary, items

            try:
                manifest_payload = json.loads(
                    _read_limited_member(
                        archive,
                        "manifest.json",
                        max_bytes=MAX_EVIDENCE_BUNDLE_MANIFEST_BYTES,
                    )
                )
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
                items = [
                    EvidenceBundleVerificationItem(
                        path="manifest.json",
                        status="error",
                        detail=f"Manifest is not valid JSON: {str(exc)}.",
                    )
                ]
                summary = EvidenceBundleVerificationSummary(
                    ok=False,
                    total_members=len(member_paths),
                    manifest_errors=1,
                )
                return metadata, summary, items

            if not isinstance(manifest_payload, dict):
                items = [
                    EvidenceBundleVerificationItem(
                        path="manifest.json",
                        status="error",
                        detail="Manifest must decode to a JSON object.",
                    )
                ]
                summary = EvidenceBundleVerificationSummary(
                    ok=False,
                    total_members=len(member_paths),
                    manifest_errors=1,
                )
                return metadata, summary, items

            try:
                manifest = EvidenceBundleManifest.model_validate(manifest_payload)
            except ValidationError as exc:
                items = [
                    EvidenceBundleVerificationItem(
                        path="manifest.json",
                        status="error",
                        detail=format_evidence_manifest_validation_error(exc),
                    )
                ]
                summary = EvidenceBundleVerificationSummary(
                    ok=False,
                    total_members=len(member_paths),
                    manifest_errors=1,
                )
                return metadata, summary, items

            metadata = EvidenceBundleVerificationMetadata(
                generated_at=iso_utc_now(),
                bundle_path=str(bundle_path),
                manifest_schema_version=manifest.schema_version,
                bundle_kind=manifest.bundle_kind,
            )

            manifest_errors = validate_evidence_manifest_structure(manifest)
            if manifest_errors:
                summary = EvidenceBundleVerificationSummary(
                    ok=False,
                    total_members=len(member_paths),
                    expected_files=len(manifest.files),
                    manifest_errors=len(manifest_errors),
                )
                return metadata, summary, manifest_errors

            items = []
            verified_files = 0
            missing_files = 0
            modified_files = 0
            actual_members = set(member_paths)
            expected_paths = {entry.path for entry in manifest.files}
            for expected in manifest.files:
                if expected.path not in actual_members:
                    missing_files += 1
                    items.append(
                        EvidenceBundleVerificationItem(
                            path=expected.path,
                            kind=expected.kind,
                            status="missing",
                            detail="Archive member declared in manifest is missing.",
                            expected_size_bytes=expected.size_bytes,
                            expected_sha256=expected.sha256,
                        )
                    )
                    continue

                member_info = archive.getinfo(expected.path)
                if member_info.file_size > MAX_EVIDENCE_BUNDLE_MEMBER_BYTES:
                    modified_files += 1
                    items.append(
                        EvidenceBundleVerificationItem(
                            path=expected.path,
                            kind=expected.kind,
                            status="error",
                            detail=(
                                "Archive member exceeds verifier size limit and was not "
                                "decompressed."
                            ),
                            expected_size_bytes=expected.size_bytes,
                            actual_size_bytes=member_info.file_size,
                            expected_sha256=expected.sha256,
                        )
                    )
                    continue
                try:
                    actual_size, actual_sha256 = _hash_limited_member(archive, expected.path)
                except ValueError as exc:
                    modified_files += 1
                    items.append(
                        EvidenceBundleVerificationItem(
                            path=expected.path,
                            kind=expected.kind,
                            status="error",
                            detail=str(exc),
                            expected_size_bytes=expected.size_bytes,
                            actual_size_bytes=member_info.file_size,
                            expected_sha256=expected.sha256,
                        )
                    )
                    continue
                if actual_size != expected.size_bytes or actual_sha256 != expected.sha256:
                    modified_files += 1
                    items.append(
                        EvidenceBundleVerificationItem(
                            path=expected.path,
                            kind=expected.kind,
                            status="modified",
                            detail=describe_evidence_bundle_mismatch(
                                expected=expected,
                                actual_size=actual_size,
                                actual_sha256=actual_sha256,
                            ),
                            expected_size_bytes=expected.size_bytes,
                            actual_size_bytes=actual_size,
                            expected_sha256=expected.sha256,
                            actual_sha256=actual_sha256,
                        )
                    )
                    continue

                verified_files += 1
                items.append(
                    EvidenceBundleVerificationItem(
                        path=expected.path,
                        kind=expected.kind,
                        status="ok",
                        detail="Archive member matches the manifest checksum.",
                        expected_size_bytes=expected.size_bytes,
                        actual_size_bytes=actual_size,
                        expected_sha256=expected.sha256,
                        actual_sha256=actual_sha256,
                    )
                )

            unexpected_members = sorted(
                path
                for path in member_paths
                if path not in expected_paths and path != "manifest.json"
            )
            for unexpected_path in unexpected_members:
                member_info = archive.getinfo(unexpected_path)
                unexpected_sha256: str | None = None
                detail = "Archive member is present but not declared in manifest."
                if member_info.file_size <= MAX_EVIDENCE_BUNDLE_MEMBER_BYTES:
                    try:
                        _actual_size, unexpected_sha256 = _hash_limited_member(
                            archive,
                            unexpected_path,
                        )
                    except ValueError:
                        detail += " Member exceeds verifier size limit and was not fully hashed."
                else:
                    detail += " Member exceeds verifier size limit and was not decompressed."
                items.append(
                    EvidenceBundleVerificationItem(
                        path=unexpected_path,
                        status="unexpected",
                        detail=detail,
                        actual_size_bytes=member_info.file_size,
                        actual_sha256=unexpected_sha256,
                    )
                )

            summary = EvidenceBundleVerificationSummary(
                ok=not (missing_files or modified_files or unexpected_members),
                total_members=len(member_paths),
                expected_files=len(manifest.files),
                verified_files=verified_files,
                missing_files=missing_files,
                modified_files=modified_files,
                unexpected_files=len(unexpected_members),
                manifest_errors=0,
            )
            return metadata, summary, items
    except zipfile.BadZipFile as exc:
        raise ValueError(f"{bundle_path} is not a valid ZIP archive: {exc}.") from exc


def _archive_limit_errors(
    member_infos: list[zipfile.ZipInfo],
) -> list[EvidenceBundleVerificationItem]:
    """Archive limit errors function."""
    errors: list[EvidenceBundleVerificationItem] = []
    if len(member_infos) > MAX_EVIDENCE_BUNDLE_MEMBERS:
        errors.append(
            EvidenceBundleVerificationItem(
                path="*",
                status="error",
                detail=(
                    f"Archive contains {len(member_infos)} members, exceeding the "
                    f"{MAX_EVIDENCE_BUNDLE_MEMBERS} member verifier limit."
                ),
            )
        )
    total_uncompressed = sum(info.file_size for info in member_infos)
    if total_uncompressed > MAX_EVIDENCE_BUNDLE_TOTAL_BYTES:
        errors.append(
            EvidenceBundleVerificationItem(
                path="*",
                status="error",
                detail=(
                    f"Archive uncompressed size {total_uncompressed} exceeds the "
                    f"{MAX_EVIDENCE_BUNDLE_TOTAL_BYTES} byte verifier limit."
                ),
                actual_size_bytes=total_uncompressed,
            )
        )
    manifest_info = next((info for info in member_infos if info.filename == "manifest.json"), None)
    if manifest_info is not None and manifest_info.file_size > MAX_EVIDENCE_BUNDLE_MANIFEST_BYTES:
        errors.append(
            EvidenceBundleVerificationItem(
                path="manifest.json",
                status="error",
                detail="Manifest exceeds verifier size limit and was not decompressed.",
                actual_size_bytes=manifest_info.file_size,
            )
        )
    return errors


def _read_limited_member(
    archive: zipfile.ZipFile,
    path: str,
    *,
    max_bytes: int,
) -> bytes:
    """Read limited member function."""
    content = bytearray()
    with archive.open(path, "r") as handle:
        for chunk in iter(lambda: handle.read(_HASH_CHUNK_BYTES), b""):
            content.extend(chunk)
            if len(content) > max_bytes:
                raise ValueError(f"{path} exceeds verifier size limit.")
    return bytes(content)


def _hash_limited_member(archive: zipfile.ZipFile, path: str) -> tuple[int, str]:
    """Hash limited member function."""
    digest = hashlib.sha256()
    consumed = 0
    with archive.open(path, "r") as handle:
        for chunk in iter(lambda: handle.read(_HASH_CHUNK_BYTES), b""):
            consumed += len(chunk)
            if consumed > MAX_EVIDENCE_BUNDLE_MEMBER_BYTES:
                raise ValueError(f"{path} exceeds verifier size limit.")
            digest.update(chunk)
    return consumed, digest.hexdigest()


def validate_evidence_manifest_structure(
    manifest: EvidenceBundleManifest,
) -> list[EvidenceBundleVerificationItem]:
    """Validate evidence manifest structure function."""
    errors: list[EvidenceBundleVerificationItem] = []
    seen_paths: set[str] = set()
    for entry in manifest.files:
        if entry.path == "manifest.json":
            errors.append(
                EvidenceBundleVerificationItem(
                    path="manifest.json",
                    kind=entry.kind,
                    status="error",
                    detail="Manifest must not declare manifest.json as a bundle member.",
                )
            )
        if entry.path in seen_paths:
            errors.append(
                EvidenceBundleVerificationItem(
                    path=entry.path,
                    kind=entry.kind,
                    status="error",
                    detail="Manifest declares the same bundle member path more than once.",
                )
            )
        seen_paths.add(entry.path)
    return errors


def format_evidence_manifest_validation_error(exc: ValidationError) -> str:
    """Format evidence manifest validation error function."""
    if not exc.errors():
        return "Manifest failed validation."
    first_error = exc.errors()[0]
    location = ".".join(str(part) for part in first_error.get("loc", ())) or "manifest"
    message = first_error.get("msg", "validation error")
    return f"Manifest failed validation at {location}: {message}."


def describe_evidence_bundle_mismatch(
    *,
    expected: EvidenceBundleFile,
    actual_size: int,
    actual_sha256: str,
) -> str:
    """Describe evidence bundle mismatch function."""
    mismatches: list[str] = []
    if actual_size != expected.size_bytes:
        mismatches.append(f"size {actual_size} != manifest {expected.size_bytes}")
    if actual_sha256 != expected.sha256:
        mismatches.append("sha256 mismatch")
    if not mismatches:
        return "Archive member does not match the manifest."
    return "Archive member does not match the manifest: " + ", ".join(mismatches) + "."


__all__ = [
    "DETECTION_COVERAGE_BUNDLE_KIND",
    "DETECTION_COVERAGE_BUNDLE_PATH",
    "DETERMINISTIC_ZIP_FILE_MODE",
    "DETERMINISTIC_ZIP_TIMESTAMP",
    "describe_evidence_bundle_mismatch",
    "format_evidence_manifest_validation_error",
    "validate_evidence_manifest_structure",
    "verify_evidence_bundle",
]

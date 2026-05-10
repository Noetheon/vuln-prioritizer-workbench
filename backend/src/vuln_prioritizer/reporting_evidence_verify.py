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


def verify_evidence_bundle(
    bundle_path: Path,
) -> tuple[
    EvidenceBundleVerificationMetadata,
    EvidenceBundleVerificationSummary,
    list[EvidenceBundleVerificationItem],
]:
    try:
        with zipfile.ZipFile(bundle_path, "r") as archive:
            member_paths = sorted(info.filename for info in archive.infolist() if not info.is_dir())
            metadata = EvidenceBundleVerificationMetadata(
                generated_at=iso_utc_now(),
                bundle_path=str(bundle_path),
            )

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
                manifest_payload = json.loads(archive.read("manifest.json"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
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

                content = archive.read(expected.path)
                actual_size = len(content)
                actual_sha256 = hashlib.sha256(content).hexdigest()
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
                items.append(
                    EvidenceBundleVerificationItem(
                        path=unexpected_path,
                        status="unexpected",
                        detail="Archive member is present but not declared in manifest.",
                        actual_size_bytes=archive.getinfo(unexpected_path).file_size,
                        actual_sha256=hashlib.sha256(archive.read(unexpected_path)).hexdigest(),
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


def validate_evidence_manifest_structure(
    manifest: EvidenceBundleManifest,
) -> list[EvidenceBundleVerificationItem]:
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

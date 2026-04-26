"""Evidence bundle creation and verification helpers."""

from __future__ import annotations

import hashlib
import json
import zipfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from vuln_prioritizer.models import (
    EvidenceBundleFile,
    EvidenceBundleInputHash,
    EvidenceBundleManifest,
    EvidenceBundleVerificationItem,
    EvidenceBundleVerificationMetadata,
    EvidenceBundleVerificationSummary,
)
from vuln_prioritizer.reporter import (
    generate_evidence_bundle_manifest_json,
    generate_html_report,
    generate_summary_markdown,
)
from vuln_prioritizer.utils import iso_utc_now

DETERMINISTIC_ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
DETERMINISTIC_ZIP_FILE_MODE = 0o644 << 16


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


def write_evidence_bundle(
    *,
    analysis_path: Path,
    output_path: Path,
    payload: dict[str, Any],
    include_input_copy: bool,
    warning_callback: Callable[[str], None] | None = None,
) -> EvidenceBundleManifest:
    metadata = payload.get("metadata", {})
    attack_summary = payload.get("attack_summary", {})
    bundle_entries: list[tuple[str, bytes, str]] = [
        ("analysis.json", analysis_path.read_bytes(), "analysis-json"),
        ("report.html", generate_html_report(payload).encode("utf-8"), "html-report"),
        ("summary.md", generate_summary_markdown(payload).encode("utf-8"), "markdown-summary"),
    ]
    navigator_layer = attack_navigator_layer_from_summary(attack_summary)
    if navigator_layer is not None:
        bundle_entries.append(
            (
                "attack-navigator-layer.json",
                json.dumps(navigator_layer, indent=2, sort_keys=True).encode("utf-8"),
                "attack-navigator-layer",
            )
        )
    reported_input_paths = analysis_input_paths(metadata)
    resolved_inputs = [
        resolved_input
        for reported_path in reported_input_paths
        if (resolved_input := resolve_analysis_input_path(reported_path, analysis_path)) is not None
    ]
    included_input_copy = False
    if include_input_copy:
        if resolved_inputs:
            multiple_inputs = len(reported_input_paths) > 1
            for index, resolved_input in enumerate(resolved_inputs, start=1):
                bundle_entries.append(
                    (
                        source_input_bundle_path(
                            resolved_input,
                            index=index,
                            multiple=multiple_inputs,
                        ),
                        resolved_input.read_bytes(),
                        "source-input",
                    )
                )
            included_input_copy = True
        elif reported_input_paths and warning_callback is not None:
            warning_callback(
                "Referenced input file(s) could not be resolved; bundle will omit the "
                "original input copy."
            )

    file_entries = [
        bundle_file_entry(path=path, content=content, kind=kind)
        for path, content, kind in bundle_entries
    ]
    input_hashes = [input_hash_entry(path) for path in resolved_inputs]
    manifest = EvidenceBundleManifest(
        generated_at=iso_utc_now(),
        source_analysis_path=str(analysis_path),
        source_analysis_sha256=hashlib.sha256(analysis_path.read_bytes()).hexdigest(),
        source_input_path=reported_input_paths[0] if reported_input_paths else None,
        source_input_paths=reported_input_paths,
        source_input_hashes=input_hashes,
        provider_snapshot=provider_snapshot_manifest_entry(metadata, analysis_path=analysis_path),
        artifact_hashes={entry.path: entry.sha256 for entry in file_entries},
        findings_count=int(metadata.get("findings_count", 0)),
        kev_hits=int(metadata.get("kev_hits", 0)),
        waived_count=int(metadata.get("waived_count", 0)),
        attack_mapped_cves=int(attack_summary.get("mapped_cves", 0)),
        included_input_copy=included_input_copy,
        files=file_entries,
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path, content, _kind in bundle_entries:
            write_deterministic_zip_member(archive, path, content)
        write_deterministic_zip_member(
            archive,
            "manifest.json",
            generate_evidence_bundle_manifest_json(manifest).encode("utf-8"),
        )
    return manifest


def write_deterministic_zip_member(
    archive: zipfile.ZipFile,
    path: str,
    content: bytes,
) -> None:
    info = zipfile.ZipInfo(filename=path, date_time=DETERMINISTIC_ZIP_TIMESTAMP)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3
    info.external_attr = DETERMINISTIC_ZIP_FILE_MODE
    archive.writestr(info, content)


def analysis_input_paths(metadata: object) -> list[str]:
    if not isinstance(metadata, dict):
        return []

    input_paths = metadata.get("input_paths")
    if isinstance(input_paths, list):
        normalized = [
            item.strip() for item in input_paths if isinstance(item, str) and item.strip()
        ]
        if normalized:
            return normalized

    input_path = metadata.get("input_path")
    if isinstance(input_path, str) and input_path.strip():
        return [input_path.strip()]
    return []


def attack_navigator_layer_from_summary(attack_summary: object) -> dict[str, Any] | None:
    if not isinstance(attack_summary, dict):
        return None
    technique_distribution = attack_summary.get("technique_distribution")
    if not isinstance(technique_distribution, dict) or not technique_distribution:
        return None
    techniques: list[dict[str, Any]] = [
        {
            "techniqueID": technique_id,
            "score": count,
            "comment": f"Observed in {count} mapped CVE(s).",
        }
        for technique_id, count in sorted(
            (
                (str(key), int(value))
                for key, value in technique_distribution.items()
                if str(key).strip() and isinstance(value, int | float) and int(value) > 0
            ),
            key=lambda item: (-item[1], item[0]),
        )
    ]
    if not techniques:
        return None
    max_score = max(int(item["score"]) for item in techniques)
    return {
        "name": "vuln-prioritizer ATT&CK coverage",
        "version": "4.5",
        "domain": "enterprise-attack",
        "description": (
            "Navigator layer generated from approved ATT&CK mappings in the evidence bundle."
        ),
        "gradient": {
            "colors": ["#dfe7fd", "#4c6ef5"],
            "minValue": 0,
            "maxValue": max_score,
        },
        "techniques": techniques,
        "legendItems": [{"label": "Mapped technique", "color": "#4c6ef5"}],
        "showTacticRowBackground": True,
        "selectTechniquesAcrossTactics": True,
    }


def source_input_bundle_path(resolved_input: Path, *, index: int, multiple: bool) -> str:
    if multiple:
        return f"input/{index:03d}-{resolved_input.name}"
    return f"input/{resolved_input.name}"


def input_hash_entry(path: Path) -> EvidenceBundleInputHash:
    content = path.read_bytes()
    return EvidenceBundleInputHash(
        path=str(path),
        size_bytes=len(content),
        sha256=hashlib.sha256(content).hexdigest(),
    )


def provider_snapshot_manifest_entry(metadata: object, *, analysis_path: Path) -> dict[str, Any]:
    if not isinstance(metadata, dict):
        return {}
    snapshot_path = metadata.get("provider_snapshot_file")
    snapshot_hash = metadata.get("provider_snapshot_hash")
    if snapshot_hash is None:
        resolved_snapshot = resolve_analysis_input_path(snapshot_path, analysis_path)
        if resolved_snapshot is not None:
            snapshot_hash = hashlib.sha256(resolved_snapshot.read_bytes()).hexdigest()
    entry = {
        "id": metadata.get("provider_snapshot_id"),
        "sha256": snapshot_hash,
        "path": snapshot_path,
        "sources": metadata.get("provider_snapshot_sources", []),
    }
    return {key: value for key, value in entry.items() if value not in (None, "", [])}


def resolve_analysis_input_path(reported_path: object, analysis_path: Path) -> Path | None:
    if not isinstance(reported_path, str) or not reported_path.strip():
        return None
    candidate = Path(reported_path).expanduser()
    paths = (
        [candidate]
        if candidate.is_absolute()
        else [Path.cwd() / candidate, analysis_path.parent / candidate]
    )
    for path in paths:
        resolved = path.resolve()
        if resolved.is_file():
            return resolved
    return None


def bundle_file_entry(*, path: str, content: bytes, kind: str) -> EvidenceBundleFile:
    return EvidenceBundleFile(
        path=path,
        kind=kind,
        size_bytes=len(content),
        sha256=hashlib.sha256(content).hexdigest(),
    )


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

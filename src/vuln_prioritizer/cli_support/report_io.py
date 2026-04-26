"""Report and evidence bundle CLI support helpers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from vuln_prioritizer.models import (
    EvidenceBundleManifest,
    EvidenceBundleVerificationItem,
    EvidenceBundleVerificationMetadata,
    EvidenceBundleVerificationSummary,
)
from vuln_prioritizer.reporting_evidence import (
    DETERMINISTIC_ZIP_FILE_MODE,
    DETERMINISTIC_ZIP_TIMESTAMP,
    analysis_input_paths,
    attack_navigator_layer_from_summary,
    bundle_file_entry,
    describe_evidence_bundle_mismatch,
    format_evidence_manifest_validation_error,
    input_hash_entry,
    provider_snapshot_manifest_entry,
    resolve_analysis_input_path,
    source_input_bundle_path,
    validate_evidence_manifest_structure,
    write_deterministic_zip_member,
)
from vuln_prioritizer.reporting_evidence import (
    verify_evidence_bundle as _verify_evidence_bundle,
)
from vuln_prioritizer.reporting_evidence import (
    write_evidence_bundle as _write_evidence_bundle,
)

from .common import console, exit_input_validation

__all__ = [
    "DETERMINISTIC_ZIP_FILE_MODE",
    "DETERMINISTIC_ZIP_TIMESTAMP",
    "analysis_input_paths",
    "attack_navigator_layer_from_summary",
    "bundle_file_entry",
    "describe_evidence_bundle_mismatch",
    "format_evidence_manifest_validation_error",
    "input_hash_entry",
    "load_analysis_report_payload",
    "provider_snapshot_manifest_entry",
    "resolve_analysis_input_path",
    "source_input_bundle_path",
    "validate_evidence_manifest_structure",
    "verify_evidence_bundle",
    "write_deterministic_zip_member",
    "write_evidence_bundle",
]


def load_analysis_report_payload(input_path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(input_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        exit_input_validation(f"{input_path} is not valid JSON: {exc.msg}.")

    if not isinstance(payload, dict):
        exit_input_validation(
            "report commands expect an analysis JSON export produced by `analyze`."
        )

    metadata = payload.get("metadata")
    findings = payload.get("findings")
    if not isinstance(metadata, dict) or not isinstance(findings, list):
        exit_input_validation(
            "report commands expect an analysis JSON export produced by `analyze`."
        )
    return payload


def verify_evidence_bundle(
    bundle_path: Path,
) -> tuple[
    EvidenceBundleVerificationMetadata,
    EvidenceBundleVerificationSummary,
    list[EvidenceBundleVerificationItem],
]:
    try:
        return _verify_evidence_bundle(bundle_path)
    except ValueError as exc:
        exit_input_validation(str(exc))


def write_evidence_bundle(
    *,
    analysis_path: Path,
    output_path: Path,
    payload: dict[str, Any],
    include_input_copy: bool,
) -> EvidenceBundleManifest:
    return _write_evidence_bundle(
        analysis_path=analysis_path,
        output_path=output_path,
        payload=payload,
        include_input_copy=include_input_copy,
        warning_callback=lambda message: console.print(f"[yellow]{message}[/yellow]"),
    )

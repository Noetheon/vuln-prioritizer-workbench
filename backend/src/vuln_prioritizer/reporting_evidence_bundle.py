"""Evidence bundle creation helpers."""
# ruff: noqa: F401,F403,F405,I001,E501

from __future__ import annotations

import hashlib
import json
import zipfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

from vuln_prioritizer.models import (
    EvidenceBundleGovernanceArtifact,
    EvidenceBundleManifest,
)
from vuln_prioritizer.reporter import (
    generate_evidence_bundle_manifest_json,
    generate_html_report,
    generate_summary_markdown,
)
from vuln_prioritizer.reporting_evidence_archive import (
    DETERMINISTIC_ZIP_FILE_MODE,
    DETERMINISTIC_ZIP_TIMESTAMP,
    bundle_file_entry,
    redacted_file_bytes,
    write_deterministic_zip_member,
)
from vuln_prioritizer.reporting_evidence_attack import attack_navigator_layer_from_summary
from vuln_prioritizer.reporting_evidence_governance import (
    DETECTION_COVERAGE_BUNDLE_KIND,
    DETECTION_COVERAGE_BUNDLE_PATH,
    detection_coverage_export,
    detection_coverage_summary_counts,
)
from vuln_prioritizer.reporting_evidence_inputs import (
    analysis_input_paths,
    input_hash_entry,
    resolve_analysis_input_path,
    safe_source_path_label,
    source_input_bundle_path,
)
from vuln_prioritizer.reporting_evidence_provider import (
    provider_snapshot_manifest_entry,
    resolve_provider_snapshot_path,
)
from vuln_prioritizer.security_redaction import redact_value
from vuln_prioritizer.utils import iso_utc_now


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
    redacted_payload, redaction_paths = redact_value(payload)
    if not isinstance(redacted_payload, dict):
        redacted_payload = {}
    redacted_analysis_bytes = json.dumps(redacted_payload, indent=2, sort_keys=True).encode("utf-8")
    bundle_entries: list[tuple[str, bytes, str]] = [
        ("analysis.json", redacted_analysis_bytes, "analysis-json"),
        ("report.html", generate_html_report(redacted_payload).encode("utf-8"), "html-report"),
        (
            "summary.md",
            generate_summary_markdown(redacted_payload).encode("utf-8"),
            "markdown-summary",
        ),
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
    governance_artifacts: list[EvidenceBundleGovernanceArtifact] = []
    detection_coverage = detection_coverage_export(redacted_payload)
    if detection_coverage is not None:
        bundle_entries.append(
            (
                DETECTION_COVERAGE_BUNDLE_PATH,
                json.dumps(detection_coverage, indent=2, sort_keys=True).encode("utf-8"),
                DETECTION_COVERAGE_BUNDLE_KIND,
            )
        )
    provider_snapshot_bundle_path = None
    provider_snapshot_path = resolve_provider_snapshot_path(
        metadata.get("provider_snapshot_file") if isinstance(metadata, dict) else None,
        analysis_path,
    )
    if provider_snapshot_path is not None:
        provider_snapshot_bundle_path = "provider/provider-snapshot.json"
        provider_snapshot_bytes, provider_snapshot_redacted = redacted_file_bytes(
            provider_snapshot_path
        )
        if provider_snapshot_redacted:
            redaction_paths.append(provider_snapshot_bundle_path)
        bundle_entries.append(
            (
                provider_snapshot_bundle_path,
                provider_snapshot_bytes,
                "provider-snapshot",
            )
        )
    elif (
        isinstance(metadata, dict)
        and metadata.get("provider_snapshot_file")
        and warning_callback is not None
    ):
        warning_callback(
            "Referenced provider snapshot could not be resolved; bundle will omit the "
            "snapshot copy."
        )
    reported_input_paths = analysis_input_paths(metadata)
    resolved_inputs = [
        resolved_input
        for reported_path in reported_input_paths
        if (resolved_input := resolve_analysis_input_path(reported_path, analysis_path)) is not None
    ]
    included_input_copy = False
    input_manifest_paths: dict[Path, str] = {}
    if include_input_copy:
        if resolved_inputs:
            multiple_inputs = len(reported_input_paths) > 1
            for index, resolved_input in enumerate(resolved_inputs, start=1):
                bundle_path = source_input_bundle_path(
                    resolved_input,
                    index=index,
                    multiple=multiple_inputs,
                )
                input_bytes, input_redacted = redacted_file_bytes(resolved_input)
                if input_redacted:
                    redaction_paths.append(bundle_path)
                bundle_entries.append(
                    (
                        bundle_path,
                        input_bytes,
                        "source-input",
                    )
                )
                input_manifest_paths[resolved_input] = bundle_path
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
    artifact_hashes = {entry.path: entry.sha256 for entry in file_entries}
    if DETECTION_COVERAGE_BUNDLE_PATH in artifact_hashes:
        governance_artifacts.append(
            EvidenceBundleGovernanceArtifact(
                bundle_path=DETECTION_COVERAGE_BUNDLE_PATH,
                kind=DETECTION_COVERAGE_BUNDLE_KIND,
                sha256=artifact_hashes[DETECTION_COVERAGE_BUNDLE_PATH],
            )
        )
    source_input_paths = [
        input_manifest_paths.get(resolved_input, safe_source_path_label(resolved_input))
        if (resolved_input := resolve_analysis_input_path(reported_path, analysis_path)) is not None
        else safe_source_path_label(reported_path)
        for reported_path in reported_input_paths
    ]
    input_hashes = [
        input_hash_entry(
            path,
            manifest_path=input_manifest_paths.get(path, safe_source_path_label(path)),
        )
        for path in resolved_inputs
    ]
    manifest = EvidenceBundleManifest(
        generated_at=iso_utc_now(),
        source_analysis_path="analysis.json",
        source_analysis_sha256=hashlib.sha256(analysis_path.read_bytes()).hexdigest(),
        source_input_path=source_input_paths[0] if source_input_paths else None,
        source_input_paths=source_input_paths,
        source_input_hashes=input_hashes,
        provider_snapshot=provider_snapshot_manifest_entry(
            metadata,
            analysis_path=analysis_path,
            bundle_path=provider_snapshot_bundle_path,
            bundle_sha256=artifact_hashes.get(provider_snapshot_bundle_path or ""),
        ),
        governance_artifacts=governance_artifacts,
        artifact_hashes=artifact_hashes,
        findings_count=int(metadata.get("findings_count", 0)),
        kev_hits=int(metadata.get("kev_hits", 0)),
        waived_count=int(metadata.get("waived_count", 0)),
        attack_mapped_cves=int(attack_summary.get("mapped_cves", 0)),
        included_input_copy=included_input_copy,
        redaction={
            "enabled": True,
            "policy": (
                "sensitive keys, local paths, and secret-shaped text are redacted "
                "in copied artifacts and manifest source references"
            ),
            "redacted_keys": sorted(set(redaction_paths)),
        },
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


__all__ = [
    "DETECTION_COVERAGE_BUNDLE_KIND",
    "DETECTION_COVERAGE_BUNDLE_PATH",
    "DETERMINISTIC_ZIP_FILE_MODE",
    "DETERMINISTIC_ZIP_TIMESTAMP",
    "analysis_input_paths",
    "attack_navigator_layer_from_summary",
    "bundle_file_entry",
    "detection_coverage_export",
    "detection_coverage_summary_counts",
    "input_hash_entry",
    "provider_snapshot_manifest_entry",
    "redacted_file_bytes",
    "resolve_analysis_input_path",
    "safe_source_path_label",
    "source_input_bundle_path",
    "write_deterministic_zip_member",
    "write_evidence_bundle",
]

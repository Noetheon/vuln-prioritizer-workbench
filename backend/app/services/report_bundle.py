"""Evidence bundle Workbench report renderer."""

from __future__ import annotations

import json
import zipfile
from io import BytesIO
from pathlib import Path
from typing import Any

from app.services.report_bundle_archive import (
    _bundle_file_entry,
    _bundle_input_hashes,
    _json_bytes,
    _safe_bundle_filename,
    _write_deterministic_zip_member,
)
from app.services.report_bundle_governance import (
    _asset_context_rows,
    _governance_asset_context_export,
    _governance_bundle_entries,
    _governance_detection_coverage_export,
    _governance_finding_row,
    _governance_rollups_export,
    _governance_vex_export,
    _governance_waivers_export,
)
from app.services.report_bundle_verification import _evidence_bundle_verification_payload
from app.services.report_contracts import (
    EVIDENCE_BUNDLE_MANIFEST_SCHEMA_VERSION,
    REPORT_FILENAME_ATTACK_NAVIGATOR,
    REPORT_KIND_ATTACK_NAVIGATOR,
    REPORT_KIND_EVIDENCE_BUNDLE,
)
from app.services.report_exports import render_analysis_result_json
from app.services.report_formatting import iso_datetime as _iso_datetime
from app.services.report_html import render_html_executive_report
from app.services.report_markdown import render_markdown_report
from app.services.report_models import MarkdownReportPayload, ReportVerificationError
from app.services.report_projection import _analysis_provider_snapshot
from app.services.report_renderer_common import (
    _boolish_signal,
    _redact_bundle_value,
    _redacted_bundle_payload,
)
from vuln_prioritizer.reporting_evidence import (
    verify_evidence_bundle as verify_evidence_bundle_archive,
)


def render_evidence_bundle_zip(
    payload: MarkdownReportPayload,
    *,
    attack_navigator_layer: dict[str, Any] | None = None,
) -> tuple[bytes, dict[str, Any]]:
    """Render a deterministic evidence ZIP and return its manifest payload."""
    bundle_payload, payload_redactions = _redacted_bundle_payload(payload)
    analysis_payload = json.loads(render_analysis_result_json(bundle_payload))
    redacted_analysis, analysis_redactions = _redact_bundle_value(analysis_payload)
    provider_payload = _analysis_provider_snapshot(bundle_payload.provider_snapshot) or {
        "available": False
    }
    redacted_provider, provider_redactions = _redact_bundle_value(provider_payload)

    entries = [
        (
            "analysis.json",
            _json_bytes(redacted_analysis),
            "analysis-json",
        ),
        (
            "technical.md",
            render_markdown_report(bundle_payload).encode("utf-8"),
            "technical-markdown",
        ),
        (
            "executive.html",
            render_html_executive_report(bundle_payload).encode("utf-8"),
            "executive-html",
        ),
        (
            "provider-snapshot.json",
            _json_bytes(redacted_provider),
            "provider-snapshot",
        ),
    ]
    governance_entries = _governance_bundle_entries(bundle_payload)
    entries.extend(governance_entries)
    if attack_navigator_layer is not None:
        redacted_layer, layer_redactions = _redact_bundle_value(
            attack_navigator_layer,
            path_prefix="attack_navigator_layer",
        )
        provider_redactions.extend(layer_redactions)
        entries.append(
            (
                REPORT_FILENAME_ATTACK_NAVIGATOR,
                _json_bytes(redacted_layer),
                REPORT_KIND_ATTACK_NAVIGATOR,
            )
        )
    file_entries = [
        _bundle_file_entry(path=path, content=content, kind=kind) for path, content, kind in entries
    ]
    artifact_hashes = {entry["path"]: entry["sha256"] for entry in file_entries}
    input_hashes = _bundle_input_hashes(payload)
    source_input_paths = [item["path"] for item in input_hashes]
    manifest: dict[str, Any] = {
        "schema_version": EVIDENCE_BUNDLE_MANIFEST_SCHEMA_VERSION,
        "bundle_kind": REPORT_KIND_EVIDENCE_BUNDLE,
        "generated_at": _iso_datetime(payload.generated_at),
        "source_analysis_path": "analysis.json",
        "source_analysis_sha256": artifact_hashes["analysis.json"],
        "source_input_path": source_input_paths[0] if source_input_paths else None,
        "source_input_paths": source_input_paths,
        "source_input_hashes": input_hashes,
        "provider_snapshot": {
            "bundle_path": "provider-snapshot.json",
            "sha256": artifact_hashes["provider-snapshot.json"],
            "content_hash": bundle_payload.provider_snapshot.content_hash
            if bundle_payload.provider_snapshot is not None
            else None,
            "id": bundle_payload.provider_snapshot.id
            if bundle_payload.provider_snapshot is not None
            else None,
        },
        "artifact_hashes": artifact_hashes,
        "findings_count": len(bundle_payload.findings),
        "kev_hits": sum(1 for finding in bundle_payload.findings if finding.in_kev),
        "waived_count": sum(
            1 for finding in bundle_payload.findings if _boolish_signal(finding, "waived")
        ),
        "attack_mapped_cves": sum(
            1 for finding in bundle_payload.findings if _boolish_signal(finding, "attack_mapped")
        ),
        "included_input_copy": False,
        "redaction": {
            "enabled": True,
            "policy": "sensitive keys and local path fields are replaced with [REDACTED]",
            "redacted_keys": sorted(
                set(payload_redactions + analysis_redactions + provider_redactions)
            ),
        },
        "files": file_entries,
    }
    if governance_entries:
        manifest["governance_artifacts"] = [
            {
                "bundle_path": path,
                "kind": kind,
                "sha256": artifact_hashes[path],
            }
            for path, _content, kind in governance_entries
        ]
    if REPORT_FILENAME_ATTACK_NAVIGATOR in artifact_hashes:
        manifest["attack_navigator_layer"] = {
            "bundle_path": REPORT_FILENAME_ATTACK_NAVIGATOR,
            "sha256": artifact_hashes[REPORT_FILENAME_ATTACK_NAVIGATOR],
        }

    output = BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path, content, _kind in entries:
            _write_deterministic_zip_member(archive, path, content)
        _write_deterministic_zip_member(archive, "manifest.json", _json_bytes(manifest))
    return output.getvalue(), manifest


def verify_evidence_bundle_zip(
    bundle_path: Path,
    *,
    display_path: str | None = None,
) -> dict[str, Any]:
    """Verify an evidence bundle ZIP and return the published report contract."""
    try:
        metadata, summary, items = verify_evidence_bundle_archive(bundle_path)
    except ValueError as exc:
        raise ReportVerificationError(str(exc)) from exc
    return _evidence_bundle_verification_payload(
        metadata,
        summary,
        items,
        display_path=display_path,
    )


__all__ = [
    "_asset_context_rows",
    "_bundle_file_entry",
    "_bundle_input_hashes",
    "_governance_asset_context_export",
    "_governance_bundle_entries",
    "_governance_detection_coverage_export",
    "_governance_finding_row",
    "_governance_rollups_export",
    "_governance_vex_export",
    "_governance_waivers_export",
    "_json_bytes",
    "_safe_bundle_filename",
    "_write_deterministic_zip_member",
    "render_evidence_bundle_zip",
    "verify_evidence_bundle_zip",
]

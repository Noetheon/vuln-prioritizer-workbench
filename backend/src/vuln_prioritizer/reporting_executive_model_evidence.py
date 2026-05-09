"""Executive report evidence model builders."""
# ruff: noqa: F401,F403,F405,I001,E501

from __future__ import annotations

from typing import Any

from vuln_prioritizer.reporting_executive_model_artifacts import *
from vuln_prioritizer.reporting_executive_model_artifacts import (
    _artifact_model,
    _bundle_contents_model,
)
from vuln_prioritizer.reporting_executive_model_helpers import _provider_evidence_notes
from vuln_prioritizer.reporting_executive_model_provider import *
from vuln_prioritizer.reporting_executive_model_provider import _provider_freshness_rows
from vuln_prioritizer.reporting_executive_model_quality import *
from vuln_prioritizer.reporting_executive_model_quality import (
    _mapping_confidence_model,
    _quality_rows,
)
from vuln_prioritizer.reporting_executive_utils import (
    _dict_value,
    _int_value,
    _provider_value,
    _text,
)


def _evidence_model(
    metadata: dict[str, Any],
    findings: list[dict[str, Any]],
    reports: list[Any],
    evidence_bundles: list[Any],
    provider_snapshot: Any | None,
) -> dict[str, Any]:
    freshness = [
        {"label": "Provider snapshot", "value": _text(metadata.get("provider_snapshot_file"))},
        {
            "label": "Locked provider data",
            "value": "yes" if metadata.get("locked_provider_data") else "no",
        },
        {"label": "NVD last sync", "value": _provider_value(provider_snapshot, "nvd_last_sync")},
        {"label": "EPSS date", "value": _provider_value(provider_snapshot, "epss_date")},
        {
            "label": "KEV catalog",
            "value": _provider_value(provider_snapshot, "kev_catalog_version"),
        },
    ]
    warnings = [str(item) for item in metadata.get("warnings", []) if item]
    provider_notes = _provider_evidence_notes(findings)
    source_formats = sorted(
        {
            str(source)
            for finding in findings
            for source in _dict_value(finding.get("provenance")).get("source_formats", [])
            if source
        }
    )
    quality_notes = warnings + [
        f"Duplicate CVEs collapsed: {_int_value(metadata.get('duplicate_cve_count'))}",
        f"Asset-context conflicts: {_int_value(metadata.get('asset_match_conflict_count'))}",
        f"VEX conflicts: {_int_value(metadata.get('vex_conflict_count'))}",
    ]
    if source_formats:
        quality_notes.append("Source formats: " + ", ".join(source_formats))
    quality_notes.extend(provider_notes)
    artifacts = _artifact_model(reports, evidence_bundles)
    return {
        "freshness": freshness,
        "quality_notes": quality_notes,
        "artifacts": artifacts,
        "provider_rows": _provider_freshness_rows(metadata, provider_snapshot),
        "quality_rows": _quality_rows(metadata, findings),
        "mapping_confidence": _mapping_confidence_model(findings),
        "bundle_contents": _bundle_contents_model(artifacts),
    }


__all__ = [
    "_artifact_model",
    "_bundle_contents_model",
    "_evidence_model",
    "_input_sources_model",
    "_mapping_confidence_model",
    "_methodology_model",
    "_provider_freshness_rows",
    "_provider_transparency_model",
    "_quality_rows",
    "_workspace_nav",
]

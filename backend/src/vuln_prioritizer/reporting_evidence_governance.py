"""Governance artifact helpers for CLI evidence bundles."""

from __future__ import annotations

from typing import Any

from vuln_prioritizer.utils import iso_utc_now

DETECTION_COVERAGE_BUNDLE_PATH = "governance/detection-coverage.json"
DETECTION_COVERAGE_BUNDLE_KIND = "governance-detection-coverage"


def detection_coverage_export(payload: dict[str, Any]) -> dict[str, Any] | None:
    coverage = payload.get("detection_coverage")
    if not isinstance(coverage, dict):
        return None
    items = [item for item in coverage.get("items", []) if isinstance(item, dict)]
    controls = [item for item in coverage.get("controls", []) if isinstance(item, dict)]
    summary = coverage.get("summary")
    if not isinstance(summary, dict):
        summary = {}
    if not items and not controls:
        return None
    metadata = payload.get("metadata")
    metadata = metadata if isinstance(metadata, dict) else {}
    return {
        "schema": "detection-coverage.v1",
        "schema_version": "1.0.0",
        "generated_at": iso_utc_now(),
        "project_id": metadata.get("project_id"),
        "run_id": metadata.get("analysis_run_id") or metadata.get("run_id"),
        "summary": detection_coverage_summary_counts(summary),
        "items": items,
        "controls": controls,
        "limitations": [
            (
                "Detection coverage is operator-supplied defensive review evidence; it is "
                "not proof that exploitation did or did not occur."
            ),
            (
                "Partial, missing, and unknown coverage identify review gaps that still need "
                "SOC validation or compensating-control documentation."
            ),
        ],
    }


def detection_coverage_summary_counts(summary: dict[Any, Any]) -> dict[str, int]:
    return {
        str(key): int(value)
        for key, value in sorted(summary.items(), key=lambda item: str(item[0]))
        if str(key).strip() and isinstance(value, int | float)
    }


__all__ = [
    "DETECTION_COVERAGE_BUNDLE_KIND",
    "DETECTION_COVERAGE_BUNDLE_PATH",
    "detection_coverage_export",
    "detection_coverage_summary_counts",
]

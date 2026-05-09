"""Artifact, input source, methodology, and navigation model builders."""

from __future__ import annotations

from typing import Any

from vuln_prioritizer.reporting_executive_model_helpers import _occurrences
from vuln_prioritizer.reporting_executive_utils import (
    _attr,
    _basename,
    _dict_value,
    _sha_preview,
    _text,
)


def _bundle_contents_model(artifacts: list[dict[str, str]]) -> dict[str, Any]:
    if not artifacts:
        return {
            "generated": False,
            "items": [
                {
                    "name": "analysis.json",
                    "detail": "not generated for this run",
                    "size": "not supplied",
                },
                {
                    "name": "summary.md",
                    "detail": "not generated for this run",
                    "size": "not supplied",
                },
                {
                    "name": "provider-snapshot.json",
                    "detail": "not generated for this run",
                    "size": "not supplied",
                },
                {
                    "name": "sha256-manifest.txt",
                    "detail": "not generated for this run",
                    "size": "not supplied",
                },
            ],
        }
    return {
        "generated": True,
        "items": [
            {"name": item["label"], "detail": item["detail"], "size": "downloadable"}
            for item in artifacts
        ],
    }


def _input_sources_model(
    metadata: dict[str, Any], findings: list[dict[str, Any]]
) -> list[dict[str, str]]:
    sources = metadata.get("input_sources")
    rows: list[dict[str, str]] = []
    if isinstance(sources, list):
        for source in sources:
            if not isinstance(source, dict):
                continue
            rows.append(
                {
                    "input": _basename(source.get("input_path") or source.get("path")),
                    "format": _text(source.get("input_format") or source.get("format")),
                    "rows": _text(source.get("total_rows"), default="not supplied"),
                    "occurrences": _text(source.get("occurrence_count"), default="not supplied"),
                    "cves": _text(source.get("unique_cves"), default="not supplied"),
                }
            )
    if not rows:
        rows.append(
            {
                "input": _basename(metadata.get("input_path")) or "not supplied",
                "format": _text(metadata.get("input_format")),
                "rows": _text(metadata.get("total_input"), default="not supplied"),
                "occurrences": str(sum(len(_occurrences(item)) for item in findings)),
                "cves": _text(metadata.get("valid_input"), default=str(len(findings))),
            }
        )
    return rows


def _methodology_model(metadata: dict[str, Any]) -> list[dict[str, str]]:
    policy = _dict_value(metadata.get("priority_policy"))
    profile = _text(metadata.get("policy_profile"), default="default")
    high_epss = _text(policy.get("high_epss_threshold"), default="0.50")
    critical_cvss = _text(policy.get("critical_cvss_threshold"), default="9.0")
    return [
        {
            "title": "Transparent priority rules",
            "body": (
                f"Policy profile {profile}; CVSS, EPSS, and KEV determine the base priority. "
                f"Critical CVSS threshold: {critical_cvss}; high EPSS threshold: {high_epss}. "
                "The operational score is a clamped 0-100 queueing helper with explicit reasons."
            ),
        },
        {
            "title": "Locked provider evidence",
            "body": (
                "Provider snapshots and hashes document which NVD, EPSS, and KEV data "
                "powered the run."
            ),
        },
        {
            "title": "ATT&CK as context",
            "body": (
                "ATT&CK mappings are optional, source-controlled, and never generated "
                "heuristically. They provide defensive review context, not proof that "
                "exploitation occurred or procedure guidance."
            ),
        },
        {
            "title": "Reviewable governance",
            "body": (
                "VEX and waiver states are displayed separately so accepted risk stays auditable."
            ),
        },
    ]


def _artifact_model(reports: list[Any], bundles: list[Any]) -> list[dict[str, str]]:
    items: list[dict[str, str]] = []
    for report in reports:
        report_id = _attr(report, "id")
        if not report_id:
            continue
        items.append(
            {
                "label": f"{_attr(report, 'kind') or 'report'} ({_attr(report, 'format')})",
                "url": f"/api/reports/{report_id}/download",
                "detail": _sha_preview(_attr(report, "sha256")),
            }
        )
    for bundle in bundles:
        bundle_id = _attr(bundle, "id")
        if not bundle_id:
            continue
        items.append(
            {
                "label": "Evidence ZIP",
                "url": f"/api/evidence-bundles/{bundle_id}/download",
                "detail": _sha_preview(_attr(bundle, "sha256")),
            }
        )
        items.append(
            {
                "label": "Verify evidence bundle",
                "url": f"/evidence-bundles/{bundle_id}/verify",
                "detail": "integrity check",
            }
        )
    return items


def _workspace_nav(
    project_id: str | None, run_id: str | None, project_name: str
) -> dict[str, Any] | None:
    if not project_id:
        return None
    project_base = f"/projects/{project_id}"
    groups = [
        {
            "label": "Analyze",
            "links": [
                {"label": "Dashboard", "href": f"{project_base}/dashboard", "active": False},
                {"label": "Import", "href": f"{project_base}/imports/new", "active": False},
                {"label": "Findings", "href": f"{project_base}/findings", "active": False},
                {
                    "label": "Intelligence",
                    "href": f"{project_base}/vulnerabilities",
                    "active": False,
                },
            ],
        },
        {
            "label": "Context",
            "links": [
                {"label": "Governance", "href": f"{project_base}/governance", "active": False},
                {"label": "Assets", "href": f"{project_base}/assets", "active": False},
                {"label": "Waivers", "href": f"{project_base}/waivers", "active": False},
                {"label": "Coverage", "href": f"{project_base}/coverage", "active": False},
            ],
        },
    ]
    if run_id:
        groups.append(
            {
                "label": "Run",
                "links": [
                    {
                        "label": "Run artifacts",
                        "href": f"/analysis-runs/{run_id}/reports",
                        "active": False,
                    },
                    {
                        "label": "Executive Report",
                        "href": f"/analysis-runs/{run_id}/executive-report",
                        "active": True,
                    },
                ],
            }
        )
    groups.append(
        {
            "label": "Operate",
            "links": [
                {"label": "Settings", "href": f"{project_base}/settings", "active": False},
            ],
        }
    )
    return {"project": project_name, "groups": groups}


__all__ = [
    "_artifact_model",
    "_bundle_contents_model",
    "_input_sources_model",
    "_methodology_model",
    "_workspace_nav",
]

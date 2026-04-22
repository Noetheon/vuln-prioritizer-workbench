"""Regression tests for GitHub alerts normalization (#27)."""

from __future__ import annotations

import json
from pathlib import Path

from vuln_prioritizer.inputs.loader import InputLoader


def _write_github_alerts_export(tmp_path: Path, alerts: list[dict[str, object]]) -> Path:
    path = tmp_path / "github_alerts_export.json"
    path.write_text(json.dumps(alerts), encoding="utf-8")
    return path


def _load_first_occurrence(tmp_path: Path, alert: dict[str, object]):
    path = _write_github_alerts_export(tmp_path, [alert])
    parsed = InputLoader().load(path=path, input_format="github-alerts-json")
    assert len(parsed.occurrences) == 1
    return parsed.occurrences[0]


def test_github_alerts_manifest_path_is_not_normalized_as_component_version(
    tmp_path: Path,
) -> None:
    occurrence = _load_first_occurrence(
        tmp_path,
        {
            "number": 27,
            "state": "open",
            "dependency": {
                "manifest_path": "backend/requirements.txt",
                "scope": "runtime",
                "package": {
                    "ecosystem": "pip",
                    "name": "moveit-transfer",
                },
            },
            "security_advisory": {
                "ghsa_id": "GHSA-4444-5555-6666",
                "cve_id": "CVE-2023-34362",
                "severity": "critical",
                "summary": "MOVEit Transfer SQL injection duplicate occurrence",
            },
            "security_vulnerability": {
                "package": {
                    "ecosystem": "pip",
                    "name": "moveit-transfer",
                },
                "vulnerable_version_range": "< 2023.0.2",
                "first_patched_version": {
                    "identifier": "2023.0.2",
                },
            },
        },
    )

    assert occurrence.file_path == "backend/requirements.txt"
    assert occurrence.component_version is None


def test_github_alerts_first_patched_version_is_preserved_in_fix_versions(
    tmp_path: Path,
) -> None:
    occurrence = _load_first_occurrence(
        tmp_path,
        {
            "number": 27,
            "state": "open",
            "dependency": {
                "manifest_path": "requirements.txt",
                "scope": "runtime",
                "package": {
                    "ecosystem": "pip",
                    "name": "moveit-transfer",
                },
            },
            "security_advisory": {
                "ghsa_id": "GHSA-1111-2222-3333",
                "cve_id": "CVE-2023-34362",
                "severity": "critical",
                "summary": "MOVEit Transfer SQL injection",
            },
            "security_vulnerability": {
                "package": {
                    "ecosystem": "pip",
                    "name": "moveit-transfer",
                },
                "vulnerable_version_range": "< 2023.0.2",
                "first_patched_version": {
                    "identifier": "2023.0.2",
                },
            },
        },
    )

    assert occurrence.fix_versions == ["2023.0.2"]

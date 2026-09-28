"""Scanner-reported CVSS scores stand in for missing NVD CVSS and survive replay."""

from __future__ import annotations

import json
from pathlib import Path

from utils.demo_imports import DEMO_SNAPSHOT, configure_demo_imports
from utils.import_contracts import completed_run_summary
from utils.workbench_env import WorkbenchApiEnv, create_project_via_api

from app.workers.workflow_worker import run_worker_once

UNANALYZED_CVE = "CVE-2026-99001"


def _snapshot_with_unanalyzed_cve(tmp_path: Path) -> None:
    """Add a CVE that NVD has published but not yet scored."""
    snapshot = json.loads(DEMO_SNAPSHOT.read_text(encoding="utf-8"))
    snapshot["items"].append(
        {
            "cve_id": UNANALYZED_CVE,
            "epss": {"cve_id": UNANALYZED_CVE, "epss": None, "percentile": None},
            "kev": {"cve_id": UNANALYZED_CVE, "in_kev": False},
            "nvd": {
                "cve_id": UNANALYZED_CVE,
                "cvss_base_score": None,
                "description": "Awaiting NVD analysis.",
                "published": "2026-09-20T00:00:00.000",
            },
        }
    )
    (tmp_path / "snapshots" / "scanner.json").write_text(json.dumps(snapshot), encoding="utf-8")


def test_scanner_cvss_ranks_unanalyzed_findings_and_survives_replay(
    file_backed_workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    env = file_backed_workbench_api_env
    configure_demo_imports(env, tmp_path)
    _snapshot_with_unanalyzed_cve(tmp_path)
    project_id = create_project_via_api(env.client, {}, name="Scanner CVSS")["id"]
    report = {
        "SchemaVersion": 2,
        "ArtifactName": "registry.example/api:3.1",
        "ArtifactType": "container_image",
        "Results": [
            {
                "Target": "registry.example/api:3.1 (alpine 3.20)",
                "Type": "alpine",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": UNANALYZED_CVE,
                        "PkgName": "libfoo",
                        "InstalledVersion": "1.0.0",
                        "Severity": "HIGH",
                        "SeveritySource": "ghsa",
                        "CVSS": {"ghsa": {"V3Score": 7.0}, "nvd": {"V3Score": 8.1}},
                    }
                ],
            }
        ],
    }
    response = env.client.post(
        f"/api/v1/projects/{project_id}/imports",
        data={
            "input_type": "trivy-json",
            "provider_snapshot_file": "scanner.json",
            "locked_provider_data": "true",
        },
        files={"file": ("trivy.json", json.dumps(report).encode(), "application/json")},
    )
    assert completed_run_summary(env, response, headers={})["status"] == "succeeded"

    (finding,) = env.client.get(f"/api/v1/projects/{project_id}/findings/").json()["data"]
    assert finding["cvss_base_score"] is None
    assert finding["priority"] == "medium"
    assert "reports CVSS 8.1 (high) from nvd" in finding["rationale"]
    occurrence = env.client.get(f"/api/v1/findings/{finding['id']}").json()["occurrences"][0]
    assert occurrence["raw_severity"] == "HIGH"

    queued = env.client.post(
        f"/api/v1/projects/{project_id}/evaluations", json={"reason": "Replay scanner scores"}
    )
    assert queued.status_code == 200, queued.text
    result = run_worker_once(
        engine=env.engine,
        settings=env.client.app.state.workbench_settings,
        worker_id="scanner-cvss-test",
        retry_delay_seconds=0,
    )
    assert result.completed == 1, result
    replayed = env.client.get(f"/api/v1/findings/{finding['id']}").json()
    assert replayed["priority"] == "medium"
    assert replayed["rationale"] == finding["rationale"]
    assert replayed["evidence"]["evaluation"]["cause"] == "manual"

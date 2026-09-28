"""Finding closure: manual resolution, rescan reconciliation, reopening, and history."""

from __future__ import annotations

import json
import uuid
from dataclasses import replace
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from utils.import_contracts import completed_run_summary
from utils.workbench_env import (
    WorkbenchApiEnv,
    create_project_via_api,
    local_api_headers,
    seed_finding_pair,
)

SNAPSHOT = Path(__file__).resolve().parents[2] / "app" / "resources" / "demo_provider_snapshot.json"
LOG4SHELL = "CVE-2021-44228"
SPRING4SHELL = "CVE-2022-22965"
MOVEIT = "CVE-2023-34362"
CSV_HEADER = b"cve_id,target_ref,component_name,component_version\n"


def _configure_imports(env: WorkbenchApiEnv, tmp_path: Path) -> None:
    snapshots = tmp_path / "snapshots"
    snapshots.mkdir(exist_ok=True)
    (snapshots / "demo.json").write_bytes(SNAPSHOT.read_bytes())
    env.client.app.state.workbench_settings = replace(
        env.client.app.state.workbench_settings,
        PROVIDER_SNAPSHOT_DIR=str(snapshots),
        IMPORT_UPLOAD_DIR=str(tmp_path / "uploads"),
        REPORT_DIR=str(tmp_path / "reports"),
    )


def _import(
    env: WorkbenchApiEnv,
    project_id: str,
    rows: list[bytes],
    *,
    input_type: str = "generic-occurrence-csv",
    resolve_missing: bool | None = None,
) -> dict[str, object]:
    data = {
        "input_type": input_type,
        "provider_snapshot_file": "demo.json",
        "locked_provider_data": "true",
    }
    if resolve_missing is not None:
        data["resolve_missing"] = "true" if resolve_missing else "false"
    body = b"".join(rows) if input_type == "cve-list" else CSV_HEADER + b"".join(rows)
    response = env.client.post(
        f"/api/v1/projects/{project_id}/imports",
        data=data,
        files={"file": ("scan.csv" if input_type != "cve-list" else "cves.txt", body, "text/csv")},
    )
    summary = completed_run_summary(env, response, headers={})
    assert summary["status"] == "succeeded", summary
    return summary


def _trivy_import(
    env: WorkbenchApiEnv,
    project_id: str,
    vulnerabilities: list[dict[str, str]],
) -> dict[str, object]:
    report = {
        "SchemaVersion": 2,
        "ArtifactName": "registry.example/app:1.0",
        "ArtifactType": "container_image",
        "Results": [
            {
                "Target": "registry.example/app:1.0 (debian 12.5)",
                "Class": "os-pkgs",
                "Type": "debian",
                **({"Vulnerabilities": vulnerabilities} if vulnerabilities else {}),
            }
        ],
    }
    response = env.client.post(
        f"/api/v1/projects/{project_id}/imports",
        data={
            "input_type": "trivy-json",
            "provider_snapshot_file": "demo.json",
            "locked_provider_data": "true",
        },
        files={"file": ("trivy.json", json.dumps(report).encode(), "application/json")},
    )
    summary = completed_run_summary(env, response, headers={})
    assert summary["status"] == "succeeded", summary
    return summary


def _findings(client: TestClient, project_id: str) -> dict[tuple[str, str | None], dict]:
    payload = client.get(f"/api/v1/projects/{project_id}/findings/?limit=100").json()
    return {(item["cve_id"], item["asset_target_ref"]): item for item in payload["data"]}


def _events(client: TestClient, finding_id: str) -> list[dict]:
    response = client.get(f"/api/v1/findings/{finding_id}/lifecycle-events")
    assert response.status_code == 200, response.text
    return response.json()["data"]


def test_rescan_resolves_unreported_findings_and_reopens_regressions(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    env = workbench_api_env
    _configure_imports(env, tmp_path)
    project_id = create_project_via_api(env.client, {}, name="Lifecycle")["id"]
    _import(
        env,
        project_id,
        [
            f"{LOG4SHELL},web-1,log4j-core,2.14.1\n".encode(),
            f"{SPRING4SHELL},web-1,spring-beans,5.3.17\n".encode(),
            f"{MOVEIT},web-2,moveit,2023.0.1\n".encode(),
        ],
    )

    rescan = _import(env, project_id, [f"{LOG4SHELL},web-1,log4j-core,2.14.1\n".encode()])

    findings = _findings(env.client, project_id)
    assert rescan["resolved_findings"] == 1
    assert rescan["reopened_findings"] == 0
    assert findings[(SPRING4SHELL, "web-1")]["status"] == "resolved"
    assert findings[(LOG4SHELL, "web-1")]["status"] == "open"
    # web-2 was not part of the rescan, so its finding stays open.
    assert findings[(MOVEIT, "web-2")]["status"] == "open"
    resolved = findings[(SPRING4SHELL, "web-1")]
    events = _events(env.client, resolved["id"])
    assert [(item["from_status"], item["to_status"], item["source"]) for item in events] == [
        ("open", "resolved", "import_not_observed")
    ]
    assert "generic-occurrence-csv import of scan.csv" in events[0]["reason"]
    assert events[0]["analysis_run_id"] == rescan["id"]
    open_ranks = [
        item["operational_rank"] for item in findings.values() if item["status"] == "open"
    ]
    assert resolved["operational_rank"] > max(open_ranks)
    detail = env.client.get(f"/api/v1/findings/{resolved['id']}").json()
    assert detail["status"] == "resolved"
    assert detail["evidence"]["status"] == "resolved"

    regression = _import(
        env,
        project_id,
        [
            f"{LOG4SHELL},web-1,log4j-core,2.14.1\n".encode(),
            f"{SPRING4SHELL},web-1,spring-beans,5.3.17\n".encode(),
        ],
    )

    reopened = _findings(env.client, project_id)[(SPRING4SHELL, "web-1")]
    assert regression["reopened_findings"] == 1
    assert regression["resolved_findings"] == 0
    assert reopened["status"] == "open"
    assert _events(env.client, reopened["id"])[0]["source"] == "import_reobserved"


def test_clean_scanner_rescan_resolves_the_targets_it_examined(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    env = workbench_api_env
    _configure_imports(env, tmp_path)
    project_id = create_project_via_api(env.client, {}, name="Clean rescan")["id"]
    _trivy_import(
        env,
        project_id,
        [
            {
                "VulnerabilityID": LOG4SHELL,
                "PkgName": "liblog4j2-java",
                "InstalledVersion": "2.14.1",
                "Severity": "CRITICAL",
            }
        ],
    )

    clean = _trivy_import(env, project_id, [])

    assert clean["resolved_findings"] == 1
    assert clean["finding_count"] == 0
    (finding,) = _findings(env.client, project_id).values()
    assert finding["status"] == "resolved"
    (event,) = _events(env.client, finding["id"])
    assert event["source"] == "import_not_observed"
    assert "registry.example/app:1.0 (debian 12.5)" in event["reason"]


def test_reconciliation_respects_opt_out_cve_lists_and_false_positives(
    workbench_api_env: WorkbenchApiEnv,
    tmp_path: Path,
) -> None:
    env = workbench_api_env
    _configure_imports(env, tmp_path)
    project_id = create_project_via_api(env.client, {}, name="Lifecycle opt-out")["id"]
    _import(
        env,
        project_id,
        [
            f"{LOG4SHELL},web-1,log4j-core,2.14.1\n".encode(),
            f"{SPRING4SHELL},web-1,spring-beans,5.3.17\n".encode(),
        ],
    )

    kept = _import(
        env,
        project_id,
        [f"{LOG4SHELL},web-1,log4j-core,2.14.1\n".encode()],
        resolve_missing=False,
    )
    assert kept["resolved_findings"] == 0
    assert _findings(env.client, project_id)[(SPRING4SHELL, "web-1")]["status"] == "open"

    cve_only = _import(env, project_id, [f"{MOVEIT}\n".encode()], input_type="cve-list")
    assert cve_only["resolved_findings"] == 0

    findings = _findings(env.client, project_id)
    false_positive = findings[(LOG4SHELL, "web-1")]
    marked = env.client.patch(
        f"/api/v1/findings/{false_positive['id']}/status",
        json={"status": "false_positive", "reason": "Library is vendored but never loaded."},
    )
    assert marked.status_code == 200, marked.text
    _import(env, project_id, [f"{LOG4SHELL},web-1,log4j-core,2.14.1\n".encode()])
    assert _findings(env.client, project_id)[(LOG4SHELL, "web-1")]["status"] == "false_positive"


def test_manual_closure_requires_reason_and_records_history(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    client = workbench_api_env.client
    headers = local_api_headers(client)
    project = create_project_via_api(client, headers)
    seeded = seed_finding_pair(
        workbench_api_env.engine,
        workbench_api_env.app_models,
        workbench_api_env.repositories,
        project_id=uuid.UUID(project["id"]),
        with_decision_evidence=True,
    )
    finding_id = str(seeded["finding_ids"][0])

    missing_reason = client.patch(
        f"/api/v1/findings/{finding_id}/status",
        headers=headers,
        json={"status": "resolved", "reason": "   "},
    )
    assert missing_reason.status_code == 422
    assert "reason is required" in missing_reason.json()["detail"]

    resolved = client.patch(
        f"/api/v1/findings/{finding_id}/status",
        headers=headers,
        json={"status": "resolved", "reason": "Patched in release 2026.09.28."},
    )
    assert resolved.status_code == 200, resolved.text
    assert resolved.json()["status"] == "resolved"

    reopened = client.patch(
        f"/api/v1/findings/{finding_id}/status",
        headers=headers,
        json={"status": "open"},
    )
    assert reopened.status_code == 200, reopened.text

    events = _events(client, finding_id)
    assert [(item["from_status"], item["to_status"]) for item in events] == [
        ("resolved", "open"),
        ("open", "resolved"),
    ]
    assert events[1]["reason"] == "Patched in release 2026.09.28."
    assert events[1]["source"] == "manual"
    assert events[1]["actor"]
    audit = client.get("/api/v1/audit/events", headers=headers).json()["data"]
    closure = next(
        item
        for item in audit
        if item["action"] == "finding.status" and item["detail"]["to"] == "resolved"
    )
    assert closure["detail"]["reason_recorded"] is True
    assert "Patched" not in str(closure["detail"])


def test_bulk_status_updates_and_reports_skipped_findings(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    client = workbench_api_env.client
    headers = local_api_headers(client)
    project = create_project_via_api(client, headers)
    seeded = seed_finding_pair(
        workbench_api_env.engine,
        workbench_api_env.app_models,
        workbench_api_env.repositories,
        project_id=uuid.UUID(project["id"]),
        with_decision_evidence=True,
    )
    first, second = (str(item) for item in seeded["finding_ids"])
    unknown = str(uuid.uuid4())
    endpoint = f"/api/v1/projects/{project['id']}/findings/status"

    rejected = client.post(
        endpoint,
        headers=headers,
        json={"finding_ids": [first], "status": "false_positive"},
    )
    assert rejected.status_code == 422

    reviewed = client.post(
        endpoint,
        headers=headers,
        json={"finding_ids": [first, second, unknown], "status": "in_review"},
    )
    assert reviewed.status_code == 200, reviewed.text
    payload = reviewed.json()
    assert payload["updated_count"] == 2
    assert set(payload["updated_ids"]) == {first, second}
    assert [item["finding_id"] for item in payload["skipped"]] == [unknown]

    repeated = client.post(
        endpoint,
        headers=headers,
        json={"finding_ids": [first], "status": "in_review"},
    )
    assert repeated.json()["updated_count"] == 0
    assert "already has status" in repeated.json()["skipped"][0]["detail"]

    governed = client.post(
        endpoint,
        headers=headers,
        json={"finding_ids": [first], "status": "accepted"},
    )
    assert governed.status_code == 422


@pytest.mark.parametrize("status", ["fixed", "accepted", "suppressed"])
def test_governance_owned_statuses_cannot_be_reopened_manually(
    workbench_api_env: WorkbenchApiEnv,
    status: str,
) -> None:
    client = workbench_api_env.client
    headers = local_api_headers(client)
    project = create_project_via_api(client, headers)
    seeded = seed_finding_pair(
        workbench_api_env.engine,
        workbench_api_env.app_models,
        workbench_api_env.repositories,
        project_id=uuid.UUID(project["id"]),
        with_decision_evidence=True,
    )
    finding_id = seeded["finding_ids"][0]
    from sqlmodel import Session

    with Session(workbench_api_env.engine) as session:
        finding = session.get(workbench_api_env.app_models.Finding, finding_id)
        assert finding is not None
        finding.status = status
        session.add(finding)
        session.commit()

    response = client.patch(
        f"/api/v1/findings/{finding_id}/status",
        headers=headers,
        json={"status": "resolved", "reason": "Trying to close governed work."},
    )
    assert response.status_code == 422
    assert "governance-managed" in response.json()["detail"]

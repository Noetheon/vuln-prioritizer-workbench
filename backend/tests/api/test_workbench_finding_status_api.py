from __future__ import annotations

import uuid

from utils.workbench_env import (
    WorkbenchApiEnv,
    create_project_via_api,
    local_api_headers,
    seed_finding_pair,
)


def test_finding_workflow_status_transitions_and_evidence_sync(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    seeded = seed_finding_pair(
        workbench_api_env.engine,
        workbench_api_env.app_models,
        workbench_api_env.repositories,
        project_id=uuid.UUID(project["id"]),
        with_decision_evidence=True,
    )
    finding_id = str(seeded["finding_ids"][0])

    in_review = workbench_api_env.client.patch(
        f"/api/v1/findings/{finding_id}/status",
        headers=headers,
        json={"status": "in_review"},
    )
    assert in_review.status_code == 200, in_review.text
    assert in_review.json()["status"] == "in_review"

    detail = workbench_api_env.client.get(f"/api/v1/findings/{finding_id}", headers=headers).json()
    assert detail["status"] == "in_review"
    assert detail["evidence"]["status"] == "in_review"

    remediating = workbench_api_env.client.patch(
        f"/api/v1/findings/{finding_id}/status",
        headers=headers,
        json={"status": "remediating"},
    )
    assert remediating.status_code == 200
    assert remediating.json()["status"] == "remediating"

    reopened = workbench_api_env.client.patch(
        f"/api/v1/findings/{finding_id}/status",
        headers=headers,
        json={"status": "open"},
    )
    assert reopened.status_code == 200
    assert reopened.json()["status"] == "open"

    audit = workbench_api_env.client.get("/api/v1/audit/events", headers=headers)
    assert audit.status_code == 200
    status_events = [event for event in audit.json()["data"] if event["action"] == "finding.status"]
    assert len(status_events) >= 3
    assert {event["status"] for event in status_events} == {"success"}


def test_finding_workflow_status_rejects_governance_states(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    seeded = seed_finding_pair(
        workbench_api_env.engine,
        workbench_api_env.app_models,
        workbench_api_env.repositories,
        project_id=uuid.UUID(project["id"]),
        with_decision_evidence=True,
    )
    finding_id = str(seeded["finding_ids"][0])

    accepted = workbench_api_env.client.patch(
        f"/api/v1/findings/{finding_id}/status",
        headers=headers,
        json={"status": "accepted"},
    )
    assert accepted.status_code == 422
    assert "governance-managed" in accepted.json()["detail"]

    fixed = workbench_api_env.client.patch(
        f"/api/v1/findings/{finding_id}/status",
        headers=headers,
        json={"status": "fixed"},
    )
    assert fixed.status_code == 422

    missing = workbench_api_env.client.patch(
        f"/api/v1/findings/{uuid.uuid4()}/status",
        headers=headers,
        json={"status": "in_review"},
    )
    assert missing.status_code == 404

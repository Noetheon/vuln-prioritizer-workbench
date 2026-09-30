from __future__ import annotations

import uuid

from sqlmodel import Session, select
from utils.workbench_env import (
    DEMO_CVE_LOG4SHELL,
    DEMO_CVE_XZ,
    WorkbenchApiEnv,
    create_project_via_api,
    local_api_headers,
    seed_finding_pair,
)

DECISION = {
    "owner": "risk-owner",
    "reason": "Compensating controls are in place until the vendor ships a fix.",
    "expires_at": "2099-12-31",
    "review_at": "2099-12-01",
    "approval_ref": "CAB-101",
}


def _seeded_project(workbench_api_env: WorkbenchApiEnv, headers: dict[str, str]):
    project = create_project_via_api(workbench_api_env.client, headers)
    seeded = seed_finding_pair(
        workbench_api_env.engine,
        workbench_api_env.app_models,
        workbench_api_env.repositories,
        project_id=uuid.UUID(project["id"]),
        with_decision_evidence=True,
    )
    return project, [str(finding_id) for finding_id in seeded["finding_ids"]]


def test_bulk_acceptance_creates_one_finding_scoped_waiver_per_finding(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    headers = local_api_headers(workbench_api_env.client)
    project, finding_ids = _seeded_project(workbench_api_env, headers)

    response = workbench_api_env.client.post(
        f"/api/v1/projects/{project['id']}/waivers/bulk",
        headers=headers,
        # A repeated id is accepted once.
        json={"finding_ids": [*finding_ids, finding_ids[0]], **DECISION},
    )

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["count"] == 2
    waivers = {waiver["finding_id"]: waiver for waiver in payload["data"]}
    assert set(waivers) == set(finding_ids)
    assert {waiver["cve_id"] for waiver in payload["data"]} == {
        DEMO_CVE_LOG4SHELL,
        DEMO_CVE_XZ,
    }
    for waiver in payload["data"]:
        assert waiver["status"] == "active"
        assert waiver["matched_findings"] == 1
        assert waiver["owner"] == "risk-owner"
        assert waiver["approval_ref"] == "CAB-101"
        assert waiver["asset_id"] is None
        assert waiver["service"] is None

    for finding_id in finding_ids:
        detail = workbench_api_env.client.get(f"/api/v1/findings/{finding_id}", headers=headers)
        assert detail.status_code == 200
        assert detail.json()["status"] == "accepted"
        assert detail.json()["waived"] is True

    with Session(workbench_api_env.engine) as session:
        audit_events = session.exec(
            select(workbench_api_env.app_models.AuditEvent).where(
                workbench_api_env.app_models.AuditEvent.action == "waiver.create"
            )
        ).all()
    assert len(audit_events) == 2


def test_bulk_acceptance_rejects_findings_of_another_project(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    headers = local_api_headers(workbench_api_env.client)
    project, finding_ids = _seeded_project(workbench_api_env, headers)
    other_project = create_project_via_api(workbench_api_env.client, headers, name="Other")

    foreign = workbench_api_env.client.post(
        f"/api/v1/projects/{other_project['id']}/waivers/bulk",
        headers=headers,
        json={"finding_ids": finding_ids, **DECISION},
    )
    assert foreign.status_code == 422
    assert foreign.json()["detail"] == "finding_ids must belong to the project."

    unknown = workbench_api_env.client.post(
        f"/api/v1/projects/{project['id']}/waivers/bulk",
        headers=headers,
        json={"finding_ids": [finding_ids[0], str(uuid.uuid4())], **DECISION},
    )
    assert unknown.status_code == 422

    # Nothing was accepted by the rejected requests.
    listed = workbench_api_env.client.get(
        f"/api/v1/projects/{project['id']}/waivers/", headers=headers
    )
    assert listed.json()["count"] == 0


def test_bulk_acceptance_validates_the_shared_decision(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    headers = local_api_headers(workbench_api_env.client)
    project, finding_ids = _seeded_project(workbench_api_env, headers)
    url = f"/api/v1/projects/{project['id']}/waivers/bulk"

    empty = workbench_api_env.client.post(
        url, headers=headers, json={"finding_ids": [], **DECISION}
    )
    assert empty.status_code == 422

    too_many = workbench_api_env.client.post(
        url,
        headers=headers,
        json={"finding_ids": [str(uuid.uuid4()) for _ in range(101)], **DECISION},
    )
    assert too_many.status_code == 422

    blank_owner = workbench_api_env.client.post(
        url, headers=headers, json={"finding_ids": finding_ids, **DECISION, "owner": "  "}
    )
    assert blank_owner.status_code == 422
    assert "owner is required" in blank_owner.text

    review_after_expiry = workbench_api_env.client.post(
        url,
        headers=headers,
        json={"finding_ids": finding_ids, **DECISION, "review_at": "2100-01-01"},
    )
    assert review_after_expiry.status_code == 422
    assert "review_after_expiry" in review_after_expiry.text

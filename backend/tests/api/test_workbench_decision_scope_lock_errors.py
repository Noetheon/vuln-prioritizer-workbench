from __future__ import annotations

import uuid
from datetime import date
from typing import Any

import pytest
from sqlmodel import Session
from utils.workbench_env import (
    DEMO_CVE_LOG4SHELL,
    WorkbenchApiEnv,
    create_project_via_api,
    local_api_headers,
    seed_finding_pair,
)

from app.api.routes.workbench_access import (
    _refresh_stale_project_waivers,
    lock_existing_project_resource,
)
from app.services.decision_scope_lock import (
    ProjectDecisionLockError,
)


@pytest.mark.parametrize(
    "mutation",
    ["project.delete", "asset.create", "finding.status", "waiver.create", "github.export"],
)
def test_project_deleted_during_lock_acquisition_returns_not_found(
    workbench_api_env: WorkbenchApiEnv,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    """A stale pre-lock read must never surface as an internal server error."""
    client = workbench_api_env.client
    headers = local_api_headers(client)
    project = create_project_via_api(client, headers)
    project_id = project["id"]
    payload: dict[str, Any] | None

    if mutation == "project.delete":
        patch_target = "app.services.project_deletion.lock_project_decision_scope"
        method = "DELETE"
        path = f"/api/v1/projects/{project_id}"
        payload = None
    elif mutation == "asset.create":
        patch_target = "app.api.routes.assets.lock_project_decision_scope"
        method = "POST"
        path = f"/api/v1/projects/{project_id}/assets/"
        payload = {"asset_key": "race-asset", "name": "Race asset"}
    elif mutation == "finding.status":
        seeded = seed_finding_pair(
            workbench_api_env.engine,
            workbench_api_env.app_models,
            workbench_api_env.repositories,
            project_id=uuid.UUID(project_id),
            with_decision_evidence=True,
        )
        patch_target = "app.api.routes.workbench_access.lock_project_decision_scope"
        method = "PATCH"
        path = f"/api/v1/findings/{seeded['finding_ids'][0]}/status"
        payload = {"status": "in_review"}
    elif mutation == "waiver.create":
        patch_target = "app.api.routes.waivers.lock_project_decision_scope"
        method = "POST"
        path = f"/api/v1/projects/{project_id}/waivers/"
        payload = {
            "cve_id": DEMO_CVE_LOG4SHELL,
            "owner": "risk-owner",
            "reason": "Exercise a project deletion race during lock acquisition.",
            "expires_at": "2099-12-31",
        }
    else:
        patch_target = "app.api.routes.github_issues.lock_project_decision_scope"
        method = "POST"
        path = f"/api/v1/projects/{project_id}/github/issues/export"
        payload = {"repository": "example/security", "dry_run": True}

    def project_disappeared(_session: Any, locked_project_id: uuid.UUID) -> None:
        raise ProjectDecisionLockError(f"Project {locked_project_id} does not exist.")

    monkeypatch.setattr(patch_target, project_disappeared)
    response = (
        client.request(method, path, headers=headers)
        if payload is None
        else client.request(method, path, headers=headers, json=payload)
    )

    assert response.status_code == 404, response.text
    assert response.json() == {
        "code": "not_found",
        "message": "Project not found",
        "details": {},
        "detail": "Project not found",
    }
    assert client.get(f"/api/v1/projects/{project_id}", headers=headers).status_code == 200


def test_project_deleted_during_daily_waiver_claim_raises_project_lock_error(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    """The pre-lock daily-refresh race must use the same request-safe exception."""
    project = create_project_via_api(
        workbench_api_env.client,
        local_api_headers(workbench_api_env.client),
    )
    project_id = uuid.UUID(project["id"])
    with Session(workbench_api_env.engine) as setup_session:
        persisted = setup_session.get(workbench_api_env.app_models.Project, project_id)
        assert persisted is not None
        persisted.waiver_evaluated_on = date(2000, 1, 1)
        setup_session.add(persisted)
        setup_session.commit()

    stale_session = Session(workbench_api_env.engine)
    try:
        stale_project = stale_session.get(workbench_api_env.app_models.Project, project_id)
        assert stale_project is not None
        with Session(workbench_api_env.engine) as deleting_session:
            current = deleting_session.get(workbench_api_env.app_models.Project, project_id)
            assert current is not None
            deleting_session.delete(current)
            deleting_session.commit()

        with pytest.raises(ProjectDecisionLockError, match="does not exist"):
            _refresh_stale_project_waivers(stale_session, stale_project)
    finally:
        stale_session.close()


@pytest.mark.parametrize(
    "mutation",
    [
        "asset.update",
        "asset.recalculate",
        "finding.status",
        "waiver.update",
        "waiver.expire",
        "waiver.delete",
    ],
)
def test_concurrently_deleted_resource_returns_not_found_after_project_lock(
    file_backed_workbench_api_env: WorkbenchApiEnv,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    """Locked mutations must re-resolve a row deleted while awaiting its project lock."""
    env = file_backed_workbench_api_env
    client = env.client
    headers = local_api_headers(client)
    project = create_project_via_api(client, headers, name=f"Resource {mutation} race")
    project_id = project["id"]
    payload: dict[str, Any] | None
    if mutation.startswith("asset."):
        created = client.post(
            f"/api/v1/projects/{project_id}/assets/",
            headers=headers,
            json={"asset_key": f"{mutation}-asset", "name": "Race asset"},
        )
        assert created.status_code == 200, created.text
        resource_model = env.app_models.Asset
        resource_id = uuid.UUID(created.json()["id"])
        patch_target = "app.api.routes.assets.lock_existing_project_resource"
        not_found_detail = "Asset not found"
        if mutation == "asset.update":
            method = "PATCH"
            path = f"/api/v1/assets/{resource_id}"
            payload = {"name": "Stale update"}
        else:
            method = "POST"
            path = f"/api/v1/assets/{resource_id}/recalculate"
            payload = None
    elif mutation == "finding.status":
        seeded = seed_finding_pair(
            env.engine,
            env.app_models,
            env.repositories,
            project_id=uuid.UUID(project_id),
        )
        resource_model = env.app_models.Finding
        resource_id = seeded["finding_ids"][0]
        patch_target = "app.api.routes.findings.lock_existing_project_resource"
        not_found_detail = "Finding not found"
        method = "PATCH"
        path = f"/api/v1/findings/{resource_id}/status"
        payload = {"status": "in_review"}
    else:
        created = client.post(
            f"/api/v1/projects/{project_id}/waivers/",
            headers=headers,
            json={
                "cve_id": DEMO_CVE_LOG4SHELL,
                "owner": "risk-owner",
                "reason": "Exercise a concurrent waiver deletion race.",
                "expires_at": "2099-12-31",
            },
        )
        assert created.status_code == 200, created.text
        resource_model = env.app_models.Waiver
        resource_id = uuid.UUID(created.json()["id"])
        patch_target = "app.api.routes.waivers.lock_existing_project_resource"
        not_found_detail = "Waiver not found"
        if mutation == "waiver.update":
            method = "PATCH"
            path = f"/api/v1/waivers/{resource_id}"
            payload = {
                "cve_id": DEMO_CVE_LOG4SHELL,
                "owner": "updated-owner",
                "reason": "The stale update must not resurrect a deleted waiver.",
                "expires_at": "2099-12-31",
            }
        elif mutation == "waiver.expire":
            method = "POST"
            path = f"/api/v1/waivers/{resource_id}/expire"
            payload = None
        else:
            method = "DELETE"
            path = f"/api/v1/waivers/{resource_id}"
            payload = None
    competing_delete_ran = False

    def delete_before_project_lock(
        session: Session,
        *,
        model: type[Any],
        resource_id: uuid.UUID,
        project_id: uuid.UUID,
        not_found_detail: str,
    ) -> Any:
        nonlocal competing_delete_ran
        assert model is resource_model
        assert resource_id == resource_id_for_assertion
        assert project_id == uuid.UUID(project_id_for_assertion)
        assert not_found_detail == expected_not_found_detail
        assert not competing_delete_ran
        competing_delete_ran = True
        with Session(env.engine) as competing_session:
            current = competing_session.get(resource_model, resource_id)
            assert current is not None
            competing_session.delete(current)
            competing_session.commit()
        return lock_existing_project_resource(
            session,
            model=model,
            resource_id=resource_id,
            project_id=project_id,
            not_found_detail=not_found_detail,
        )

    resource_id_for_assertion = resource_id
    project_id_for_assertion = project_id
    expected_not_found_detail = not_found_detail
    monkeypatch.setattr(patch_target, delete_before_project_lock)
    response = (
        client.request(method, path, headers=headers)
        if payload is None
        else client.request(method, path, headers=headers, json=payload)
    )

    assert competing_delete_ran
    assert response.status_code == 404, response.text
    assert response.json() == {
        "code": "not_found",
        "message": not_found_detail,
        "details": {},
        "detail": not_found_detail,
    }
    assert client.get(f"/api/v1/projects/{project_id}", headers=headers).status_code == 200
    with Session(env.engine) as verification_session:
        assert verification_session.get(resource_model, resource_id) is None

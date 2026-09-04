from __future__ import annotations

import uuid
from datetime import date
from typing import Any

import pytest
from sqlalchemy import event
from sqlmodel import Session, select
from utils.workbench_env import (
    WorkbenchApiEnv,
    create_asset,
    create_project_via_api,
    local_api_headers,
    seed_finding_pair,
)

from app.api.routes.workbench_access import _refresh_stale_project_waivers
from app.models import FindingStatus
from app.repositories.waivers import WaiverRepository


def test_zero_waiver_sync_returns_before_loading_project_findings(
    workbench_api_env: WorkbenchApiEnv,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    project_id = uuid.UUID(project["id"])

    with Session(workbench_api_env.engine) as session:
        repository = WaiverRepository(session)

        def fail_if_loaded(_project_id: uuid.UUID) -> list[Any]:
            raise AssertionError("zero-waiver sync loaded project findings")

        monkeypatch.setattr(repository, "_project_findings", fail_if_loaded)

        assert repository.sync_project_waivers(project_id) == {}


def test_waiver_project_findings_load_asset_context_in_one_batch(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    project_id = uuid.UUID(project["id"])
    finding_ids = seed_finding_pair(
        workbench_api_env.engine,
        workbench_api_env.app_models,
        workbench_api_env.repositories,
        project_id=project_id,
    )["finding_ids"]
    with Session(workbench_api_env.engine) as session:
        second_asset = create_asset(
            session,
            workbench_api_env.app_models,
            workbench_api_env.repositories,
            project_id=project_id,
            asset_key="secondary-api",
            name="Secondary API",
        )
        second_finding = session.get(workbench_api_env.app_models.Finding, finding_ids[1])
        assert second_finding is not None
        second_finding.asset_id = second_asset.id
        session.add(second_finding)
        session.commit()

    asset_selects: list[str] = []

    def record_asset_select(
        _connection: Any,
        _cursor: Any,
        statement: str,
        _parameters: Any,
        _context: Any,
        _executemany: bool,
    ) -> None:
        if statement.lstrip().upper().startswith("SELECT") and "FROM asset" in statement:
            asset_selects.append(statement)

    event.listen(workbench_api_env.engine, "before_cursor_execute", record_asset_select)
    try:
        with Session(workbench_api_env.engine) as session:
            findings = WaiverRepository(session)._project_findings(project_id)
            assert {finding.asset_id for finding in findings} == {
                finding.asset.id for finding in findings if finding.asset is not None
            }
    finally:
        event.remove(workbench_api_env.engine, "before_cursor_execute", record_asset_select)

    assert len(asset_selects) == 1


def test_delete_last_waiver_forces_projection_rebuild(
    workbench_api_env: WorkbenchApiEnv,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    finding_id = seed_finding_pair(
        workbench_api_env.engine,
        workbench_api_env.app_models,
        workbench_api_env.repositories,
        project_id=uuid.UUID(project["id"]),
        with_decision_evidence=True,
    )["finding_ids"][0]
    created = workbench_api_env.client.post(
        f"/api/v1/projects/{project['id']}/waivers/",
        headers=headers,
        json={
            "finding_id": str(finding_id),
            "owner": "risk-owner",
            "reason": "Exercise the final-waiver deletion path.",
            "expires_at": "2099-12-31",
        },
    )
    assert created.status_code == 200, created.text

    original_sync = WaiverRepository.sync_project_waivers
    force_values: list[bool] = []

    def counted_sync(
        repository: WaiverRepository,
        project_id: uuid.UUID,
        *,
        force: bool = False,
        changed_finding_ids: set[uuid.UUID] | None = None,
    ) -> dict[uuid.UUID, int]:
        force_values.append(force)
        return original_sync(
            repository,
            project_id,
            force=force,
            changed_finding_ids=changed_finding_ids,
        )

    monkeypatch.setattr(WaiverRepository, "sync_project_waivers", counted_sync)
    deleted = workbench_api_env.client.delete(
        f"/api/v1/waivers/{created.json()['id']}",
        headers=headers,
    )

    assert deleted.status_code == 204, deleted.text
    assert force_values == [True]
    detail = workbench_api_env.client.get(
        f"/api/v1/findings/{finding_id}",
        headers=headers,
    )
    assert detail.status_code == 200, detail.text
    assert detail.json()["status"] == "open"
    assert detail.json()["waived"] is False


def test_stale_project_read_expires_waiver_once_per_utc_day(
    workbench_api_env: WorkbenchApiEnv,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("WORKBENCH_FIXED_NOW", "2026-09-01T12:00:00+00:00")
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    project_id = uuid.UUID(project["id"])
    finding_id = seed_finding_pair(
        workbench_api_env.engine,
        workbench_api_env.app_models,
        workbench_api_env.repositories,
        project_id=project_id,
        with_decision_evidence=True,
    )["finding_ids"][0]
    created = workbench_api_env.client.post(
        f"/api/v1/projects/{project['id']}/waivers/",
        headers=headers,
        json={
            "finding_id": str(finding_id),
            "owner": "risk-owner",
            "reason": "Expire this decision on the next read day.",
            "expires_at": "2026-09-02",
        },
    )
    assert created.status_code == 200, created.text
    assert created.json()["status"] == "review_due"
    accepted = workbench_api_env.client.get(
        f"/api/v1/findings/{finding_id}",
        headers=headers,
    )
    assert accepted.status_code == 200, accepted.text
    assert accepted.json()["status"] == "accepted"
    assert accepted.json()["waived"] is True

    monkeypatch.setenv("WORKBENCH_FIXED_NOW", "2026-09-03T00:01:00+00:00")
    original_sync = WaiverRepository.sync_project_waivers
    sync_count = 0

    def counted_sync(
        repository: WaiverRepository,
        requested_project_id: uuid.UUID,
        *,
        force: bool = False,
        changed_finding_ids: set[uuid.UUID] | None = None,
    ) -> dict[uuid.UUID, int]:
        nonlocal sync_count
        sync_count += 1
        return original_sync(
            repository,
            requested_project_id,
            force=force,
            changed_finding_ids=changed_finding_ids,
        )

    monkeypatch.setattr(WaiverRepository, "sync_project_waivers", counted_sync)
    expired = workbench_api_env.client.get(
        f"/api/v1/findings/{finding_id}",
        headers=headers,
    )
    second_read = workbench_api_env.client.get(
        f"/api/v1/findings/{finding_id}",
        headers=headers,
    )

    assert expired.status_code == 200, expired.text
    assert expired.json()["status"] == "open"
    assert expired.json()["waived"] is False
    assert second_read.status_code == 200, second_read.text
    assert sync_count == 1
    with Session(workbench_api_env.engine) as session:
        persisted_project = session.get(workbench_api_env.app_models.Project, project_id)
        assert persisted_project is not None
        assert persisted_project.waiver_evaluated_on == date(2026, 9, 3)
        lifecycle_events = session.exec(
            select(workbench_api_env.app_models.AuditEvent).where(
                workbench_api_env.app_models.AuditEvent.action == "waiver.lifecycle_refresh",
                workbench_api_env.app_models.AuditEvent.project_id == project_id,
            )
        ).all()
        assert len(lifecycle_events) == 1
        assert lifecycle_events[0].detail_json["evaluated_on"] == "2026-09-03"
        assert lifecycle_events[0].detail_json["changed_finding_count"] == 2
        assert str(finding_id) in lifecycle_events[0].detail_json["changed_finding_ids"]


def test_two_stale_sessions_claim_only_one_daily_waiver_refresh(
    workbench_api_env: WorkbenchApiEnv,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("WORKBENCH_FIXED_NOW", "2026-09-01T12:00:00+00:00")
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    project_id = uuid.UUID(project["id"])
    monkeypatch.setenv("WORKBENCH_FIXED_NOW", "2026-09-02T00:01:00+00:00")
    sync_count = 0

    def counted_sync(
        repository: WaiverRepository,
        requested_project_id: uuid.UUID,
        *,
        force: bool = False,
        changed_finding_ids: set[uuid.UUID] | None = None,
    ) -> dict[uuid.UUID, int]:
        nonlocal sync_count
        _ = repository, force
        assert requested_project_id == project_id
        sync_count += 1
        assert changed_finding_ids is not None
        changed_finding_ids.add(uuid.UUID(int=1))
        return {}

    monkeypatch.setattr(WaiverRepository, "sync_project_waivers", counted_sync)
    with (
        Session(workbench_api_env.engine) as first_session,
        Session(workbench_api_env.engine) as stale_session,
    ):
        first_project = first_session.get(workbench_api_env.app_models.Project, project_id)
        stale_project = stale_session.get(workbench_api_env.app_models.Project, project_id)
        assert first_project is not None
        assert stale_project is not None
        assert first_project.waiver_evaluated_on == date(2026, 9, 1)
        assert stale_project.waiver_evaluated_on == date(2026, 9, 1)

        _refresh_stale_project_waivers(first_session, first_project)
        _refresh_stale_project_waivers(stale_session, stale_project)

        assert first_project.waiver_evaluated_on == date(2026, 9, 2)
        assert stale_project.waiver_evaluated_on == date(2026, 9, 2)

    assert sync_count == 1
    with Session(workbench_api_env.engine) as session:
        lifecycle_events = session.exec(
            select(workbench_api_env.app_models.AuditEvent).where(
                workbench_api_env.app_models.AuditEvent.action == "waiver.lifecycle_refresh",
                workbench_api_env.app_models.AuditEvent.project_id == project_id,
            )
        ).all()
        assert len(lifecycle_events) == 1


def test_stale_read_rolls_back_projection_and_freshness_marker_together(
    workbench_api_env: WorkbenchApiEnv,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("WORKBENCH_FIXED_NOW", "2026-09-01T12:00:00+00:00")
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    project_id = uuid.UUID(project["id"])
    finding_id = seed_finding_pair(
        workbench_api_env.engine,
        workbench_api_env.app_models,
        workbench_api_env.repositories,
        project_id=project_id,
    )["finding_ids"][0]
    monkeypatch.setenv("WORKBENCH_FIXED_NOW", "2026-09-02T00:01:00+00:00")

    def fail_after_flush(
        repository: WaiverRepository,
        requested_project_id: uuid.UUID,
        *,
        force: bool = False,
        changed_finding_ids: set[uuid.UUID] | None = None,
    ) -> dict[uuid.UUID, int]:
        _ = force, changed_finding_ids
        finding = repository.session.get(workbench_api_env.app_models.Finding, finding_id)
        persisted_project = repository.session.get(
            workbench_api_env.app_models.Project,
            requested_project_id,
        )
        assert finding is not None
        assert persisted_project is not None
        finding.status = FindingStatus.ACCEPTED
        persisted_project.waiver_evaluated_on = date(2026, 9, 2)
        repository.session.add(finding)
        repository.session.add(persisted_project)
        repository.session.flush()
        raise RuntimeError("synthetic waiver refresh failure")

    monkeypatch.setattr(WaiverRepository, "sync_project_waivers", fail_after_flush)
    with pytest.raises(RuntimeError, match="synthetic waiver refresh failure"):
        workbench_api_env.client.get(
            f"/api/v1/findings/{finding_id}",
            headers=headers,
        )

    with Session(workbench_api_env.engine) as session:
        finding = session.get(workbench_api_env.app_models.Finding, finding_id)
        persisted_project = session.get(workbench_api_env.app_models.Project, project_id)
        assert finding is not None
        assert persisted_project is not None
        assert finding.status == FindingStatus.OPEN
        assert persisted_project.waiver_evaluated_on == date(2026, 9, 1)


@pytest.mark.parametrize("terminal_status", [FindingStatus.FIXED, FindingStatus.SUPPRESSED])
def test_waiver_create_and_delete_preserve_legacy_terminal_status_without_projection(
    workbench_api_env: WorkbenchApiEnv,
    terminal_status: FindingStatus,
) -> None:
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    project_id = uuid.UUID(project["id"])
    finding_id = seed_finding_pair(
        workbench_api_env.engine,
        workbench_api_env.app_models,
        workbench_api_env.repositories,
        project_id=project_id,
    )["finding_ids"][0]
    with Session(workbench_api_env.engine) as session:
        finding = session.get(workbench_api_env.app_models.Finding, finding_id)
        assert finding is not None
        finding.status = terminal_status
        session.add(finding)
        session.commit()

    created = workbench_api_env.client.post(
        f"/api/v1/projects/{project['id']}/waivers/",
        headers=headers,
        json={
            "finding_id": str(finding_id),
            "owner": "risk-owner",
            "reason": "Terminal workflow states must remain authoritative.",
            "expires_at": "2099-12-31",
        },
    )
    assert created.status_code == 200, created.text
    after_create = workbench_api_env.client.get(
        f"/api/v1/findings/{finding_id}",
        headers=headers,
    )
    assert after_create.status_code == 200, after_create.text
    assert after_create.json()["status"] == terminal_status.value

    deleted = workbench_api_env.client.delete(
        f"/api/v1/waivers/{created.json()['id']}",
        headers=headers,
    )
    assert deleted.status_code == 204, deleted.text
    after_delete = workbench_api_env.client.get(
        f"/api/v1/findings/{finding_id}",
        headers=headers,
    )
    assert after_delete.status_code == 200, after_delete.text
    assert after_delete.json()["status"] == terminal_status.value

"""Current queue reads preserve decisions without loading their historical graphs."""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from sqlmodel import Session
from utils.workbench_env import WorkbenchApiEnv, create_project_via_api, seed_finding_pair

from app.repositories import FindingRepository, RunRepository, WaiverRepository
from app.repositories.current_projections import FindingCurrentProjectionRepository
from app.services.dashboard import build_project_dashboard_payload


def test_compact_list_and_dashboard_preserve_sla_without_hydrating_evidence(
    workbench_api_env: WorkbenchApiEnv,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    env = workbench_api_env
    project = create_project_via_api(env.client, {})
    project_id = uuid.UUID(project["id"])
    seeded = seed_finding_pair(
        env.engine,
        env.app_models,
        env.repositories,
        project_id=project_id,
        with_decision_evidence=True,
    )
    with Session(env.engine) as session:
        repository = FindingCurrentProjectionRepository(session)
        for finding_id in seeded["finding_ids"]:
            payload = repository.current_payload(finding_id)
            assert payload is not None
            # Provider documents can grow independently of the list contract.
            payload["provider"]["provider_evidence"]["large_advisory"] = "x" * 262_144
            payload["remediation"]["sla"] = {"label": "Custom policy", "target_hours": 6}
            repository.update_current_payload(finding_id, payload)
        session.commit()
    endpoint = f"/api/v1/projects/{project_id}"
    expanded = env.client.get(endpoint + "/findings/", params={"include_evidence": True})
    assert expanded.status_code == 200, expanded.text
    full_rows = expanded.json()["data"]
    assert all(row["evidence"] for row in full_rows)
    assert any(row["sla"] is not None for row in full_rows)

    def unexpected_hydration(*_args: Any, **_kwargs: Any) -> None:
        pytest.fail("A compact current read must not hydrate historical finding evidence")

    with monkeypatch.context() as patch:
        patch.setattr(
            FindingCurrentProjectionRepository, "evidence_for_records", unexpected_hydration
        )
        compact = env.client.get(endpoint + "/findings/")
        assert compact.status_code == 200, compact.text
        rows = compact.json()["data"]
        assert all(row["evidence"] is None for row in rows)
        assert [
            {key: value for key, value in row.items() if key != "evidence"} for row in rows
        ] == [{key: value for key, value in row.items() if key != "evidence"} for row in full_rows]
        assert len(compact.content) < len(expanded.content) * 0.15
        assert len(compact.content) < len(rows) * 4_000
        dashboard = env.client.get(endpoint + "/dashboard")
        assert dashboard.status_code == 200, dashboard.text
        queue = dashboard.json()["findings"]["remediation_queue"]["data"]
        assert all(row["evidence"] is None for row in queue)
        assert [row["sla"] for row in queue] == [row["sla"] for row in rows]
    detail = env.client.get(f"/api/v1/findings/{rows[0]['id']}")
    assert detail.status_code == 200, detail.text
    assert detail.json()["evidence"] == full_rows[0]["evidence"]


def test_compact_dashboard_matches_aggregates_from_full_recorded_decisions(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    env = workbench_api_env
    project = create_project_via_api(env.client, {})
    project_id = uuid.UUID(project["id"])
    seed_finding_pair(
        env.engine,
        env.app_models,
        env.repositories,
        project_id=project_id,
        with_decision_evidence=True,
    )
    with Session(env.engine) as session:
        runs, _ = RunRepository(session).list_analysis_runs_page(project_id, limit=30)
        waivers = WaiverRepository(session)
        expected = build_project_dashboard_payload(
            project_id=project_id,
            findings=FindingRepository(session).list_project_findings(project_id),
            runs=runs,
            waivers=waivers.list_project_waivers(project_id),
            waiver_repository=waivers,
            remediation_limit=50,
        ).model_dump(mode="json")
    response = env.client.get(f"/api/v1/projects/{project_id}/dashboard")
    assert response.status_code == 200, response.text
    actual = response.json()
    for key in ("summary", "risk_reduction"):
        assert actual[key] == expected[key]
    assert actual["findings"]["signal_counts"] == expected["findings"]["signal_counts"]
    for key in expected["governance"]:
        if key != "generated_at":
            assert actual["governance"][key] == expected["governance"][key]

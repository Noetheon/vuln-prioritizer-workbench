from __future__ import annotations

import uuid

from sqlmodel import Session
from utils.workbench_env import (
    WorkbenchApiEnv,
    create_asset,
    create_component,
    create_finding,
    create_project_via_api,
    create_vulnerability,
    local_api_headers,
    seed_finding_pair,
)

from app.decision_core import finding_queries
from app.repositories import FindingPageQuery


def test_operational_findings_page_uses_database_projection_without_evidence_scan(
    workbench_api_env: WorkbenchApiEnv,
    monkeypatch,
) -> None:
    project = create_project_via_api(
        workbench_api_env.client,
        local_api_headers(workbench_api_env.client),
    )
    project_id = uuid.UUID(project["id"])
    with Session(workbench_api_env.engine) as session:
        asset = create_asset(
            session,
            workbench_api_env.app_models,
            workbench_api_env.repositories,
            project_id=project_id,
        )
        component = create_component(session, workbench_api_env.repositories)
        for index in range(5):
            cve_id = f"CVE-2024-{index + 1:04d}"
            vulnerability = create_vulnerability(
                session,
                workbench_api_env.repositories,
                cve_id=cve_id,
            )
            create_finding(
                session,
                workbench_api_env.app_models,
                workbench_api_env.repositories,
                project_id=project_id,
                vulnerability_id=vulnerability.id,
                component_id=component.id,
                asset_id=asset.id,
                cve_id=cve_id,
            )
        session.commit()

    def fail_evidence_scan(*_args, **_kwargs):  # noqa: ANN002, ANN003, ANN202
        raise AssertionError("Current finding pages must not scan historical evidence.")

    monkeypatch.setattr(finding_queries, "project_finding_decision_views", fail_evidence_scan)

    with Session(workbench_api_env.engine) as session:
        findings, count = finding_queries.list_project_findings_query(
            session,
            FindingPageQuery(project_id=project_id, limit=2, sort="operational"),
        )

    assert count == 5
    assert len(findings) == 2
    assert [finding.cve_id for finding in findings] == ["CVE-2024-0001", "CVE-2024-0002"]

    with Session(workbench_api_env.engine) as session:
        wildcard_findings, wildcard_count = finding_queries.list_project_findings_query(
            session,
            FindingPageQuery(project_id=project_id, query="2024_0001"),
        )
        literal_findings, literal_count = finding_queries.list_project_findings_query(
            session,
            FindingPageQuery(project_id=project_id, query="2024-0001"),
        )

    assert wildcard_findings == []
    assert wildcard_count == 0
    assert [finding.cve_id for finding in literal_findings] == ["CVE-2024-0001"]
    assert literal_count == 1


def test_numeric_sort_keeps_missing_projection_values_last_in_both_directions(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    project = create_project_via_api(
        workbench_api_env.client,
        local_api_headers(workbench_api_env.client),
    )
    project_id = uuid.UUID(project["id"])
    seeded = seed_finding_pair(
        workbench_api_env.engine,
        workbench_api_env.app_models,
        workbench_api_env.repositories,
        project_id=project_id,
        with_decision_evidence=True,
    )
    with Session(workbench_api_env.engine) as session:
        asset = create_asset(
            session,
            workbench_api_env.app_models,
            workbench_api_env.repositories,
            project_id=project_id,
            asset_key="unknown-score-api",
            name="Unknown Score API",
        )
        component = create_component(
            session,
            workbench_api_env.repositories,
            name="unknown-score-component",
        )
        vulnerability = create_vulnerability(
            session,
            workbench_api_env.repositories,
            cve_id="CVE-2024-9999",
        )
        missing_score = create_finding(
            session,
            workbench_api_env.app_models,
            workbench_api_env.repositories,
            project_id=project_id,
            vulnerability_id=vulnerability.id,
            component_id=component.id,
            asset_id=asset.id,
            cve_id="CVE-2024-9999",
        )
        missing_score_id = missing_score.id
        session.commit()

    with Session(workbench_api_env.engine) as session:
        ascending, _ = finding_queries.list_project_findings_query(
            session,
            FindingPageQuery(project_id=project_id, sort="score", direction="asc"),
        )
        descending, _ = finding_queries.list_project_findings_query(
            session,
            FindingPageQuery(project_id=project_id, sort="score", direction="desc"),
        )

    seeded_ids = [uuid.UUID(str(value)) for value in seeded["finding_ids"]]
    assert [finding.id for finding in ascending] == [
        seeded_ids[1],
        seeded_ids[0],
        missing_score_id,
    ]
    assert [finding.id for finding in descending] == [
        seeded_ids[0],
        seeded_ids[1],
        missing_score_id,
    ]

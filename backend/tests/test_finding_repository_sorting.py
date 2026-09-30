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


def test_legacy_findings_without_projection_keep_component_query_fallback(
    workbench_api_env: WorkbenchApiEnv,
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
        for cve_id, component_name in (
            ("CVE-2024-8001", "legacy-zulu"),
            ("CVE-2024-8002", "legacy-alpha"),
        ):
            component = create_component(
                session,
                workbench_api_env.repositories,
                name=component_name,
            )
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

    with Session(workbench_api_env.engine) as session:
        matches, count = finding_queries.list_project_findings_query(
            session,
            FindingPageQuery(project_id=project_id, query="legacy-alpha"),
        )
        ordered, _ = finding_queries.list_project_findings_query(
            session,
            FindingPageQuery(project_id=project_id, sort="component", direction="asc"),
        )

    assert count == 1
    assert [finding.cve_id for finding in matches] == ["CVE-2024-8002"]
    assert [finding.cve_id for finding in ordered] == [
        "CVE-2024-8002",
        "CVE-2024-8001",
    ]


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


def test_priority_sort_puts_open_work_and_higher_scores_first_within_a_band(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    project = create_project_via_api(
        workbench_api_env.client,
        local_api_headers(workbench_api_env.client),
    )
    project_id = uuid.UUID(project["id"])
    rows = {
        # name: (cve, priority, rank, score, status)
        "accepted": ("CVE-2020-1472", "critical", 1, 25.0, "accepted"),
        "open_83": ("CVE-2020-1473", "critical", 1, 83.0, "open"),
        "open_99": ("CVE-2021-44228", "critical", 1, 99.0, "open"),
        "fixed": ("CVE-2021-44229", "critical", 1, 0.0, "fixed"),
        "low": ("CVE-2024-7347", "low", 4, 26.0, "open"),
    }
    ids: dict[str, uuid.UUID] = {}
    with Session(workbench_api_env.engine) as session:
        asset = create_asset(
            session,
            workbench_api_env.app_models,
            workbench_api_env.repositories,
            project_id=project_id,
        )
        component = create_component(session, workbench_api_env.repositories)
        for name, (cve_id, priority, rank, score, status) in rows.items():
            vulnerability = create_vulnerability(
                session,
                workbench_api_env.repositories,
                cve_id=cve_id,
            )
            finding = create_finding(
                session,
                workbench_api_env.app_models,
                workbench_api_env.repositories,
                project_id=project_id,
                vulnerability_id=vulnerability.id,
                component_id=component.id,
                asset_id=asset.id,
                cve_id=cve_id,
            )
            session.add(
                workbench_api_env.app_models.FindingCurrentProjection(
                    finding_id=finding.id,
                    project_id=project_id,
                    cve_id=cve_id,
                    dedup_key=f"{cve_id}|{name}",
                    priority=priority,
                    status=status,
                    priority_rank=rank,
                    risk_score=score,
                    read_summary_json={},
                    source_payload_sha256="0" * 64,
                    projection_payload_sha256="0" * 64,
                )
            )
            ids[name] = finding.id
        session.commit()

    def ordered(direction: str) -> list[str]:
        with Session(workbench_api_env.engine) as session:
            findings, _ = finding_queries.list_project_findings_query(
                session,
                FindingPageQuery(project_id=project_id, sort="priority", direction=direction),
            )
        by_id = {value: key for key, value in ids.items()}
        return [by_id[finding.id] for finding in findings]

    assert ordered("asc") == ["open_99", "open_83", "accepted", "fixed", "low"]
    assert ordered("desc") == ["low", "open_99", "open_83", "accepted", "fixed"]

from __future__ import annotations

import uuid
from types import SimpleNamespace

from sqlmodel import Session
from utils.workbench_env import (
    WorkbenchApiEnv,
    create_asset,
    create_component,
    create_finding,
    create_project_via_api,
    create_vulnerability,
    local_api_headers,
)

from app.decision_core import finding_queries
from app.decision_core.finding_queries import _can_use_database_cve_page, _finding_page_sort_key
from app.repositories import FindingPageQuery


def test_finding_page_operational_sort_key_stabilizes_equal_rank_ties() -> None:
    query = SimpleNamespace(sort="operational")
    tied_views = [
        _view("payments", "team-payments", "pay-api-01"),
        _view("identity", "team-identity", "id-admin-01"),
        _view("catalog", "team-catalog", "catalog-api-01"),
    ]

    sorted_views = sorted(tied_views, key=lambda view: _finding_page_sort_key(view, query))

    assert [_service(view) for view in sorted_views] == [
        "catalog",
        "identity",
        "payments",
    ]


def test_unfiltered_cve_sort_can_use_database_pagination_without_evidence_filters() -> None:
    project_id = uuid.uuid4()

    assert _can_use_database_cve_page(FindingPageQuery(project_id=project_id, sort="cve"))
    assert not _can_use_database_cve_page(
        FindingPageQuery(project_id=project_id, sort="cve", priority="High")
    )
    assert not _can_use_database_cve_page(
        FindingPageQuery(project_id=project_id, sort="operational")
    )


def test_operational_findings_page_batches_general_query_evidence_lookup(
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

    chunk_sizes: list[int] = []
    original_project_finding_decision_views = finding_queries.project_finding_decision_views

    def recording_project_finding_decision_views(session, findings):  # noqa: ANN001
        chunk_sizes.append(len(findings))
        return original_project_finding_decision_views(session, findings)

    monkeypatch.setattr(finding_queries, "_GENERAL_FINDING_PAGE_CHUNK_SIZE", 2)
    monkeypatch.setattr(
        finding_queries,
        "project_finding_decision_views",
        recording_project_finding_decision_views,
    )

    with Session(workbench_api_env.engine) as session:
        findings, count = finding_queries.list_project_findings_query(
            session,
            FindingPageQuery(project_id=project_id, limit=2, sort="operational"),
        )

    assert count == 5
    assert len(findings) == 2
    assert chunk_sizes == [2, 2, 1]


def _view(business_service: str, owner: str, asset_key: str) -> SimpleNamespace:
    asset = SimpleNamespace(
        asset_key=asset_key,
        business_service=business_service,
        owner=owner,
    )
    component = SimpleNamespace(name="log4j-core", version="2.14.1")
    finding = SimpleNamespace(asset=asset, component=component, id=uuid.uuid4())
    return SimpleNamespace(
        cve_id="CVE-2021-44228",
        finding=finding,
        operational_rank=1,
        priority_rank=1,
    )


def _service(view: SimpleNamespace) -> str:
    return str(view.finding.asset.business_service)

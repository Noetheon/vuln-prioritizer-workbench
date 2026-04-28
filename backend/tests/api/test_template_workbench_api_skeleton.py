from __future__ import annotations

import importlib
import uuid
from collections.abc import Callable, Generator, Iterator
from dataclasses import dataclass
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.engine import Engine
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

from app.core.config import settings
from app.main import app

_CONFIGURED_USER_ID = uuid.UUID("00000000-0000-4000-8000-000000000011")


@dataclass(frozen=True)
class TemplateApiEnv:
    client: TestClient
    engine: Engine
    app_models: Any
    repositories: Any


@pytest.fixture()
def api_env() -> Iterator[TemplateApiEnv]:
    env, cleanup = _client_with_temp_database(configured_is_superuser=True)
    try:
        yield env
    finally:
        cleanup()


@pytest.fixture()
def restricted_api_env() -> Iterator[TemplateApiEnv]:
    env, cleanup = _client_with_temp_database(configured_is_superuser=False)
    try:
        yield env
    finally:
        cleanup()


def test_vpw011_openapi_exposes_workbench_domain_routes_without_items() -> None:
    client = TestClient(app)

    response = client.get("/api/v1/openapi.json")

    assert response.status_code == 200
    payload = response.json()
    paths = set(payload["paths"])
    schemas = set(payload["components"]["schemas"])

    expected_paths = {
        "/api/v1/projects/",
        "/api/v1/projects/{project_id}",
        "/api/v1/projects/{project_id}/assets/",
        "/api/v1/assets/{asset_id}",
        "/api/v1/projects/{project_id}/runs/",
        "/api/v1/runs/{run_id}",
        "/api/v1/projects/{project_id}/findings/",
        "/api/v1/findings/{finding_id}",
    }
    expected_schemas = {
        "AnalysisRunPublic",
        "AnalysisRunsPublic",
        "AssetCreate",
        "AssetPublic",
        "AssetsPublic",
        "AssetUpdate",
        "FindingPublic",
        "FindingsPublic",
        "ProjectCreate",
        "ProjectPublic",
        "ProjectsPublic",
        "ProjectUpdate",
    }
    assert expected_paths.issubset(paths)

    assert all("/items" not in path for path in paths)
    assert client.get("/api/v1/items/").status_code == 404
    assert expected_schemas.issubset(schemas)
    assert all("Item" not in schema_name for schema_name in schemas)


def test_vpw011_domain_routes_require_auth(api_env: TemplateApiEnv) -> None:
    project_id = uuid.uuid4()
    asset_id = uuid.uuid4()
    run_id = uuid.uuid4()
    finding_id = uuid.uuid4()

    protected_calls: tuple[tuple[str, str, dict[str, Any]], ...] = (
        ("get", "/api/v1/projects/", {}),
        ("post", "/api/v1/projects/", {"json": {"name": "Unauthenticated Project"}}),
        ("get", f"/api/v1/projects/{project_id}", {}),
        ("patch", f"/api/v1/projects/{project_id}", {"json": {"name": "Updated"}}),
        ("delete", f"/api/v1/projects/{project_id}", {}),
        ("get", f"/api/v1/projects/{project_id}/assets/", {}),
        (
            "post",
            f"/api/v1/projects/{project_id}/assets/",
            {
                "json": {
                    "asset_key": "payments-api",
                    "name": "Payments API",
                }
            },
        ),
        ("patch", f"/api/v1/assets/{asset_id}", {"json": {"name": "Renamed API"}}),
        ("get", f"/api/v1/projects/{project_id}/runs/", {}),
        ("get", f"/api/v1/runs/{run_id}", {}),
        (
            "get",
            f"/api/v1/projects/{project_id}/findings/",
            {"params": {"limit": 1, "offset": 0}},
        ),
        ("get", f"/api/v1/findings/{finding_id}", {}),
    )

    for method, path, kwargs in protected_calls:
        response = getattr(api_env.client, method)(path, **kwargs)
        assert response.status_code == 401, f"{method.upper()} {path}: {response.text}"


def test_vpw011_project_lifecycle_create_list_get_update_delete(
    api_env: TemplateApiEnv,
) -> None:
    headers = _auth_headers(api_env.client)

    create_response = api_env.client.post(
        "/api/v1/projects/",
        headers=headers,
        json={
            "name": "External Attack Surface",
            "description": "Internet-facing CVE prioritization workspace.",
        },
    )
    assert create_response.status_code == 200
    created = create_response.json()
    assert created["name"] == "External Attack Surface"
    assert created["description"] == "Internet-facing CVE prioritization workspace."
    assert created["owner_id"] == _current_user(api_env.client, headers)["id"]

    list_response = api_env.client.get("/api/v1/projects/", headers=headers)
    assert list_response.status_code == 200
    assert list_response.json()["data"] == [created]
    assert list_response.json()["count"] == 1

    get_response = api_env.client.get(f"/api/v1/projects/{created['id']}", headers=headers)
    assert get_response.status_code == 200
    assert get_response.json() == created

    update_response = api_env.client.patch(
        f"/api/v1/projects/{created['id']}",
        headers=headers,
        json={
            "name": "External Attack Surface Updated",
            "description": "Updated Workbench project description.",
        },
    )
    assert update_response.status_code == 200
    updated = update_response.json()
    assert updated["id"] == created["id"]
    assert updated["owner_id"] == created["owner_id"]
    assert updated["name"] == "External Attack Surface Updated"
    assert updated["description"] == "Updated Workbench project description."

    delete_response = api_env.client.delete(
        f"/api/v1/projects/{created['id']}",
        headers=headers,
    )
    assert delete_response.status_code == 204

    missing_after_delete = api_env.client.get(
        f"/api/v1/projects/{created['id']}",
        headers=headers,
    )
    assert missing_after_delete.status_code == 404
    assert api_env.client.get("/api/v1/projects/", headers=headers).json() == {
        "data": [],
        "count": 0,
    }


def test_vpw011_asset_list_create_and_update(api_env: TemplateApiEnv) -> None:
    headers = _auth_headers(api_env.client)
    project = _create_project(api_env.client, headers)

    create_response = api_env.client.post(
        f"/api/v1/projects/{project['id']}/assets/",
        headers=headers,
        json={
            "asset_key": "payments-api",
            "name": "Payments API",
            "target_ref": "registry.example.test/payments-api:2026.04.28",
            "owner": "platform",
            "business_service": "payments",
            "environment": "production",
            "exposure": "internet-facing",
            "criticality": "critical",
        },
    )
    assert create_response.status_code == 200
    created = create_response.json()
    assert created["project_id"] == project["id"]
    assert created["asset_key"] == "payments-api"
    assert created["name"] == "Payments API"
    assert created["environment"] == "production"
    assert created["exposure"] == "internet-facing"
    assert created["criticality"] == "critical"

    list_response = api_env.client.get(
        f"/api/v1/projects/{project['id']}/assets/",
        headers=headers,
    )
    assert list_response.status_code == 200
    assert list_response.json()["data"] == [created]
    assert list_response.json()["count"] == 1

    update_response = api_env.client.patch(
        f"/api/v1/assets/{created['id']}",
        headers=headers,
        json={"name": "Payments API Cluster", "criticality": "high"},
    )
    assert update_response.status_code == 200
    updated = update_response.json()
    assert updated["id"] == created["id"]
    assert updated["project_id"] == project["id"]
    assert updated["name"] == "Payments API Cluster"
    assert updated["criticality"] == "high"


def test_vpw011_run_list_and_get_use_repository_seeded_graph(
    api_env: TemplateApiEnv,
) -> None:
    headers = _auth_headers(api_env.client)
    project = _create_project(api_env.client, headers)
    seeded = _seed_analysis_run(
        api_env.engine,
        api_env.app_models,
        api_env.repositories,
        project_id=uuid.UUID(project["id"]),
    )

    list_response = api_env.client.get(
        f"/api/v1/projects/{project['id']}/runs/",
        headers=headers,
    )
    assert list_response.status_code == 200
    list_payload = list_response.json()
    assert list_payload["count"] == 1
    assert list_payload["data"][0]["id"] == str(seeded["run_id"])
    assert list_payload["data"][0]["project_id"] == project["id"]
    assert list_payload["data"][0]["status"] == "completed"

    get_response = api_env.client.get(f"/api/v1/runs/{seeded['run_id']}", headers=headers)
    assert get_response.status_code == 200
    detail = get_response.json()
    assert detail["id"] == str(seeded["run_id"])
    assert detail["provider_snapshot_id"] == str(seeded["provider_snapshot_id"])
    assert detail["summary_json"] == {"parsed": 2, "findings": 2}


def test_vpw011_finding_list_and_get_support_pagination(
    api_env: TemplateApiEnv,
) -> None:
    headers = _auth_headers(api_env.client)
    project = _create_project(api_env.client, headers)
    seeded = _seed_findings(
        api_env.engine,
        api_env.app_models,
        api_env.repositories,
        project_id=uuid.UUID(project["id"]),
    )

    list_response = api_env.client.get(
        f"/api/v1/projects/{project['id']}/findings/",
        headers=headers,
        params={"limit": 1, "offset": 1},
    )
    assert list_response.status_code == 200
    page = list_response.json()
    assert page["count"] == 2
    assert len(page["data"]) == 1
    assert page["data"][0]["id"] == str(seeded["finding_ids"][1])
    assert page["data"][0]["cve_id"] == "CVE-2024-3094"

    get_response = api_env.client.get(
        f"/api/v1/findings/{seeded['finding_ids'][0]}",
        headers=headers,
    )
    assert get_response.status_code == 200
    detail = get_response.json()
    assert detail["id"] == str(seeded["finding_ids"][0])
    assert detail["project_id"] == project["id"]
    assert detail["cve_id"] == "CVE-2021-44228"
    assert detail["priority"] == "critical"
    assert detail["in_kev"] is True


def test_vpw011_404_and_403_are_consistent_for_project_scoped_resources(
    restricted_api_env: TemplateApiEnv,
) -> None:
    headers = _auth_headers(restricted_api_env.client)
    foreign = _seed_foreign_project_graph(
        restricted_api_env.engine,
        restricted_api_env.app_models,
        restricted_api_env.repositories,
    )
    missing_id = uuid.UUID("00000000-0000-4000-8000-000000000404")

    not_found_calls: tuple[tuple[str, str, dict[str, Any]], ...] = (
        ("get", f"/api/v1/projects/{missing_id}", {}),
        ("patch", f"/api/v1/assets/{missing_id}", {"json": {"name": "Missing Asset"}}),
        ("get", f"/api/v1/runs/{missing_id}", {}),
        ("get", f"/api/v1/findings/{missing_id}", {}),
        ("get", f"/api/v1/projects/{missing_id}/assets/", {}),
        ("get", f"/api/v1/projects/{missing_id}/runs/", {}),
        ("get", f"/api/v1/projects/{missing_id}/findings/", {}),
    )
    forbidden_calls: tuple[tuple[str, str, dict[str, Any]], ...] = (
        ("get", f"/api/v1/projects/{foreign['project_id']}", {}),
        ("patch", f"/api/v1/assets/{foreign['asset_id']}", {"json": {"name": "Foreign Asset"}}),
        ("get", f"/api/v1/runs/{foreign['run_id']}", {}),
        ("get", f"/api/v1/findings/{foreign['finding_id']}", {}),
        ("get", f"/api/v1/projects/{foreign['project_id']}/assets/", {}),
        ("get", f"/api/v1/projects/{foreign['project_id']}/runs/", {}),
        ("get", f"/api/v1/projects/{foreign['project_id']}/findings/", {}),
    )

    for method, path, kwargs in not_found_calls:
        response = getattr(restricted_api_env.client, method)(path, headers=headers, **kwargs)
        assert response.status_code == 404, f"{method.upper()} {path}: {response.text}"

    for method, path, kwargs in forbidden_calls:
        response = getattr(restricted_api_env.client, method)(path, headers=headers, **kwargs)
        assert response.status_code == 403, f"{method.upper()} {path}: {response.text}"

    invalid_sort = restricted_api_env.client.get(
        f"/api/v1/projects/{missing_id}/findings/",
        headers=headers,
        params={"sort": "unknown"},
    )
    assert invalid_sort.status_code == 422


def _client_with_temp_database(
    *,
    configured_is_superuser: bool,
) -> tuple[TemplateApiEnv, Callable[[], None]]:
    from app.api import deps
    from app.core import security

    app.dependency_overrides.clear()
    app_models = importlib.import_module("app.models")
    app_models.import_table_models()
    repositories = importlib.import_module("app.repositories")
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)

    with Session(engine) as session:
        _seed_configured_user(
            session,
            app_models,
            security,
            is_superuser=configured_is_superuser,
        )

    def override_get_db() -> Generator[Session, None, None]:
        with Session(engine) as session:
            yield session

    app.dependency_overrides[deps.get_db] = override_get_db

    def cleanup() -> None:
        app.dependency_overrides.pop(deps.get_db, None)
        engine.dispose()

    return TemplateApiEnv(TestClient(app), engine, app_models, repositories), cleanup


def _seed_configured_user(
    session: Session,
    app_models: Any,
    security: Any,
    *,
    is_superuser: bool,
) -> None:
    password_hash = getattr(security, "get_password_hash", lambda password: password)(
        settings.FIRST_SUPERUSER_PASSWORD
    )
    session.add(
        app_models.User(
            id=_CONFIGURED_USER_ID,
            email=settings.FIRST_SUPERUSER,
            hashed_password=password_hash,
            is_active=True,
            is_superuser=is_superuser,
        )
    )
    session.commit()


def _login(client: TestClient) -> str:
    response = client.post(
        "/api/v1/login/access-token",
        data={
            "username": settings.FIRST_SUPERUSER,
            "password": settings.FIRST_SUPERUSER_PASSWORD,
        },
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["token_type"] == "bearer"
    return str(payload["access_token"])


def _auth_headers(client: TestClient) -> dict[str, str]:
    return {"Authorization": f"Bearer {_login(client)}"}


def _current_user(client: TestClient, headers: dict[str, str]) -> dict[str, Any]:
    response = client.get("/api/v1/users/me", headers=headers)
    assert response.status_code == 200
    return response.json()


def _create_project(client: TestClient, headers: dict[str, str]) -> dict[str, Any]:
    response = client.post(
        "/api/v1/projects/",
        headers=headers,
        json={"name": "Workbench API Contract", "description": None},
    )
    assert response.status_code == 200
    return response.json()


def _seed_analysis_run(
    engine: Engine,
    app_models: Any,
    repositories: Any,
    *,
    project_id: uuid.UUID,
) -> dict[str, uuid.UUID]:
    with Session(engine) as session:
        run_repository = repositories.RunRepository(session)
        snapshot = run_repository.get_or_create_provider_snapshot(
            content_hash=f"sha256:{uuid.uuid4().hex}",
            nvd_last_sync="2026-04-28T10:15:00Z",
            epss_date="2026-04-28",
            kev_catalog_version="2026-04-28",
            source_hashes_json={"nvd": "sha256:nvd-feed"},
        )
        run = run_repository.create_analysis_run(
            project_id=project_id,
            provider_snapshot_id=snapshot.id,
            input_type="cve-list",
            filename="known-cves.txt",
            status=app_models.AnalysisRunStatus.COMPLETED,
            summary_json={"parsed": 2, "findings": 2},
        )
        run_id = run.id
        snapshot_id = snapshot.id
        session.commit()
    return {"run_id": run_id, "provider_snapshot_id": snapshot_id}


def _seed_findings(
    engine: Engine,
    app_models: Any,
    repositories: Any,
    *,
    project_id: uuid.UUID,
) -> dict[str, list[uuid.UUID]]:
    with Session(engine) as session:
        asset = repositories.AssetRepository(session).upsert_asset(
            project_id=project_id,
            asset_key="payments-api",
            name="Payments API",
            environment=app_models.AssetEnvironment.PRODUCTION,
            exposure=app_models.AssetExposure.INTERNET_FACING,
            criticality=app_models.AssetCriticality.CRITICAL,
        )
        finding_repository = repositories.FindingRepository(session)
        component = finding_repository.upsert_component(
            name="log4j-core",
            version="2.14.1",
            purl=f"pkg:maven/org.apache.logging.log4j/log4j-core@{uuid.uuid4().hex}",
            ecosystem="maven",
        )
        first_vulnerability = finding_repository.upsert_vulnerability(
            cve_id="CVE-2021-44228",
            source_id="CVE-2021-44228",
            cvss_score=10.0,
            severity="CRITICAL",
        )
        second_vulnerability = finding_repository.upsert_vulnerability(
            cve_id="CVE-2024-3094",
            source_id="CVE-2024-3094",
            cvss_score=10.0,
            severity="CRITICAL",
        )
        first_finding = finding_repository.create_or_update_finding(
            project_id=project_id,
            vulnerability_id=first_vulnerability.id,
            component_id=component.id,
            asset_id=asset.id,
            cve_id="CVE-2021-44228",
            priority=app_models.FindingPriority.CRITICAL,
            priority_rank=1,
            operational_rank=1,
            in_kev=True,
        )
        second_finding = finding_repository.create_or_update_finding(
            project_id=project_id,
            vulnerability_id=second_vulnerability.id,
            component_id=component.id,
            asset_id=asset.id,
            cve_id="CVE-2024-3094",
            priority=app_models.FindingPriority.HIGH,
            priority_rank=2,
            operational_rank=2,
            in_kev=True,
        )
        finding_ids = [first_finding.id, second_finding.id]
        session.commit()
    return {"finding_ids": finding_ids}


def _seed_foreign_project_graph(
    engine: Engine,
    app_models: Any,
    repositories: Any,
) -> dict[str, uuid.UUID]:
    foreign_user_id = uuid.uuid4()
    with Session(engine) as session:
        session.add(
            app_models.User(
                id=foreign_user_id,
                email=f"{foreign_user_id}@example.test",
                hashed_password="not-used",
                is_active=True,
                is_superuser=False,
            )
        )
        project = repositories.ProjectRepository(session).create_project(
            app_models.ProjectCreate(name="Foreign Project", description=None),
            owner_id=foreign_user_id,
        )
        asset = repositories.AssetRepository(session).upsert_asset(
            project_id=project.id,
            asset_key="foreign-api",
            name="Foreign API",
        )
        run_ids = _seed_analysis_run_in_session(
            session,
            app_models,
            repositories,
            project_id=project.id,
        )
        finding = _seed_finding_in_session(
            session,
            app_models,
            repositories,
            project_id=project.id,
            asset_id=asset.id,
        )
        ids = {
            "project_id": project.id,
            "asset_id": asset.id,
            "run_id": run_ids["run_id"],
            "finding_id": finding.id,
        }
        session.commit()
    return ids


def _seed_analysis_run_in_session(
    session: Session,
    app_models: Any,
    repositories: Any,
    *,
    project_id: uuid.UUID,
) -> dict[str, uuid.UUID]:
    run_repository = repositories.RunRepository(session)
    snapshot = run_repository.get_or_create_provider_snapshot(
        content_hash=f"sha256:{uuid.uuid4().hex}",
        source_hashes_json={"nvd": "sha256:nvd-feed"},
    )
    run = run_repository.create_analysis_run(
        project_id=project_id,
        provider_snapshot_id=snapshot.id,
        input_type="cve-list",
        filename="foreign-cves.txt",
        status=app_models.AnalysisRunStatus.COMPLETED,
    )
    return {"run_id": run.id, "provider_snapshot_id": snapshot.id}


def _seed_finding_in_session(
    session: Session,
    app_models: Any,
    repositories: Any,
    *,
    project_id: uuid.UUID,
    asset_id: uuid.UUID,
) -> Any:
    finding_repository = repositories.FindingRepository(session)
    vulnerability = finding_repository.upsert_vulnerability(
        cve_id=f"CVE-2026-{uuid.uuid4().int % 10000:04d}",
        source_id="foreign-cve",
        cvss_score=7.5,
        severity="HIGH",
    )
    return finding_repository.create_or_update_finding(
        project_id=project_id,
        vulnerability_id=vulnerability.id,
        asset_id=asset_id,
        cve_id=vulnerability.cve_id,
        priority=app_models.FindingPriority.HIGH,
        priority_rank=2,
    )

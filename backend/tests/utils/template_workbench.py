"""Reusable fixtures and factories for the template Workbench domain tests."""

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
from utils.workbench_factories import (
    template_analysis_run as build_analysis_run_model,
)
from utils.workbench_factories import (
    template_asset as build_asset_model,
)
from utils.workbench_factories import (
    template_component as build_component_model,
)
from utils.workbench_factories import (
    template_finding as build_finding_model,
)
from utils.workbench_factories import (
    template_project as build_project_model,
)
from utils.workbench_factories import (
    template_provider_snapshot as build_provider_snapshot_model,
)
from utils.workbench_factories import (
    template_user as build_user_model,
)
from utils.workbench_factories import (
    template_vulnerability as build_vulnerability_model,
)

CONFIGURED_USER_ID = uuid.UUID("00000000-0000-4000-8000-000000000011")
DEMO_CVE_LOG4SHELL = "CVE-2021-44228"
DEMO_CVE_XZ = "CVE-2024-3094"


@dataclass(frozen=True)
class TemplateApiEnv:
    """FastAPI client plus its isolated in-memory template database."""

    client: TestClient
    engine: Engine
    app_models: Any
    repositories: Any


@dataclass(frozen=True)
class WorkbenchDomainGraph:
    """IDs for a minimal valid Workbench domain graph."""

    user_id: uuid.UUID
    project_id: uuid.UUID
    asset_id: uuid.UUID
    component_id: uuid.UUID
    vulnerability_id: uuid.UUID
    finding_id: uuid.UUID
    provider_snapshot_id: uuid.UUID
    run_id: uuid.UUID


@pytest.fixture()
def template_api_env() -> Iterator[TemplateApiEnv]:
    """Yield an authenticated-template-capable app with isolated SQLModel metadata."""
    env, cleanup = create_template_api_env(configured_is_superuser=True)
    try:
        yield env
    finally:
        cleanup()


@pytest.fixture()
def restricted_template_api_env() -> Iterator[TemplateApiEnv]:
    """Yield an app where the configured user is not a superuser."""
    env, cleanup = create_template_api_env(configured_is_superuser=False)
    try:
        yield env
    finally:
        cleanup()


@pytest.fixture()
def template_user_model() -> Any:
    """Return a minimal unsaved User object."""
    return build_user_model()


@pytest.fixture()
def template_project_model(template_user_model: Any) -> Any:
    """Return a minimal unsaved Project object."""
    return build_project_model(owner=template_user_model)


@pytest.fixture()
def template_asset_model(template_project_model: Any) -> Any:
    """Return a minimal unsaved Asset object."""
    return build_asset_model(project=template_project_model)


@pytest.fixture()
def template_component_model() -> Any:
    """Return a minimal unsaved Component object."""
    return build_component_model()


@pytest.fixture()
def template_vulnerability_model() -> Any:
    """Return a minimal unsaved Vulnerability object."""
    return build_vulnerability_model(cve_id=DEMO_CVE_LOG4SHELL)


@pytest.fixture()
def template_finding_model(
    template_project_model: Any,
    template_asset_model: Any,
    template_component_model: Any,
    template_vulnerability_model: Any,
) -> Any:
    """Return a minimal unsaved Finding object."""
    return build_finding_model(
        project=template_project_model,
        asset=template_asset_model,
        component=template_component_model,
        vulnerability=template_vulnerability_model,
    )


@pytest.fixture()
def template_provider_snapshot_model() -> Any:
    """Return a minimal unsaved ProviderSnapshot object."""
    return build_provider_snapshot_model()


@pytest.fixture()
def template_analysis_run_model(
    template_project_model: Any,
    template_provider_snapshot_model: Any,
) -> Any:
    """Return a minimal unsaved AnalysisRun object."""
    return build_analysis_run_model(
        project=template_project_model,
        provider_snapshot=template_provider_snapshot_model,
    )


def create_template_api_env(
    *,
    configured_is_superuser: bool = True,
) -> tuple[TemplateApiEnv, Callable[[], None]]:
    """Create a TestClient wired to a disposable in-memory SQLModel database."""
    from app.api import deps

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
        seed_configured_user(
            session,
            app_models,
            is_superuser=configured_is_superuser,
        )

    def override_get_db() -> Generator[Session, None, None]:
        with Session(engine) as session:
            yield session

    app.dependency_overrides[deps.get_db] = override_get_db

    def cleanup() -> None:
        app.dependency_overrides.clear()
        engine.dispose()

    return TemplateApiEnv(TestClient(app), engine, app_models, repositories), cleanup


def seed_configured_user(session: Session, app_models: Any, *, is_superuser: bool = True) -> Any:
    """Persist the configured template user without storing a real password secret."""
    user = make_user(
        app_models,
        user_id=CONFIGURED_USER_ID,
        email=settings.FIRST_SUPERUSER,
        is_superuser=is_superuser,
        hashed_password="configured-superuser-password-placeholder",
    )
    session.add(user)
    session.commit()
    return user


def make_user(
    app_models: Any,
    *,
    user_id: uuid.UUID | None = None,
    email: str = "owner@example.test",
    is_superuser: bool = True,
    hashed_password: str = "not-used",
) -> Any:
    """Build a minimal valid User model."""
    return app_models.User(
        id=user_id or uuid.uuid4(),
        email=email,
        hashed_password=hashed_password,
        is_active=True,
        is_superuser=is_superuser,
    )


def create_user(
    session: Session,
    app_models: Any,
    *,
    email: str = "owner@example.test",
    is_superuser: bool = True,
) -> Any:
    """Persist a minimal valid User and flush it for downstream FK use."""
    user = make_user(app_models, email=email, is_superuser=is_superuser)
    session.add(user)
    session.flush()
    return user


def create_project(
    session: Session,
    app_models: Any,
    repositories: Any,
    *,
    owner_id: uuid.UUID,
    name: str = "Workbench Fixture Project",
    description: str | None = None,
) -> Any:
    """Persist a minimal valid Project."""
    return repositories.ProjectRepository(session).create_project(
        app_models.ProjectCreate(name=name, description=description),
        owner_id=owner_id,
    )


def create_asset(
    session: Session,
    app_models: Any,
    repositories: Any,
    *,
    project_id: uuid.UUID,
    asset_key: str = "payments-api",
    name: str = "Payments API",
) -> Any:
    """Persist a minimal valid Asset."""
    return repositories.AssetRepository(session).upsert_asset(
        project_id=project_id,
        asset_key=asset_key,
        name=name,
        environment=app_models.AssetEnvironment.PRODUCTION,
        exposure=app_models.AssetExposure.INTERNET_FACING,
        criticality=app_models.AssetCriticality.CRITICAL,
    )


def create_component(
    session: Session,
    repositories: Any,
    *,
    name: str = "log4j-core",
    version: str = "2.14.1",
    purl: str | None = None,
    ecosystem: str = "maven",
) -> Any:
    """Persist a minimal valid Component."""
    return repositories.FindingRepository(session).upsert_component(
        name=name,
        version=version,
        purl=purl or f"pkg:maven/org.apache.logging.log4j/log4j-core@{uuid.uuid4().hex}",
        ecosystem=ecosystem,
    )


def create_vulnerability(
    session: Session,
    repositories: Any,
    *,
    cve_id: str = DEMO_CVE_LOG4SHELL,
    cvss_score: float = 10.0,
    severity: str = "CRITICAL",
) -> Any:
    """Persist a minimal valid Vulnerability."""
    return repositories.FindingRepository(session).upsert_vulnerability(
        cve_id=cve_id,
        source_id=cve_id,
        cvss_score=cvss_score,
        severity=severity,
    )


def create_finding(
    session: Session,
    app_models: Any,
    repositories: Any,
    *,
    project_id: uuid.UUID,
    vulnerability_id: uuid.UUID,
    cve_id: str,
    component_id: uuid.UUID | None = None,
    asset_id: uuid.UUID | None = None,
    priority: Any | None = None,
    priority_rank: int = 1,
    operational_rank: int = 1,
) -> Any:
    """Persist a minimal valid Finding."""
    return repositories.FindingRepository(session).create_or_update_finding(
        project_id=project_id,
        vulnerability_id=vulnerability_id,
        component_id=component_id,
        asset_id=asset_id,
        cve_id=cve_id,
        priority=priority or app_models.FindingPriority.CRITICAL,
        priority_rank=priority_rank,
        operational_rank=operational_rank,
        in_kev=True,
    )


def create_provider_snapshot(
    session: Session,
    repositories: Any,
    *,
    content_hash: str | None = None,
) -> Any:
    """Persist a minimal valid ProviderSnapshot."""
    return repositories.RunRepository(session).get_or_create_provider_snapshot(
        content_hash=content_hash or f"sha256:{uuid.uuid4().hex}",
        nvd_last_sync="2026-04-28T10:15:00Z",
        epss_date="2026-04-28",
        kev_catalog_version="2026-04-28",
        source_hashes_json={"nvd": "sha256:nvd-feed"},
    )


def create_analysis_run(
    session: Session,
    app_models: Any,
    repositories: Any,
    *,
    project_id: uuid.UUID,
    provider_snapshot_id: uuid.UUID | None = None,
    input_type: str = "cve-list",
    filename: str = "known-cves.txt",
    status: Any | None = None,
) -> Any:
    """Persist a minimal valid AnalysisRun."""
    return repositories.RunRepository(session).create_analysis_run(
        project_id=project_id,
        provider_snapshot_id=provider_snapshot_id,
        input_type=input_type,
        filename=filename,
        status=status or app_models.AnalysisRunStatus.COMPLETED,
        summary_json={"parsed": 2, "findings": 2},
    )


def seed_domain_graph(
    engine: Engine,
    app_models: Any,
    repositories: Any,
    *,
    user_email: str = "fixture-owner@example.test",
) -> WorkbenchDomainGraph:
    """Seed one valid User -> Project -> Asset/Component/Vulnerability/Finding/Run graph."""
    with Session(engine) as session:
        user = create_user(session, app_models, email=user_email, is_superuser=False)
        project = create_project(
            session,
            app_models,
            repositories,
            owner_id=user.id,
            name="Fixture Graph Project",
        )
        asset = create_asset(session, app_models, repositories, project_id=project.id)
        component = create_component(session, repositories)
        vulnerability = create_vulnerability(session, repositories)
        finding = create_finding(
            session,
            app_models,
            repositories,
            project_id=project.id,
            vulnerability_id=vulnerability.id,
            component_id=component.id,
            asset_id=asset.id,
            cve_id=vulnerability.cve_id,
        )
        snapshot = create_provider_snapshot(session, repositories)
        run = create_analysis_run(
            session,
            app_models,
            repositories,
            project_id=project.id,
            provider_snapshot_id=snapshot.id,
        )
        graph = WorkbenchDomainGraph(
            user_id=user.id,
            project_id=project.id,
            asset_id=asset.id,
            component_id=component.id,
            vulnerability_id=vulnerability.id,
            finding_id=finding.id,
            provider_snapshot_id=snapshot.id,
            run_id=run.id,
        )
        session.commit()
        return graph


def seed_analysis_run(
    engine: Engine,
    app_models: Any,
    repositories: Any,
    *,
    project_id: uuid.UUID,
) -> dict[str, uuid.UUID]:
    """Seed an AnalysisRun and ProviderSnapshot for API read tests."""
    with Session(engine) as session:
        snapshot = create_provider_snapshot(session, repositories)
        run = create_analysis_run(
            session,
            app_models,
            repositories,
            project_id=project_id,
            provider_snapshot_id=snapshot.id,
        )
        ids = {"run_id": run.id, "provider_snapshot_id": snapshot.id}
        session.commit()
        return ids


def seed_finding_pair(
    engine: Engine,
    app_models: Any,
    repositories: Any,
    *,
    project_id: uuid.UUID,
) -> dict[str, list[uuid.UUID]]:
    """Seed two deterministic demo-CVE findings for pagination tests."""
    with Session(engine) as session:
        asset = create_asset(session, app_models, repositories, project_id=project_id)
        component = create_component(session, repositories)
        first_vulnerability = create_vulnerability(
            session,
            repositories,
            cve_id=DEMO_CVE_LOG4SHELL,
        )
        second_vulnerability = create_vulnerability(
            session,
            repositories,
            cve_id=DEMO_CVE_XZ,
        )
        first_finding = create_finding(
            session,
            app_models,
            repositories,
            project_id=project_id,
            vulnerability_id=first_vulnerability.id,
            component_id=component.id,
            asset_id=asset.id,
            cve_id=DEMO_CVE_LOG4SHELL,
            priority=app_models.FindingPriority.CRITICAL,
            priority_rank=1,
            operational_rank=1,
        )
        second_finding = create_finding(
            session,
            app_models,
            repositories,
            project_id=project_id,
            vulnerability_id=second_vulnerability.id,
            component_id=component.id,
            asset_id=asset.id,
            cve_id=DEMO_CVE_XZ,
            priority=app_models.FindingPriority.HIGH,
            priority_rank=2,
            operational_rank=2,
        )
        finding_ids = [first_finding.id, second_finding.id]
        session.commit()
        return {"finding_ids": finding_ids}


def seed_foreign_project_graph(
    engine: Engine,
    app_models: Any,
    repositories: Any,
) -> dict[str, uuid.UUID]:
    """Seed a graph owned by a different non-superuser for 403 tests."""
    with Session(engine) as session:
        user = create_user(
            session,
            app_models,
            email=f"{uuid.uuid4()}@example.test",
            is_superuser=False,
        )
        project = create_project(
            session,
            app_models,
            repositories,
            owner_id=user.id,
            name="Foreign Project",
        )
        asset = create_asset(
            session,
            app_models,
            repositories,
            project_id=project.id,
            asset_key="foreign-api",
            name="Foreign API",
        )
        run_ids = seed_analysis_run_in_session(
            session,
            app_models,
            repositories,
            project_id=project.id,
        )
        finding = seed_finding_in_session(
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


def seed_analysis_run_in_session(
    session: Session,
    app_models: Any,
    repositories: Any,
    *,
    project_id: uuid.UUID,
) -> dict[str, uuid.UUID]:
    """Seed a ProviderSnapshot and AnalysisRun in an existing transaction."""
    snapshot = create_provider_snapshot(session, repositories)
    run = create_analysis_run(
        session,
        app_models,
        repositories,
        project_id=project_id,
        provider_snapshot_id=snapshot.id,
        filename="foreign-cves.txt",
    )
    return {"run_id": run.id, "provider_snapshot_id": snapshot.id}


def seed_finding_in_session(
    session: Session,
    app_models: Any,
    repositories: Any,
    *,
    project_id: uuid.UUID,
    asset_id: uuid.UUID,
) -> Any:
    """Seed one Finding in an existing transaction."""
    cve_id = f"CVE-2026-{uuid.uuid4().int % 10000:04d}"
    vulnerability = create_vulnerability(
        session,
        repositories,
        cve_id=cve_id,
        cvss_score=7.5,
        severity="HIGH",
    )
    return create_finding(
        session,
        app_models,
        repositories,
        project_id=project_id,
        vulnerability_id=vulnerability.id,
        asset_id=asset_id,
        cve_id=vulnerability.cve_id,
        priority=app_models.FindingPriority.HIGH,
        priority_rank=2,
    )


def login(client: TestClient) -> str:
    """Return a bearer token for the configured template user."""
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


def auth_headers(client: TestClient) -> dict[str, str]:
    """Return Authorization headers for the configured template user."""
    return {"Authorization": f"Bearer {login(client)}"}


def current_user(client: TestClient, headers: dict[str, str]) -> dict[str, Any]:
    """Read the current user through the public template API."""
    response = client.get("/api/v1/users/me", headers=headers)
    assert response.status_code == 200
    return response.json()


def create_project_via_api(client: TestClient, headers: dict[str, str]) -> dict[str, Any]:
    """Create a project through the API for route-level tests."""
    response = client.post(
        "/api/v1/projects/",
        headers=headers,
        json={"name": "Workbench API Contract", "description": None},
    )
    assert response.status_code == 200
    return response.json()

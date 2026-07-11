"""Reusable fixtures and factories for Workbench domain tests."""

from __future__ import annotations

import importlib
import uuid
from collections.abc import Callable, Generator, Iterator
from dataclasses import dataclass
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.engine import Engine
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

from app.core.config import settings
from app.core.local_actor import LocalWorkbenchActor, configured_local_actor
from app.core.migration_bootstrap import ALEMBIC_HEAD
from app.core.rate_limit import InMemoryRateLimiter
from app.main import app
from utils.workbench_factories import (
    workbench_analysis_run as build_analysis_run_model,
)
from utils.workbench_factories import (
    workbench_asset as build_asset_model,
)
from utils.workbench_factories import (
    workbench_component as build_component_model,
)
from utils.workbench_factories import (
    workbench_finding as build_finding_model,
)
from utils.workbench_factories import (
    workbench_project as build_project_model,
)
from utils.workbench_factories import (
    workbench_provider_snapshot as build_provider_snapshot_model,
)
from utils.workbench_factories import (
    workbench_vulnerability as build_vulnerability_model,
)

DEMO_CVE_LOG4SHELL = "CVE-2021-44228"
DEMO_CVE_XZ = "CVE-2024-3094"


@dataclass(frozen=True)
class WorkbenchApiEnv:
    """FastAPI client plus its isolated in-memory Workbench database."""

    client: TestClient
    engine: Engine
    app_models: Any
    repositories: Any


@dataclass(frozen=True)
class WorkbenchDomainGraph:
    """IDs for a minimal valid Workbench domain graph."""

    actor_id: uuid.UUID
    project_id: uuid.UUID
    asset_id: uuid.UUID
    component_id: uuid.UUID
    vulnerability_id: uuid.UUID
    finding_id: uuid.UUID
    provider_snapshot_id: uuid.UUID
    run_id: uuid.UUID


@pytest.fixture()
def workbench_api_env() -> Iterator[WorkbenchApiEnv]:
    """Yield a local Workbench API app with isolated SQLModel metadata."""
    env, cleanup = create_workbench_api_env()
    try:
        yield env
    finally:
        cleanup()


@pytest.fixture()
def secondary_workbench_api_env() -> Iterator[WorkbenchApiEnv]:
    """Yield a secondary local Workbench API environment."""
    env, cleanup = create_workbench_api_env()
    try:
        yield env
    finally:
        cleanup()


@pytest.fixture()
def workbench_local_actor_model() -> Any:
    """Return the local actor fixture used by route tests."""
    return configured_local_actor(settings)


@pytest.fixture()
def workbench_project_model(workbench_local_actor_model: Any) -> Any:
    """Return a minimal unsaved Project object."""
    return build_project_model(local_actor=workbench_local_actor_model)


@pytest.fixture()
def workbench_asset_model(workbench_project_model: Any) -> Any:
    """Return a minimal unsaved Asset object."""
    return build_asset_model(project=workbench_project_model)


@pytest.fixture()
def workbench_component_model() -> Any:
    """Return a minimal unsaved Component object."""
    return build_component_model()


@pytest.fixture()
def workbench_vulnerability_model() -> Any:
    """Return a minimal unsaved Vulnerability object."""
    return build_vulnerability_model(cve_id=DEMO_CVE_LOG4SHELL)


@pytest.fixture()
def workbench_finding_model(
    workbench_project_model: Any,
    workbench_asset_model: Any,
    workbench_component_model: Any,
    workbench_vulnerability_model: Any,
) -> Any:
    """Return a minimal unsaved Finding object."""
    return build_finding_model(
        project=workbench_project_model,
        asset=workbench_asset_model,
        component=workbench_component_model,
        vulnerability=workbench_vulnerability_model,
    )


@pytest.fixture()
def workbench_provider_snapshot_model() -> Any:
    """Return a minimal unsaved ProviderSnapshot object."""
    return build_provider_snapshot_model()


@pytest.fixture()
def workbench_analysis_run_model(
    workbench_project_model: Any,
    workbench_provider_snapshot_model: Any,
) -> Any:
    """Return a minimal unsaved AnalysisRun object."""
    return build_analysis_run_model(
        project=workbench_project_model,
        provider_snapshot=workbench_provider_snapshot_model,
    )


def create_workbench_api_env() -> tuple[WorkbenchApiEnv, Callable[[], None]]:
    """Create a TestClient wired to a disposable in-memory SQLModel database."""
    from app.api import deps

    previous_settings = getattr(app.state, "workbench_settings", settings)
    app.dependency_overrides.clear()
    app.state.rate_limiter = InMemoryRateLimiter()
    app.state.workbench_settings = settings
    app_models = importlib.import_module("app.models")
    app_models.import_table_models()
    repositories = importlib.import_module("app.repositories")
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)
    stamp_test_alembic_head(engine)

    def override_get_db() -> Generator[Session, None, None]:
        with Session(engine) as session:
            yield session

    app.dependency_overrides[deps.get_db] = override_get_db
    client = TestClient(app)

    def cleanup() -> None:
        client.close()
        app.dependency_overrides.clear()
        app.state.workbench_settings = previous_settings
        engine.dispose()

    return WorkbenchApiEnv(client, engine, app_models, repositories), cleanup


def stamp_test_alembic_head(engine: Engine) -> None:
    """Mark create_all test databases as schema-current for readiness tests."""
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL)"))
        connection.execute(
            text("INSERT INTO alembic_version (version_num) VALUES (:version_num)"),
            {"version_num": ALEMBIC_HEAD},
        )


def make_local_actor(
    app_models: Any,
    *,
    actor_id: uuid.UUID | None = None,
    email: str = "owner@example.test",
) -> Any:
    """Build a minimal local actor fixture."""
    _ = app_models
    return LocalWorkbenchActor(
        id=actor_id or uuid.uuid5(uuid.NAMESPACE_URL, email.lower()),
        email=email,
    )


def create_local_actor(
    session: Session,
    app_models: Any,
    *,
    email: str = "owner@example.test",
) -> Any:
    """Return a local actor fixture; projects no longer have user FKs."""
    _ = session
    return make_local_actor(app_models, email=email)


def create_project(
    session: Session,
    app_models: Any,
    repositories: Any,
    *,
    name: str = "Workbench Fixture Project",
    description: str | None = None,
) -> Any:
    """Persist a minimal valid Project."""
    _ = app_models
    return repositories.ProjectRepository(session).create_project(
        app_models.ProjectCreate(name=name, description=description)
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
        result_ref_json={"parsed": 2, "findings": 2},
    )


def seed_domain_graph(
    engine: Engine,
    app_models: Any,
    repositories: Any,
    *,
    actor_email: str = "fixture-actor@example.test",
) -> WorkbenchDomainGraph:
    """Seed one valid Project -> Asset/Component/Vulnerability/Finding/Run graph."""
    with Session(engine) as session:
        actor = create_local_actor(session, app_models, email=actor_email)
        project = create_project(
            session,
            app_models,
            repositories,
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
            actor_id=actor.id,
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
    with_decision_evidence: bool = False,
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
        if with_decision_evidence:
            from utils.workbench_evidence_seed import (  # noqa: PLC0415
                _seed_analysis_evidence,
                _seed_finding_evidence,
            )

            snapshot = create_provider_snapshot(
                session,
                repositories,
                content_hash="sha256:github-issue-preview-snapshot",
            )
            run = create_analysis_run(
                session,
                app_models,
                repositories,
                project_id=project_id,
                provider_snapshot_id=snapshot.id,
                filename="github-issue-preview-cves.txt",
            )
            evidence_repo = repositories.EvidenceRepository(session)
            analysis_evidence = evidence_repo.prepare_analysis_evidence_record(
                project_id=project_id,
                analysis_run_id=run.id,
                provider_snapshot_id=snapshot.id,
            )
            evidence_items = [
                _seed_finding_evidence(
                    finding=first_finding,
                    analysis_run_id=run.id,
                    project_id=project_id,
                    asset_key=asset.asset_key,
                    asset_name=asset.name or asset.asset_key,
                    component_name=component.name,
                    component_version=component.version or "",
                    priority=app_models.FindingPriority.CRITICAL,
                    priority_rank=1,
                    risk_score=98.6,
                    operational_rank=1,
                    epss=0.9442,
                    cvss=10.0,
                    in_kev=True,
                    rationale="EPSS and KEV make this urgent.",
                    action="Upgrade log4j-core.",
                    confidence="high",
                    flags=[],
                ),
                _seed_finding_evidence(
                    finding=second_finding,
                    analysis_run_id=run.id,
                    project_id=project_id,
                    asset_key=asset.asset_key,
                    asset_name=asset.name or asset.asset_key,
                    component_name=component.name,
                    component_version=component.version or "",
                    priority=app_models.FindingPriority.HIGH,
                    priority_rank=2,
                    risk_score=72.4,
                    operational_rank=2,
                    epss=0.31,
                    cvss=7.5,
                    in_kev=False,
                    rationale="Provider evidence indicates high remediation priority.",
                    action="Review and patch affected package.",
                    confidence="medium",
                    flags=[],
                ),
            ]
            evidence_repo.replace_finding_decision_evidence(
                analysis_evidence_id=analysis_evidence.id,
                project_id=project_id,
                analysis_run_id=run.id,
                evidence_items=evidence_items,
            )
            evidence_repo.upsert_analysis_evidence(
                project_id=project_id,
                analysis_run_id=run.id,
                provider_snapshot_id=snapshot.id,
                evidence=_seed_analysis_evidence(
                    project_id=project_id,
                    run=run,
                    provider_snapshot_id=snapshot.id,
                    provider_snapshot_hash=snapshot.content_hash,
                    finding_count=2,
                    counts_by_priority={"Critical": 1, "High": 1},
                    locked_provider_data=True,
                    findings=evidence_items,
                ),
            )
        session.commit()
        return {"finding_ids": finding_ids}


def seed_secondary_project_graph(
    engine: Engine,
    app_models: Any,
    repositories: Any,
) -> dict[str, uuid.UUID]:
    """Seed another local project graph for cross-project tests."""
    with Session(engine) as session:
        create_local_actor(
            session,
            app_models,
            email=f"{uuid.uuid4()}@example.test",
        )
        project = create_project(
            session,
            app_models,
            repositories,
            name="Secondary Project",
        )
        asset = create_asset(
            session,
            app_models,
            repositories,
            project_id=project.id,
            asset_key="secondary_project-api",
            name="Secondary API",
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
        filename="secondary_project-cves.txt",
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


def local_api_headers(client: TestClient) -> dict[str, str]:
    """Return headers for local single-user API calls."""
    return {}


def create_project_via_api(
    client: TestClient,
    headers: dict[str, str],
    *,
    name: str = "Workbench API Contract",
) -> dict[str, Any]:
    """Create a project through the API for route-level tests."""
    response = client.post(
        "/api/v1/projects/",
        headers=headers,
        json={"name": name, "description": None},
    )
    assert response.status_code == 200
    return response.json()

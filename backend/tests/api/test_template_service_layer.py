from __future__ import annotations

import importlib
import inspect
import uuid
from collections.abc import Iterator
from typing import Any

import pytest
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel


@pytest.fixture()
def app_models() -> Any:
    models = importlib.import_module("app.models")
    models.import_table_models()
    return models


@pytest.fixture()
def repository_classes() -> Any:
    return importlib.import_module("app.repositories")


@pytest.fixture()
def session(app_models: Any) -> Iterator[Session]:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        yield session
    engine.dispose()


def test_project_routes_delegate_domain_persistence_to_repository() -> None:
    route_module = importlib.import_module("app.api.routes.projects")
    source = inspect.getsource(route_module)

    assert "ProjectRepository" in source
    assert "select(" not in source
    assert "func.count" not in source
    assert "session.add" not in source


def test_project_repository_scopes_visibility_and_leaves_commit_to_caller(
    app_models: Any,
    repository_classes: Any,
    session: Session,
) -> None:
    owner = _user(app_models, email="owner@example.test", is_superuser=False)
    other = _user(app_models, email="other@example.test", is_superuser=False)
    admin = _user(app_models, email="admin@example.test", is_superuser=True)
    session.add_all([owner, other, admin])

    repository = repository_classes.ProjectRepository(session)
    owned = repository.create_project(
        app_models.ProjectCreate(name="Owned", description="Visible to owner."),
        owner_id=owner.id,
    )
    session.add(
        app_models.Project(
            owner_id=other.id,
            name="Other",
            description="Hidden from owner.",
        )
    )
    session.commit()

    owner_projects, owner_count = repository.list_visible_projects(owner)
    admin_projects, admin_count = repository.list_visible_projects(admin)

    assert {project.id for project in owner_projects} == {owned.id}
    assert owner_count == 1
    assert {project.name for project in admin_projects} == {"Owned", "Other"}
    assert admin_count == 2
    assert repository.get_visible_project(owned.id, owner) is not None
    assert repository.get_visible_project(owned.id, other) is None

    rolled_back = repository.create_project(
        app_models.ProjectCreate(name="Rollback", description=None),
        owner_id=owner.id,
    )
    rolled_back_id = rolled_back.id
    session.rollback()

    assert session.get(app_models.Project, rolled_back_id) is None


def test_asset_finding_and_run_repositories_persist_domain_graph(
    app_models: Any,
    repository_classes: Any,
    session: Session,
) -> None:
    user = _user(app_models)
    session.add(user)

    project = repository_classes.ProjectRepository(session).create_project(
        app_models.ProjectCreate(name="Repository Contract", description=None),
        owner_id=user.id,
    )
    asset_repository = repository_classes.AssetRepository(session)
    finding_repository = repository_classes.FindingRepository(session)
    run_repository = repository_classes.RunRepository(session)

    asset = asset_repository.upsert_asset(
        project_id=project.id,
        asset_key="payments-api",
        name="Payments API",
        target_ref="registry.example.test/payments-api:2026.04.28",
        owner="platform",
        business_service="payments",
        environment=app_models.AssetEnvironment.PRODUCTION,
        exposure=app_models.AssetExposure.INTERNET_FACING,
        criticality=app_models.AssetCriticality.CRITICAL,
    )
    component = finding_repository.upsert_component(
        name="log4j-core",
        version="2.14.1",
        purl="pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
        ecosystem="maven",
    )
    vulnerability = finding_repository.upsert_vulnerability(
        cve_id="CVE-2021-44228",
        source_id="CVE-2021-44228",
        cvss_score=10.0,
        severity="CRITICAL",
        provider_json={"nvd": {"lastModified": "2026-04-28T10:15:00Z"}},
    )
    finding = finding_repository.create_or_update_finding(
        project_id=project.id,
        vulnerability_id=vulnerability.id,
        component_id=component.id,
        asset_id=asset.id,
        cve_id="CVE-2021-44228",
        priority=app_models.FindingPriority.CRITICAL,
        priority_rank=1,
        in_kev=True,
        explanation_json={"reason": "KEV and internet-facing production asset"},
    )
    snapshot = run_repository.get_or_create_provider_snapshot(
        content_hash="sha256:repo-contract",
        nvd_last_sync="2026-04-28T10:15:00Z",
        epss_date="2026-04-28",
        kev_catalog_version="2026-04-28",
        source_hashes_json={"nvd": "sha256:nvd"},
    )
    same_snapshot = run_repository.get_or_create_provider_snapshot(
        content_hash="sha256:repo-contract",
    )
    run = run_repository.create_analysis_run(
        project_id=project.id,
        provider_snapshot_id=snapshot.id,
        input_type="trivy-json",
        filename="trivy.json",
        status=app_models.AnalysisRunStatus.RUNNING,
    )
    occurrence = run_repository.add_finding_occurrence(
        finding_id=finding.id,
        analysis_run_id=run.id,
        source="dependency-scan",
        scanner="trivy",
        raw_reference="pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
        fix_version="2.17.1",
        evidence_json={"input_line": 42},
    )
    finished = run_repository.finish_analysis_run(
        run.id,
        status=app_models.AnalysisRunStatus.COMPLETED_WITH_ERRORS,
        summary_json={"findings": 1, "degraded_providers": ["nvd"]},
        error_json={"nvd": "cache replay used"},
    )
    session.commit()

    assert same_snapshot.id == snapshot.id
    assert occurrence.finding_id == finding.id
    assert finished.finished_at is not None
    assert finished.summary_json["findings"] == 1
    assert [item.id for item in asset_repository.list_project_assets(project.id)] == [asset.id]
    assert [item.id for item in finding_repository.list_project_findings(project.id)] == [
        finding.id
    ]
    assert [item.id for item in run_repository.list_analysis_runs(project.id)] == [run.id]


def test_user_auth_crud_surface_stays_outside_workbench_repositories() -> None:
    repositories = importlib.import_module("app.repositories")
    repository_exports = set(getattr(repositories, "__all__", ()))

    assert {
        "ProjectRepository",
        "AssetRepository",
        "FindingRepository",
        "RunRepository",
    }.issubset(repository_exports)
    assert "UserRepository" not in repository_exports
    assert "AuthRepository" not in repository_exports


def _user(
    app_models: Any,
    *,
    email: str = "owner@example.test",
    is_superuser: bool = True,
) -> Any:
    return app_models.User(
        id=uuid.uuid4(),
        email=email,
        hashed_password="not-used",
        is_active=True,
        is_superuser=is_superuser,
    )

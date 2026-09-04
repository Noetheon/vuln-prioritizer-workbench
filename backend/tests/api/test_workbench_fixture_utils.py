from __future__ import annotations

from pathlib import Path

from sqlalchemy import text
from sqlmodel import Session
from utils.workbench_env import (
    DEMO_CVE_LOG4SHELL,
    WorkbenchApiEnv,
    create_analysis_run,
    create_asset,
    create_component,
    create_finding,
    create_local_actor,
    create_project,
    create_provider_snapshot,
    create_vulnerability,
    create_workbench_api_env,
    seed_domain_graph,
)

from app.api import deps
from app.main import app


def test_vpw012_api_test_uses_each_core_model_fixture(
    workbench_local_actor_model: object,
    workbench_project_model: object,
    workbench_asset_model: object,
    workbench_component_model: object,
    workbench_vulnerability_model: object,
    workbench_finding_model: object,
    workbench_provider_snapshot_model: object,
    workbench_analysis_run_model: object,
) -> None:
    assert workbench_local_actor_model.email
    assert workbench_project_model.name == "Workbench Project 1"
    assert workbench_asset_model.project_id == workbench_project_model.id
    assert workbench_component_model.name == "log4j-core"
    assert workbench_vulnerability_model.cve_id == DEMO_CVE_LOG4SHELL
    assert workbench_finding_model.project_id == workbench_project_model.id
    assert workbench_finding_model.asset_id == workbench_asset_model.id
    assert workbench_finding_model.component_id == workbench_component_model.id
    assert workbench_finding_model.vulnerability_id == workbench_vulnerability_model.id
    assert workbench_analysis_run_model.project_id == workbench_project_model.id
    assert workbench_analysis_run_model.provider_snapshot_id == workbench_provider_snapshot_model.id


def test_vpw012_factories_create_minimal_valid_workbench_domain_objects(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    app_models = workbench_api_env.app_models
    repositories = workbench_api_env.repositories

    with Session(workbench_api_env.engine) as session:
        actor = create_local_actor(
            session,
            app_models,
            email="factory-owner@example.test",
        )
        project = create_project(
            session,
            app_models,
            repositories,
            name="Factory Project",
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
            priority=app_models.FindingPriority.CRITICAL,
            priority_rank=1,
            operational_rank=1,
        )
        snapshot = create_provider_snapshot(session, repositories)
        run = create_analysis_run(
            session,
            app_models,
            repositories,
            project_id=project.id,
            provider_snapshot_id=snapshot.id,
        )
        ids = {
            "actor": actor.id,
            "project": project.id,
            "asset_project": asset.project_id,
            "asset": asset.id,
            "component_name": component.name,
            "vulnerability_cve": vulnerability.cve_id,
            "finding_project": finding.project_id,
            "run_project": run.project_id,
            "run_snapshot": run.provider_snapshot_id,
            "snapshot": snapshot.id,
        }
        session.commit()

    assert ids["actor"]
    assert ids["asset_project"] == ids["project"]
    assert ids["asset"]
    assert ids["component_name"] == "log4j-core"
    assert ids["vulnerability_cve"] == "CVE-2021-44228"
    assert ids["finding_project"] == ids["project"]
    assert ids["run_project"] == ids["project"]
    assert ids["run_snapshot"] == ids["snapshot"]


def test_vpw012_seed_domain_graph_uses_all_core_factories(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    graph = seed_domain_graph(
        workbench_api_env.engine,
        workbench_api_env.app_models,
        workbench_api_env.repositories,
    )

    with Session(workbench_api_env.engine) as session:
        assert graph.actor_id
        assert session.get(workbench_api_env.app_models.Project, graph.project_id) is not None
        assert session.get(workbench_api_env.app_models.Asset, graph.asset_id) is not None
        assert session.get(workbench_api_env.app_models.Component, graph.component_id) is not None
        assert (
            session.get(workbench_api_env.app_models.Vulnerability, graph.vulnerability_id)
            is not None
        )
        assert session.get(workbench_api_env.app_models.Finding, graph.finding_id) is not None
        assert (
            session.get(workbench_api_env.app_models.ProviderSnapshot, graph.provider_snapshot_id)
            is not None
        )
        assert session.get(workbench_api_env.app_models.AnalysisRun, graph.run_id) is not None


def test_vpw012_workbench_api_env_cleanup_removes_db_override() -> None:
    env, cleanup = create_workbench_api_env()
    assert deps.get_db in app.dependency_overrides

    cleanup()

    assert deps.get_db not in app.dependency_overrides


def test_vpw072_workbench_api_env_can_use_file_backed_sqlite(tmp_path: Path) -> None:
    database_path = tmp_path / "file-backed-workbench.db"
    env, cleanup = create_workbench_api_env(database_path=database_path)
    try:
        assert env.engine.dialect.name == "sqlite"
        assert env.engine.url.database == str(database_path.resolve())
        assert database_path.is_file()
        assert env.client.app.state.workbench_settings.SQLALCHEMY_DATABASE_URI == (
            f"sqlite:///{database_path.resolve().as_posix()}"
        )
    finally:
        cleanup()


def test_workbench_api_env_enforces_sqlite_foreign_keys(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    with workbench_api_env.engine.connect() as connection:
        assert connection.execute(text("PRAGMA foreign_keys")).scalar_one() == 1

from __future__ import annotations

from sqlmodel import Session
from utils.template_workbench import (
    CONFIGURED_USER_ID,
    DEMO_CVE_LOG4SHELL,
    TemplateApiEnv,
    create_analysis_run,
    create_asset,
    create_component,
    create_finding,
    create_project,
    create_provider_snapshot,
    create_user,
    create_vulnerability,
    seed_domain_graph,
)

from app.api import deps
from app.main import app


def test_vpw012_api_test_uses_each_core_model_fixture(
    template_user_model: object,
    template_project_model: object,
    template_asset_model: object,
    template_component_model: object,
    template_vulnerability_model: object,
    template_finding_model: object,
    template_provider_snapshot_model: object,
    template_analysis_run_model: object,
) -> None:
    assert template_project_model.owner_id == template_user_model.id
    assert template_asset_model.project_id == template_project_model.id
    assert template_component_model.name == "log4j-core"
    assert template_vulnerability_model.cve_id == DEMO_CVE_LOG4SHELL
    assert template_finding_model.project_id == template_project_model.id
    assert template_finding_model.asset_id == template_asset_model.id
    assert template_finding_model.component_id == template_component_model.id
    assert template_finding_model.vulnerability_id == template_vulnerability_model.id
    assert template_analysis_run_model.project_id == template_project_model.id
    assert template_analysis_run_model.provider_snapshot_id == template_provider_snapshot_model.id


def test_vpw012_factories_create_minimal_valid_workbench_domain_objects(
    template_api_env: TemplateApiEnv,
) -> None:
    app_models = template_api_env.app_models
    repositories = template_api_env.repositories

    with Session(template_api_env.engine) as session:
        user = create_user(
            session,
            app_models,
            email="factory-owner@example.test",
            is_superuser=False,
        )
        project = create_project(
            session,
            app_models,
            repositories,
            owner_id=user.id,
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
            "user": user.id,
            "project_owner": project.owner_id,
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

    assert ids["user"]
    assert ids["project_owner"] == ids["user"]
    assert ids["asset_project"] == ids["project"]
    assert ids["asset"]
    assert ids["component_name"] == "log4j-core"
    assert ids["vulnerability_cve"] == "CVE-2021-44228"
    assert ids["finding_project"] == ids["project"]
    assert ids["run_project"] == ids["project"]
    assert ids["run_snapshot"] == ids["snapshot"]


def test_vpw012_seed_domain_graph_uses_all_core_factories(
    template_api_env: TemplateApiEnv,
) -> None:
    graph = seed_domain_graph(
        template_api_env.engine,
        template_api_env.app_models,
        template_api_env.repositories,
    )

    with Session(template_api_env.engine) as session:
        assert session.get(template_api_env.app_models.User, graph.user_id) is not None
        assert session.get(template_api_env.app_models.Project, graph.project_id) is not None
        assert session.get(template_api_env.app_models.Asset, graph.asset_id) is not None
        assert session.get(template_api_env.app_models.Component, graph.component_id) is not None
        assert (
            session.get(template_api_env.app_models.Vulnerability, graph.vulnerability_id)
            is not None
        )
        assert session.get(template_api_env.app_models.Finding, graph.finding_id) is not None
        assert (
            session.get(template_api_env.app_models.ProviderSnapshot, graph.provider_snapshot_id)
            is not None
        )
        assert session.get(template_api_env.app_models.AnalysisRun, graph.run_id) is not None


def test_vpw012_template_api_env_cleanup_removes_db_override() -> None:
    from utils.template_workbench import create_template_api_env

    env, cleanup = create_template_api_env()
    assert deps.get_db in app.dependency_overrides

    with Session(env.engine) as session:
        user = session.get(env.app_models.User, CONFIGURED_USER_ID)
        assert user is not None
        assert user.hashed_password == "configured-superuser-password-placeholder"

    cleanup()

    assert deps.get_db not in app.dependency_overrides

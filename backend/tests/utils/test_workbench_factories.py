from __future__ import annotations

from utils.workbench_factories import (
    workbench_analysis_run,
    workbench_asset,
    workbench_component,
    workbench_finding,
    workbench_local_actor,
    workbench_project,
    workbench_provider_snapshot,
    workbench_test_graph,
    workbench_vulnerability,
)


def test_workbench_test_graph_builds_coherent_unsaved_domain_objects() -> None:
    graph = workbench_test_graph()

    assert graph.actor.email == "owner-1@example.test"
    assert graph.asset.project_id == graph.project.id
    assert graph.finding.project_id == graph.project.id
    assert graph.finding.asset_id == graph.asset.id
    assert graph.finding.component_id == graph.component.id
    assert graph.finding.vulnerability_id == graph.vulnerability.id
    assert graph.finding.cve_id == graph.vulnerability.cve_id
    assert graph.analysis_run.project_id == graph.project.id
    assert graph.analysis_run.provider_snapshot_id == graph.provider_snapshot.id


def test_workbench_factories_accept_overrides_without_mutating_later_instances() -> None:
    actor = workbench_local_actor(email="security@example.test")
    project = workbench_project(local_actor=actor, name="Security Workbench")
    asset = workbench_asset(project=project, asset_key="edge-api")
    component = workbench_component(name="openssl", version="3.0.0")
    vulnerability = workbench_vulnerability(cve_id="CVE-2026-9999", cvss_score=9.1)
    finding = workbench_finding(
        project=project,
        asset=asset,
        component=component,
        vulnerability=vulnerability,
        priority_rank=2,
    )
    snapshot = workbench_provider_snapshot(content_hash="sha256:custom")
    run = workbench_analysis_run(project=project, provider_snapshot=snapshot, filename="scan.json")

    assert actor.email == "security@example.test"
    assert project.name == "Security Workbench"
    assert asset.asset_key == "edge-api"
    assert component.name == "openssl"
    assert vulnerability.cve_id == "CVE-2026-9999"
    assert finding.priority_rank == 2
    assert snapshot.content_hash == "sha256:custom"
    assert run.filename == "scan.json"
    assert workbench_provider_snapshot().source_hashes_json["kev"] == "sha256:kev-feed-1"


def test_workbench_factories_support_explicit_foreign_key_ids() -> None:
    import uuid

    project_id = uuid.uuid4()
    asset_id = uuid.uuid4()
    component_id = uuid.uuid4()
    vulnerability_id = uuid.uuid4()
    provider_snapshot_id = uuid.uuid4()

    project = workbench_project()
    asset = workbench_asset(project_id=project_id)
    finding = workbench_finding(
        project_id=project_id,
        asset_id=asset_id,
        component_id=component_id,
        vulnerability_id=vulnerability_id,
    )
    run = workbench_analysis_run(
        project_id=project_id,
        provider_snapshot_id=provider_snapshot_id,
    )

    assert project.name == "Workbench Project 1"
    assert asset.project_id == project_id
    assert finding.project_id == project_id
    assert finding.asset_id == asset_id
    assert finding.component_id == component_id
    assert finding.vulnerability_id == vulnerability_id
    assert run.project_id == project_id
    assert run.provider_snapshot_id == provider_snapshot_id

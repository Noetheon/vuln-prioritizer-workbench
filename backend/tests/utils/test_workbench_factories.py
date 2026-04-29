from __future__ import annotations

import uuid

from utils.workbench_factories import (
    template_analysis_run,
    template_asset,
    template_component,
    template_finding,
    template_project,
    template_provider_snapshot,
    template_user,
    template_vulnerability,
    template_workbench_graph,
)


def test_template_workbench_graph_builds_coherent_unsaved_domain_objects() -> None:
    graph = template_workbench_graph()

    assert graph.project.owner_id == graph.user.id
    assert graph.asset.project_id == graph.project.id
    assert graph.finding.project_id == graph.project.id
    assert graph.finding.asset_id == graph.asset.id
    assert graph.finding.component_id == graph.component.id
    assert graph.finding.vulnerability_id == graph.vulnerability.id
    assert graph.finding.cve_id == graph.vulnerability.cve_id
    assert graph.analysis_run.project_id == graph.project.id
    assert graph.analysis_run.provider_snapshot_id == graph.provider_snapshot.id


def test_template_factories_accept_overrides_without_mutating_later_instances() -> None:
    user = template_user(email="security@example.test")
    project = template_project(owner=user, name="Security Workbench")
    asset = template_asset(project=project, asset_key="edge-api")
    component = template_component(name="openssl", version="3.0.0")
    vulnerability = template_vulnerability(cve_id="CVE-2026-9999", cvss_score=9.1)
    finding = template_finding(
        project=project,
        asset=asset,
        component=component,
        vulnerability=vulnerability,
        priority_rank=2,
    )
    snapshot = template_provider_snapshot(content_hash="sha256:custom")
    run = template_analysis_run(project=project, provider_snapshot=snapshot, filename="scan.json")

    assert user.email == "security@example.test"
    assert project.name == "Security Workbench"
    assert asset.asset_key == "edge-api"
    assert component.name == "openssl"
    assert vulnerability.cve_id == "CVE-2026-9999"
    assert finding.priority_rank == 2
    assert snapshot.content_hash == "sha256:custom"
    assert run.filename == "scan.json"
    assert template_provider_snapshot().source_hashes_json["kev"] == "sha256:kev-feed-1"


def test_template_factories_support_explicit_foreign_key_ids() -> None:
    owner_id = uuid.uuid4()
    project_id = uuid.uuid4()
    asset_id = uuid.uuid4()
    component_id = uuid.uuid4()
    vulnerability_id = uuid.uuid4()
    provider_snapshot_id = uuid.uuid4()

    project = template_project(owner_id=owner_id)
    asset = template_asset(project_id=project_id)
    finding = template_finding(
        project_id=project_id,
        asset_id=asset_id,
        component_id=component_id,
        vulnerability_id=vulnerability_id,
    )
    run = template_analysis_run(
        project_id=project_id,
        provider_snapshot_id=provider_snapshot_id,
    )

    assert project.owner_id == owner_id
    assert asset.project_id == project_id
    assert finding.project_id == project_id
    assert finding.asset_id == asset_id
    assert finding.component_id == component_id
    assert finding.vulnerability_id == vulnerability_id
    assert run.project_id == project_id
    assert run.provider_snapshot_id == provider_snapshot_id

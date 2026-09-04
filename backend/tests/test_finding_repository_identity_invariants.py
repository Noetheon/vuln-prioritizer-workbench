from __future__ import annotations

from typing import Any, Literal

import pytest
from sqlmodel import Session, select
from utils.workbench_env import (
    WorkbenchApiEnv,
    create_asset,
    create_component,
    create_project,
    create_vulnerability,
)

from app.repositories.findings import (
    ComponentIdentityInvariantError,
    FindingIdentityInvariantError,
    normalize_component_persistence_identity,
)

IdentityField = Literal["vulnerability_id", "component_id", "asset_id"]
ReuseMode = Literal["dedup_lookup", "prefetched_dedup"]


def _seed_finding_identity_graph(
    session: Session,
    workbench_api_env: WorkbenchApiEnv,
) -> dict[str, Any]:
    repositories = workbench_api_env.repositories
    app_models = workbench_api_env.app_models
    project = create_project(session, app_models, repositories, name="Finding Identity")
    primary_asset = create_asset(
        session,
        app_models,
        repositories,
        project_id=project.id,
        asset_key="primary-asset",
        name="Primary Asset",
    )
    other_asset = create_asset(
        session,
        app_models,
        repositories,
        project_id=project.id,
        asset_key="other-asset",
        name="Other Asset",
    )
    primary_component = create_component(
        session,
        repositories,
        name="primary-component",
        version="1.0.0",
        purl="pkg:generic/primary-component@1.0.0",
    )
    other_component = create_component(
        session,
        repositories,
        name="other-component",
        version="2.0.0",
        purl="pkg:generic/other-component@2.0.0",
    )
    primary_vulnerability = create_vulnerability(
        session,
        repositories,
        cve_id="CVE-2026-1001",
    )
    other_vulnerability = create_vulnerability(
        session,
        repositories,
        cve_id="CVE-2026-1002",
    )
    finding_repository = repositories.FindingRepository(session)
    finding = finding_repository.create_or_update_finding(
        project_id=project.id,
        vulnerability_id=primary_vulnerability.id,
        cve_id=primary_vulnerability.cve_id,
        dedup_key="finding-scope-v2:stable-identity",
        component_id=primary_component.id,
        asset_id=primary_asset.id,
        status=app_models.FindingStatus.IN_REVIEW,
    )
    session.commit()
    session.refresh(finding)
    return {
        "finding": finding,
        "other_asset": other_asset,
        "other_component": other_component,
        "other_vulnerability": other_vulnerability,
        "project": project,
    }


@pytest.mark.parametrize("reuse_mode", ["dedup_lookup", "prefetched_dedup"])
@pytest.mark.parametrize(
    "identity_field",
    ["vulnerability_id", "component_id", "asset_id"],
)
def test_dedup_reuse_rejects_conflicting_finding_identity_before_mutation(
    workbench_api_env: WorkbenchApiEnv,
    identity_field: IdentityField,
    reuse_mode: ReuseMode,
) -> None:
    with Session(workbench_api_env.engine) as session:
        graph = _seed_finding_identity_graph(session, workbench_api_env)
        finding = graph["finding"]
        repository = workbench_api_env.repositories.FindingRepository(session)
        original_identity = (
            finding.vulnerability_id,
            finding.component_id,
            finding.asset_id,
        )
        original_last_seen_at = finding.last_seen_at
        requested_identity = {
            "vulnerability_id": finding.vulnerability_id,
            "component_id": finding.component_id,
            "asset_id": finding.asset_id,
        }
        requested_identity[identity_field] = getattr(graph[f"other_{identity_field[:-3]}"], "id")
        prefetched_finding = None
        if reuse_mode == "prefetched_dedup":
            prefetched_finding = repository.get_project_finding_by_dedup_key(
                project_id=graph["project"].id,
                dedup_key=finding.dedup_key,
            )
            assert prefetched_finding is not None

        with pytest.raises(
            FindingIdentityInvariantError,
            match=rf"dedup_key.*{identity_field}",
        ):
            repository.create_or_update_finding(
                project_id=graph["project"].id,
                vulnerability_id=requested_identity["vulnerability_id"],
                cve_id=finding.cve_id,
                dedup_key=finding.dedup_key,
                component_id=requested_identity["component_id"],
                asset_id=requested_identity["asset_id"],
                status=workbench_api_env.app_models.FindingStatus.OPEN,
                existing_finding=prefetched_finding,
                lookup_existing=reuse_mode == "dedup_lookup",
            )

        persisted = repository.get_finding(finding.id)
        assert persisted is not None
        assert (
            persisted.vulnerability_id,
            persisted.component_id,
            persisted.asset_id,
        ) == original_identity
        assert persisted.status == workbench_api_env.app_models.FindingStatus.IN_REVIEW
        assert persisted.last_seen_at == original_last_seen_at
        assert repository.count_project_findings(graph["project"].id) == 1


def test_dedup_reuse_accepts_the_exact_finding_identity(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    with Session(workbench_api_env.engine) as session:
        graph = _seed_finding_identity_graph(session, workbench_api_env)
        finding = graph["finding"]
        repository = workbench_api_env.repositories.FindingRepository(session)

        reused = repository.create_or_update_finding(
            project_id=graph["project"].id,
            vulnerability_id=finding.vulnerability_id,
            cve_id=finding.cve_id,
            dedup_key=finding.dedup_key,
            component_id=finding.component_id,
            asset_id=finding.asset_id,
            status=workbench_api_env.app_models.FindingStatus.OPEN,
        )

        assert reused.id == finding.id
        assert reused.status == workbench_api_env.app_models.FindingStatus.IN_REVIEW
        assert repository.count_project_findings(graph["project"].id) == 1


def test_explicit_asset_context_rebind_changes_only_the_mutable_asset_link(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    with Session(workbench_api_env.engine) as session:
        graph = _seed_finding_identity_graph(session, workbench_api_env)
        finding = graph["finding"]
        repository = workbench_api_env.repositories.FindingRepository(session)

        rebound = repository.create_or_update_finding(
            project_id=graph["project"].id,
            vulnerability_id=finding.vulnerability_id,
            cve_id=finding.cve_id,
            dedup_key=finding.dedup_key,
            component_id=finding.component_id,
            asset_id=graph["other_asset"].id,
            status=workbench_api_env.app_models.FindingStatus.OPEN,
            allow_asset_rebind=True,
        )

        assert rebound.id == finding.id
        assert rebound.asset_id == graph["other_asset"].id
        assert rebound.vulnerability_id == finding.vulnerability_id
        assert rebound.component_id == finding.component_id
        assert repository.count_project_findings(graph["project"].id) == 1


@pytest.mark.parametrize("identity_field", ["project_id", "cve_id"])
def test_prefetched_reuse_rejects_conflicting_project_or_cve_identity(
    workbench_api_env: WorkbenchApiEnv,
    identity_field: Literal["project_id", "cve_id"],
) -> None:
    with Session(workbench_api_env.engine) as session:
        graph = _seed_finding_identity_graph(session, workbench_api_env)
        finding = graph["finding"]
        repository = workbench_api_env.repositories.FindingRepository(session)
        requested_project_id = graph["project"].id
        requested_cve_id = finding.cve_id
        if identity_field == "project_id":
            requested_project_id = create_project(
                session,
                workbench_api_env.app_models,
                workbench_api_env.repositories,
                name="Other Project",
            ).id
        else:
            requested_cve_id = graph["other_vulnerability"].cve_id

        with pytest.raises(
            FindingIdentityInvariantError,
            match=rf"dedup_key.*{identity_field}",
        ):
            repository.create_or_update_finding(
                project_id=requested_project_id,
                vulnerability_id=finding.vulnerability_id,
                cve_id=requested_cve_id,
                dedup_key=finding.dedup_key,
                component_id=finding.component_id,
                asset_id=finding.asset_id,
                status=workbench_api_env.app_models.FindingStatus.OPEN,
                existing_finding=finding,
                lookup_existing=False,
            )

        persisted = repository.get_finding(finding.id)
        assert persisted is not None
        assert persisted.project_id == graph["project"].id
        assert persisted.cve_id == finding.cve_id
        assert persisted.status == workbench_api_env.app_models.FindingStatus.IN_REVIEW


def test_component_repository_preserves_generic_purl_case_semantics(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    with Session(workbench_api_env.engine) as session:
        repository = workbench_api_env.repositories.FindingRepository(session)
        upper = repository.upsert_component(
            name="Foo",
            version="ReleaseA",
            purl="pkg:generic/Foo@ReleaseA",
        )
        lower = repository.upsert_component(
            name="foo",
            version="releasea",
            purl="pkg:generic/foo@releasea",
        )

        assert upper.id != lower.id
        assert upper.purl == "pkg:generic/Foo@ReleaseA"
        assert lower.purl == "pkg:generic/foo@releasea"


def test_component_repository_allows_distinct_fallback_package_types(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    with Session(workbench_api_env.engine) as session:
        repository = workbench_api_env.repositories.FindingRepository(session)
        deb = repository.upsert_component(
            name="widget",
            version="1.0",
            ecosystem="generic",
            package_type="deb",
        )
        rpm = repository.upsert_component(
            name="widget",
            version="1.0",
            ecosystem="generic",
            package_type="rpm",
        )

        assert deb.id != rpm.id
        assert deb.identity_key != rpm.identity_key
        assert len(session.exec(select(workbench_api_env.app_models.Component)).all()) == 2


def test_component_repository_keeps_versions_for_versionless_purls_distinct(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    with Session(workbench_api_env.engine) as session:
        repository = workbench_api_env.repositories.FindingRepository(session)
        version_4 = repository.upsert_component(
            name="django",
            version="4.2",
            purl="pkg:pypi/django",
        )
        version_5 = repository.upsert_component(
            name="django",
            version="5.0",
            purl="pkg:pypi/django",
        )

        assert version_4.id != version_5.id
        assert version_4.identity_key != version_5.identity_key
        assert len(session.exec(select(workbench_api_env.app_models.Component)).all()) == 2


def test_component_repository_uses_versioned_purl_as_authoritative_version(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    with Session(workbench_api_env.engine) as session:
        repository = workbench_api_env.repositories.FindingRepository(session)
        upstream_version = repository.upsert_component(
            name="xz",
            version="5.6.0",
            purl="pkg:apk/alpine/xz@5.6.0-r0",
        )
        package_version = repository.upsert_component(
            name="xz",
            version="5.6.0-r0",
            purl="pkg:apk/alpine/xz@5.6.0-r0",
        )

        assert upstream_version.id == package_version.id
        assert package_version.version == "5.6.0-r0"
        assert len(session.exec(select(workbench_api_env.app_models.Component)).all()) == 1


def test_component_repository_rejects_purl_identity_hash_mismatch(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    with Session(workbench_api_env.engine) as session:
        identity = normalize_component_persistence_identity(
            name="django",
            version="4.2.0",
            purl="pkg:pypi/django@4.2.0",
        )
        corrupted = workbench_api_env.app_models.Component(
            name="Django legacy A",
            purl="PKG:PYPI/Django@4.2.0",
            identity_key=identity.storage_key,
            identity_material='component-identity-v1:["purl","pkg:pypi/other@1"]',
        )
        session.add(corrupted)
        session.flush()
        repository = workbench_api_env.repositories.FindingRepository(session)

        with pytest.raises(
            ComponentIdentityInvariantError,
            match="hash resolved to contradictory canonical material",
        ):
            repository.upsert_component(
                name="django",
                version="4.2.0",
                purl="pkg:pypi/django@4.2.0",
            )

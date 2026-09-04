"""Regression tests for collision-free observation, scope, and persistence identities."""

from __future__ import annotations

import uuid
from collections.abc import Sequence

import pytest
from sqlmodel import Session, select
from utils.workbench_env import (
    WorkbenchApiEnv,
    create_project,
    create_project_via_api,
    local_api_headers,
)

from app.decision_core.identity import (
    component_scope_identity,
    finding_scope_identity,
    finding_scope_key,
    observation_identity,
    observation_key,
)
from app.domain.asset_identity import (
    ASSET_IDENTITY_KEY_PREFIX,
    ASSET_IDENTITY_NORMALIZATION_VERSION,
)
from app.domain.component_identity import component_storage_key
from app.domain.engine.models import AnalysisContext, PrioritizedFinding
from app.importers.contracts import NormalizedOccurrence
from app.repositories.assets import AssetIdentityInvariantError
from app.repositories.findings import (
    ComponentIdentityInvariantError,
    normalize_component_persistence_identity,
)
from app.services import WorkbenchAnalysisResult
from app.services.import_execution_dedup import (
    _asset_persistence_key,
    _asset_storage_keys_by_identity,
    _preferred_asset_storage_key,
)
from app.services.import_execution_persistence import _persist_workbench_occurrences
from app.services.import_execution_persistence_bulk import (
    _persist_workbench_occurrences_bulk_insert,
)

_PROJECT_ID = uuid.UUID("3f976fd6-f069-48fc-91d8-1772f7208f7c")
_CVE_ID = "CVE-2026-4242"


def _decision(cve_id: str) -> PrioritizedFinding:
    return PrioritizedFinding(
        cve_id=cve_id,
        priority_label="High",
        priority_rank=2,
        priority_state="Open",
        operational_score=87,
        cvss_severity=None,
        rationale="Identity collision regression.",
        recommended_action="Review the affected scope.",
    )


def _analysis_result(
    occurrences: Sequence[NormalizedOccurrence],
) -> WorkbenchAnalysisResult:
    return WorkbenchAnalysisResult(
        findings_by_cve={
            occurrence.cve_id: _decision(occurrence.cve_id) for occurrence in occurrences
        },
        context=AnalysisContext(
            input_path="identity-collision.csv",
            output_format="json",
            generated_at="2026-09-04T00:00:00Z",
        ),
        provider_snapshot_id=None,
        provider_snapshot_hash=None,
        provider_snapshot_file=None,
        locked_provider_data=False,
    )


@pytest.mark.parametrize(
    ("literal_scope_kwargs", "different_field"),
    [
        ({"component_name": "__none__"}, "component_identity"),
        ({"target_ref": "__none__"}, "target_ref"),
    ],
)
def test_missing_finding_scope_values_do_not_alias_literal_none_sentinel(
    literal_scope_kwargs: dict[str, str],
    different_field: str,
) -> None:
    missing = finding_scope_identity(project_id=_PROJECT_ID, cve_id=_CVE_ID)
    literal = finding_scope_identity(
        project_id=_PROJECT_ID,
        cve_id=_CVE_ID,
        **literal_scope_kwargs,
    )

    assert getattr(missing, different_field) is None
    assert getattr(literal, different_field) is not None
    assert finding_scope_key(missing) != finding_scope_key(literal)


@pytest.mark.parametrize("optional_field", ["source_record_id", "source_id"])
def test_missing_observation_value_does_not_alias_literal_none_sentinel(
    optional_field: str,
) -> None:
    missing = observation_identity(
        source="scanner",
        source_record_id=None,
        source_id=None,
        cve_id=_CVE_ID,
    )
    literal_kwargs = {
        "source": "scanner",
        "source_record_id": None,
        "source_id": None,
        "cve_id": _CVE_ID,
    }
    literal_kwargs[optional_field] = "__none__"
    literal = observation_identity(**literal_kwargs)

    assert getattr(missing, optional_field) is None
    assert getattr(literal, optional_field) == "__none__"
    assert observation_key(missing) != observation_key(literal)


def test_v2_scope_and_asset_identities_share_frozen_nfc_normalization() -> None:
    composed_target = "Caf\u00e9"
    decomposed_target = "Cafe\u0301"
    composed_scope = finding_scope_identity(
        project_id=_PROJECT_ID,
        cve_id=_CVE_ID,
        target_kind="host",
        target_ref=composed_target,
    )
    decomposed_scope = finding_scope_identity(
        project_id=_PROJECT_ID,
        cve_id=_CVE_ID,
        target_kind="host",
        target_ref=decomposed_target,
    )
    composed_asset_key = _asset_persistence_key(
        NormalizedOccurrence(
            cve_id=_CVE_ID,
            target_kind="host",
            target_ref=composed_target,
        )
    )
    decomposed_asset_key = _asset_persistence_key(
        NormalizedOccurrence(
            cve_id=_CVE_ID,
            target_kind="host",
            target_ref=decomposed_target,
        )
    )

    assert ASSET_IDENTITY_NORMALIZATION_VERSION == "nfc-v1"
    assert composed_scope == decomposed_scope
    assert composed_scope.target_ref == composed_target
    assert finding_scope_key(composed_scope) == (
        "vpw-finding-scope-v2:eae59f9aadfd5637cf350a6f6e31dec6d9f9f35d1c89db7c6d667cd4d552b78f"
    )
    assert (
        composed_asset_key
        == decomposed_asset_key
        == (
            "vpw-asset-identity-v2:742a8cb39363b1a0879b6f708ca9a6421d7238d2d18349b44f69dfe743af71f5"
        )
    )

    spaced_kind = NormalizedOccurrence(
        cve_id=_CVE_ID,
        target_kind="H\u00d6ST   Group",
        target_ref=composed_target,
    )
    decomposed_kind = NormalizedOccurrence(
        cve_id=_CVE_ID,
        target_kind="HO\u0308ST Group",
        target_ref=decomposed_target,
    )
    assert spaced_kind.target_kind == decomposed_kind.target_kind == "h\u00f6st group"
    assert _asset_persistence_key(spaced_kind) == _asset_persistence_key(decomposed_kind)


def test_observation_ids_preserve_canonically_distinct_source_bytes() -> None:
    composed_id = "Caf\u00e9"
    decomposed_id = "Cafe\u0301"
    composed = observation_identity(
        source="scanner",
        source_record_id=composed_id,
        cve_id=_CVE_ID,
    )
    decomposed = observation_identity(
        source="scanner",
        source_record_id=decomposed_id,
        cve_id=_CVE_ID,
    )

    assert composed.source_record_id == composed_id
    assert decomposed.source_record_id == decomposed_id
    assert observation_key(composed) != observation_key(decomposed)


def test_import_collapses_nfc_and_nfd_target_and_asset_scope_but_keeps_observations(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    composed = NormalizedOccurrence(
        cve_id=_CVE_ID,
        target_kind="host",
        target_ref="Caf\u00e9-target",
        asset_id="Caf\u00e9-asset",
        source="unicode-regression",
        raw_evidence={"source_record_id": "Caf\u00e9-record"},
    )
    decomposed = NormalizedOccurrence(
        cve_id=_CVE_ID,
        target_kind="host",
        target_ref="Cafe\u0301-target",
        asset_id="Cafe\u0301-asset",
        source="unicode-regression",
        raw_evidence={"source_record_id": "Cafe\u0301-record"},
    )

    assert composed.target_ref == decomposed.target_ref == "Caf\u00e9-target"
    assert composed.asset_id == decomposed.asset_id == "Caf\u00e9-asset"

    with Session(workbench_api_env.engine) as session:
        project = create_project(
            session,
            workbench_api_env.app_models,
            workbench_api_env.repositories,
            name="Unicode scope identity regression",
        )
        run = workbench_api_env.repositories.RunRepository(session).create_analysis_run(
            project_id=project.id,
            input_type="generic-occurrence-csv",
            filename="unicode-equivalence.csv",
        )

        summary = _persist_workbench_occurrences(
            session=session,
            project_id=project.id,
            run_id=run.id,
            occurrences=[composed, decomposed],
            analysis_result=_analysis_result([composed, decomposed]),
        )
        session.flush()

        findings = session.exec(
            select(workbench_api_env.app_models.Finding).where(
                workbench_api_env.app_models.Finding.project_id == project.id
            )
        ).all()
        assets = session.exec(
            select(workbench_api_env.app_models.Asset).where(
                workbench_api_env.app_models.Asset.project_id == project.id
            )
        ).all()
        occurrences = session.exec(
            select(workbench_api_env.app_models.FindingOccurrence).where(
                workbench_api_env.app_models.FindingOccurrence.analysis_run_id == run.id
            )
        ).all()

    assert summary["finding_count"] == 1
    assert len(findings) == len(assets) == 1
    assert len(occurrences) == 2
    assert findings[0].asset_id == assets[0].id
    assert assets[0].asset_key == "Caf\u00e9-asset"
    assert assets[0].target_ref == "Caf\u00e9-target"
    assert len({row.evidence_json["observation_key"] for row in occurrences}) == 2


@pytest.mark.parametrize("explicit_first", [False, True])
def test_finding_scope_uses_its_single_explicit_asset_id_independent_of_input_order(
    workbench_api_env: WorkbenchApiEnv,
    *,
    explicit_first: bool,
) -> None:
    raw = NormalizedOccurrence(
        cve_id="CVE-2299-2200",
        target_kind="host",
        target_ref="build-host-1",
        source="identity-regression",
        raw_evidence={"source_record_id": "raw"},
    )
    explicit = NormalizedOccurrence(
        cve_id=raw.cve_id,
        target_kind=raw.target_kind,
        target_ref=raw.target_ref,
        asset_id="asset-prod",
        source=raw.source,
        raw_evidence={"source_record_id": "enriched"},
    )
    ordered = [explicit, raw] if explicit_first else [raw, explicit]

    with Session(workbench_api_env.engine) as session:
        project = create_project(
            session,
            workbench_api_env.app_models,
            workbench_api_env.repositories,
            name=f"Mixed asset identity order {explicit_first}",
        )
        run = workbench_api_env.repositories.RunRepository(session).create_analysis_run(
            project_id=project.id,
            input_type="generic-occurrence-csv",
            filename="mixed-asset-identity.csv",
        )

        summary = _persist_workbench_occurrences(
            session=session,
            project_id=project.id,
            run_id=run.id,
            occurrences=ordered,
            analysis_result=_analysis_result(ordered),
        )
        session.flush()

        findings = session.exec(
            select(workbench_api_env.app_models.Finding).where(
                workbench_api_env.app_models.Finding.project_id == project.id
            )
        ).all()
        assets = session.exec(
            select(workbench_api_env.app_models.Asset).where(
                workbench_api_env.app_models.Asset.project_id == project.id
            )
        ).all()
        persisted_occurrences = session.exec(
            select(workbench_api_env.app_models.FindingOccurrence).where(
                workbench_api_env.app_models.FindingOccurrence.analysis_run_id == run.id
            )
        ).all()

    assert summary["finding_count"] == 1
    assert summary["occurrence_count"] == 2
    assert len(findings) == len(assets) == 1
    assert findings[0].asset_id == assets[0].id
    assert assets[0].asset_key == "asset-prod"
    assert assets[0].target_ref == "build-host-1"
    assert len(persisted_occurrences) == 2
    assert {row.evidence_json["asset_id"] for row in persisted_occurrences} == {
        None,
        "asset-prod",
    }


def test_non_purl_component_coordinate_delimiters_cannot_redistribute_identity() -> None:
    first_component = component_scope_identity(
        component_name="a|b",
        component_version="c",
        package_type="d",
    )
    second_component = component_scope_identity(
        component_name="a",
        component_version="b|c",
        package_type="d",
    )

    assert first_component is not None
    assert second_component is not None
    assert first_component != second_component

    first_scope = finding_scope_identity(
        project_id=_PROJECT_ID,
        cve_id=_CVE_ID,
        component_name="a|b",
        component_version="c",
        package_type="d",
    )
    second_scope = finding_scope_identity(
        project_id=_PROJECT_ID,
        cve_id=_CVE_ID,
        component_name="a",
        component_version="b|c",
        package_type="d",
    )

    assert first_scope.component_identity != second_scope.component_identity
    assert finding_scope_key(first_scope) != finding_scope_key(second_scope)


def test_asset_persistence_key_namespaces_explicit_and_source_target_identities() -> None:
    explicit_asset = NormalizedOccurrence(
        cve_id=_CVE_ID,
        asset_id="host:server-1",
    )
    generic_target = NormalizedOccurrence(
        cve_id=_CVE_ID,
        target_ref="host:server-1",
    )
    typed_target = NormalizedOccurrence(
        cve_id=_CVE_ID,
        target_kind="host",
        target_ref="server-1",
    )

    keys = {
        _asset_persistence_key(explicit_asset),
        _asset_persistence_key(generic_target),
        _asset_persistence_key(typed_target),
    }

    assert None not in keys
    assert len(keys) == 3


def test_asset_persistence_key_encodes_colons_without_field_boundary_aliases() -> None:
    colon_in_kind = NormalizedOccurrence(
        cve_id=_CVE_ID,
        target_kind="host:cluster",
        target_ref="node-1",
    )
    colon_in_ref = NormalizedOccurrence(
        cve_id=_CVE_ID,
        target_kind="host",
        target_ref="cluster:node-1",
    )

    assert _asset_persistence_key(colon_in_kind) != _asset_persistence_key(colon_in_ref)


def test_component_repository_rejects_coordinate_identity_hash_mismatch(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    with Session(workbench_api_env.engine) as session:
        identity = normalize_component_persistence_identity(
            name="requests",
            version="2.0.0",
            ecosystem="pypi",
            package_type="pypi",
        )
        corrupted = workbench_api_env.app_models.Component(
            name="  Requests  ",
            version="2.0.0",
            ecosystem="PyPI",
            identity_key=identity.storage_key,
            identity_material='component-identity-v1:["coordinates","other",null,null]',
        )
        session.add(corrupted)
        session.flush()

        repository = workbench_api_env.repositories.FindingRepository(session)
        with pytest.raises(
            ComponentIdentityInvariantError,
            match="hash resolved to contradictory canonical material",
        ):
            repository.upsert_component(
                name=" REQUESTS ",
                version="2.0.0",
                ecosystem="pypi",
                package_type="pypi",
            )


def test_component_repository_uses_the_same_unicode_casefold_as_scope_identity(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    with Session(workbench_api_env.engine) as session:
        repository = workbench_api_env.repositories.FindingRepository(session)
        first = repository.upsert_component(
            name="Straße",
            version="1.0",
            ecosystem="generic",
        )
        second = repository.upsert_component(
            name="STRASSE",
            version="1.0",
            ecosystem="generic",
        )

        assert first.id == second.id
        assert len(session.exec(select(workbench_api_env.app_models.Component)).all()) == 1


def test_component_identity_normalizes_canonically_equivalent_unicode(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    composed = component_scope_identity(
        component_name="Caf\u00e9",
        component_version="1.0",
        package_type="generic",
    )
    decomposed = component_scope_identity(
        component_name="Cafe\u0301",
        component_version="1.0",
        package_type="generic",
    )

    assert composed == decomposed
    with Session(workbench_api_env.engine) as session:
        repository = workbench_api_env.repositories.FindingRepository(session)
        first = repository.upsert_component(
            name="Caf\u00e9",
            version="1.0",
            ecosystem="generic",
        )
        second = repository.upsert_component(
            name="Cafe\u0301",
            version="1.0",
            ecosystem="generic",
        )

        assert first.id == second.id
        assert len(session.exec(select(workbench_api_env.app_models.Component)).all()) == 1


def test_component_purl_normalizes_canonically_equivalent_unicode() -> None:
    composed = component_scope_identity(
        component_name=None,
        purl="pkg:generic/Caf\u00e9@1",
    )
    decomposed = component_scope_identity(
        component_name=None,
        purl="pkg:generic/Cafe\u0301@1",
    )

    assert composed == decomposed


def test_component_purl_canonicalization_has_frozen_v1_golden_keys() -> None:
    npm = component_scope_identity(
        component_name="Animation",
        component_version="12.3.1",
        purl="pkg:npm/%40Angular/Animation@12.3.1",
    )
    composer = component_scope_identity(
        component_name="Console",
        component_version="6.0.0",
        purl="pkg:composer/Symfony/Console@6.0.0",
    )

    assert npm == 'component-identity-v1:["purl","pkg:npm/%40Angular/animation@12.3.1"]'
    assert composer == ('component-identity-v1:["purl","pkg:composer/symfony/console@6.0.0"]')
    assert component_storage_key(npm) == (
        "vpw-component-storage-v1:a7052945f7bd768675c329495746a59816743eb48fa8076895feeb7271c78527"
    )
    assert component_storage_key(composer) == (
        "vpw-component-storage-v1:6f2e4c50024bdf2564f1d5cc8aff08bc0dd0b784cc0c91d1aeb57b5d63910231"
    )


def test_import_persistence_keeps_colliding_asset_labels_as_distinct_identities(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    explicit = NormalizedOccurrence(
        cve_id="CVE-2201-1000",
        asset_id="asset-prod",
        target_kind="host",
        target_ref="other-host",
        source="identity-regression",
        raw_evidence={
            "source_record_id": "explicit",
            "owner": "explicit-owner",
            "criticality": "critical",
        },
    )
    generic = NormalizedOccurrence(
        cve_id="CVE-2201-1001",
        target_ref="asset-prod",
        source="identity-regression",
        raw_evidence={
            "source_record_id": "generic",
            "owner": "generic-owner",
            "criticality": "low",
        },
    )
    colon_in_kind = NormalizedOccurrence(
        cve_id="CVE-2201-1002",
        target_kind="host:cluster",
        target_ref="node-1",
        source="identity-regression",
        raw_evidence={"source_record_id": "colon-kind", "owner": "kind-owner"},
    )
    colon_in_ref = NormalizedOccurrence(
        cve_id="CVE-2201-1003",
        target_kind="host",
        target_ref="cluster:node-1",
        source="identity-regression",
        raw_evidence={"source_record_id": "colon-ref", "owner": "ref-owner"},
    )
    occurrences = [explicit, generic, colon_in_kind, colon_in_ref]

    with Session(workbench_api_env.engine) as session:
        project = create_project(
            session,
            workbench_api_env.app_models,
            workbench_api_env.repositories,
            name="Asset identity collision regression",
        )
        run = workbench_api_env.repositories.RunRepository(session).create_analysis_run(
            project_id=project.id,
            input_type="generic-occurrence-csv",
            filename="identity-collision.csv",
        )

        summary = _persist_workbench_occurrences(
            session=session,
            project_id=project.id,
            run_id=run.id,
            occurrences=occurrences,
            analysis_result=_analysis_result(occurrences),
        )
        session.flush()

        findings = session.exec(
            select(workbench_api_env.app_models.Finding).where(
                workbench_api_env.app_models.Finding.project_id == project.id
            )
        ).all()
        assets = session.exec(
            select(workbench_api_env.app_models.Asset).where(
                workbench_api_env.app_models.Asset.project_id == project.id
            )
        ).all()
        asset_by_id = {asset.id: asset for asset in assets}
        asset_by_cve = {
            finding.cve_id: asset_by_id[finding.asset_id]
            for finding in findings
            if finding.asset_id is not None
        }

    assert summary["finding_count"] == 4
    assert len(findings) == len(assets) == len(asset_by_cve) == 4
    assert len({finding.asset_id for finding in findings}) == 4

    explicit_asset = asset_by_cve[explicit.cve_id]
    generic_asset = asset_by_cve[generic.cve_id]
    assert explicit_asset.id != generic_asset.id
    assert explicit_asset.asset_key == "asset-prod"
    assert explicit_asset.target_ref == "other-host"
    assert explicit_asset.owner == "explicit-owner"
    assert generic_asset.asset_key == _asset_persistence_key(generic)
    assert generic_asset.target_ref == "asset-prod"
    assert generic_asset.owner == "generic-owner"

    kind_asset = asset_by_cve[colon_in_kind.cve_id]
    ref_asset = asset_by_cve[colon_in_ref.cve_id]
    assert kind_asset.id != ref_asset.id
    assert {
        kind_asset.asset_key,
        ref_asset.asset_key,
    } == {
        _preferred_asset_storage_key(colon_in_kind),
        _asset_persistence_key(colon_in_ref),
    } or {
        kind_asset.asset_key,
        ref_asset.asset_key,
    } == {
        _asset_persistence_key(colon_in_kind),
        _preferred_asset_storage_key(colon_in_ref),
    }
    assert kind_asset.target_ref == "node-1"
    assert kind_asset.owner == "kind-owner"
    assert ref_asset.target_ref == "cluster:node-1"
    assert ref_asset.owner == "ref-owner"


def test_explicit_asset_id_wins_readable_collision_across_separate_imports(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    implicit = NormalizedOccurrence(
        cve_id="CVE-2204-0901",
        target_ref="asset-prod",
        source="identity-regression",
        raw_evidence={"source_record_id": "implicit"},
    )
    explicit = NormalizedOccurrence(
        cve_id="CVE-2204-0902",
        asset_id="asset-prod",
        target_kind="host",
        target_ref="other-host",
        source="identity-regression",
        raw_evidence={"source_record_id": "explicit"},
    )
    implicit_identity_key = _asset_persistence_key(implicit)
    assert implicit_identity_key is not None

    def persist(
        session: Session,
        *,
        project_id: uuid.UUID,
        occurrences: list[NormalizedOccurrence],
        filename: str,
    ) -> None:
        run = workbench_api_env.repositories.RunRepository(session).create_analysis_run(
            project_id=project_id,
            input_type="generic-occurrence-csv",
            filename=filename,
        )
        _persist_workbench_occurrences(
            session=session,
            project_id=project_id,
            run_id=run.id,
            occurrences=occurrences,
            analysis_result=_analysis_result(occurrences),
        )
        session.commit()

    def persisted_assignment(
        session: Session,
        *,
        project_id: uuid.UUID,
    ) -> tuple[dict[str, uuid.UUID], dict[uuid.UUID, str]]:
        findings = session.exec(
            select(workbench_api_env.app_models.Finding).where(
                workbench_api_env.app_models.Finding.project_id == project_id
            )
        ).all()
        assets = session.exec(
            select(workbench_api_env.app_models.Asset).where(
                workbench_api_env.app_models.Asset.project_id == project_id
            )
        ).all()
        return (
            {
                finding.cve_id: finding.asset_id
                for finding in findings
                if finding.asset_id is not None
            },
            {asset.id: asset.asset_key for asset in assets},
        )

    with Session(workbench_api_env.engine) as session:
        implicit_first_project = create_project(
            session,
            workbench_api_env.app_models,
            workbench_api_env.repositories,
            name="Implicit collision first",
        )
        project_id = implicit_first_project.id
        persist(
            session,
            project_id=project_id,
            occurrences=[implicit],
            filename="implicit-first.csv",
        )
        first_assignment, _ = persisted_assignment(session, project_id=project_id)
        original_implicit_asset_id = first_assignment[implicit.cve_id]

        persist(
            session,
            project_id=project_id,
            occurrences=[explicit],
            filename="explicit-second.csv",
        )
        persist(
            session,
            project_id=project_id,
            occurrences=[explicit, implicit],
            filename="repeat-both.csv",
        )
        assignment, asset_keys = persisted_assignment(session, project_id=project_id)

        assert len(asset_keys) == 2
        assert assignment[implicit.cve_id] == original_implicit_asset_id
        assert asset_keys[assignment[implicit.cve_id]] == implicit_identity_key
        assert asset_keys[assignment[explicit.cve_id]] == "asset-prod"

        explicit_first_project = create_project(
            session,
            workbench_api_env.app_models,
            workbench_api_env.repositories,
            name="Explicit collision first",
        )
        reverse_project_id = explicit_first_project.id
        persist(
            session,
            project_id=reverse_project_id,
            occurrences=[explicit],
            filename="explicit-first.csv",
        )
        persist(
            session,
            project_id=reverse_project_id,
            occurrences=[implicit],
            filename="implicit-second.csv",
        )
        reverse_assignment, reverse_asset_keys = persisted_assignment(
            session,
            project_id=reverse_project_id,
        )

    assert len(reverse_asset_keys) == 2
    assert reverse_asset_keys[reverse_assignment[implicit.cve_id]] == implicit_identity_key
    assert reverse_asset_keys[reverse_assignment[explicit.cve_id]] == "asset-prod"


def test_hashed_collision_asset_remains_canonical_after_readable_key_is_freed(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    explicit = NormalizedOccurrence(
        cve_id="CVE-2204-1000",
        asset_id="asset-prod",
        target_kind="host",
        target_ref="other-host",
        source="identity-regression",
        raw_evidence={"source_record_id": "explicit"},
    )
    first_implicit = NormalizedOccurrence(
        cve_id="CVE-2204-1001",
        target_ref="asset-prod",
        source="identity-regression",
        raw_evidence={"source_record_id": "implicit-first"},
    )
    repeated_identity = NormalizedOccurrence(
        cve_id="CVE-2204-1002",
        target_ref="asset-prod",
        source="identity-regression",
        raw_evidence={"source_record_id": "implicit-later"},
    )

    with Session(workbench_api_env.engine) as session:
        project = create_project(
            session,
            workbench_api_env.app_models,
            workbench_api_env.repositories,
            name="Stable hashed asset identity",
        )
        first_run = workbench_api_env.repositories.RunRepository(session).create_analysis_run(
            project_id=project.id,
            input_type="generic-occurrence-csv",
            filename="collision-first.csv",
        )
        _persist_workbench_occurrences(
            session=session,
            project_id=project.id,
            run_id=first_run.id,
            occurrences=[explicit, first_implicit],
            analysis_result=_analysis_result([explicit, first_implicit]),
        )
        session.flush()

        initial_findings = session.exec(
            select(workbench_api_env.app_models.Finding).where(
                workbench_api_env.app_models.Finding.project_id == project.id
            )
        ).all()
        initial_assets = session.exec(
            select(workbench_api_env.app_models.Asset).where(
                workbench_api_env.app_models.Asset.project_id == project.id
            )
        ).all()
        initial_assets_by_id = {asset.id: asset for asset in initial_assets}
        initial_finding_by_cve = {finding.cve_id: finding for finding in initial_findings}
        explicit_asset = initial_assets_by_id[initial_finding_by_cve[explicit.cve_id].asset_id]
        implicit_asset = initial_assets_by_id[
            initial_finding_by_cve[first_implicit.cve_id].asset_id
        ]
        implicit_asset_id = implicit_asset.id
        assert implicit_asset.asset_key == _asset_persistence_key(first_implicit)

        explicit_asset.asset_key = "renamed-explicit-asset"
        session.add(explicit_asset)
        session.flush()

        follow_up_run = workbench_api_env.repositories.RunRepository(session).create_analysis_run(
            project_id=project.id,
            input_type="generic-occurrence-csv",
            filename="collision-follow-up.csv",
        )
        follow_up_summary = _persist_workbench_occurrences(
            session=session,
            project_id=project.id,
            run_id=follow_up_run.id,
            occurrences=[repeated_identity],
            analysis_result=_analysis_result([repeated_identity]),
        )
        session.flush()

        persisted_assets = session.exec(
            select(workbench_api_env.app_models.Asset).where(
                workbench_api_env.app_models.Asset.project_id == project.id
            )
        ).all()
        follow_up_finding = session.exec(
            select(workbench_api_env.app_models.Finding).where(
                workbench_api_env.app_models.Finding.project_id == project.id,
                workbench_api_env.app_models.Finding.cve_id == repeated_identity.cve_id,
            )
        ).one()

    assert follow_up_summary["created_findings"] == 1
    assert len(persisted_assets) == 2
    assert follow_up_finding.asset_id == implicit_asset_id
    assert implicit_asset.asset_key == _asset_persistence_key(repeated_identity)


def test_asset_patch_allows_unchanged_internal_key_but_rejects_a_new_claim(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    explicit = NormalizedOccurrence(
        cve_id="CVE-2204-2000",
        asset_id="host:shared",
        target_kind="host",
        target_ref="explicit-host",
        source="identity-regression",
        raw_evidence={"source_record_id": "explicit"},
    )
    implicit = NormalizedOccurrence(
        cve_id="CVE-2204-2001",
        target_kind="host",
        target_ref="shared",
        source="identity-regression",
        raw_evidence={"source_record_id": "implicit"},
    )
    internal_key = _asset_persistence_key(implicit)
    assert internal_key is not None

    with Session(workbench_api_env.engine) as session:
        project = create_project(
            session,
            workbench_api_env.app_models,
            workbench_api_env.repositories,
            name="Editable internal asset key",
        )
        run = workbench_api_env.repositories.RunRepository(session).create_analysis_run(
            project_id=project.id,
            input_type="generic-occurrence-csv",
            filename="editable-internal-key.csv",
        )
        _persist_workbench_occurrences(
            session=session,
            project_id=project.id,
            run_id=run.id,
            occurrences=[explicit, implicit],
            analysis_result=_analysis_result([explicit, implicit]),
        )
        session.commit()
        internal_asset = session.exec(
            select(workbench_api_env.app_models.Asset).where(
                workbench_api_env.app_models.Asset.project_id == project.id,
                workbench_api_env.app_models.Asset.asset_key == internal_key,
            )
        ).one()
        internal_asset_id = internal_asset.id

    headers = local_api_headers(workbench_api_env.client)
    unchanged = workbench_api_env.client.patch(
        f"/api/v1/assets/{internal_asset_id}",
        headers=headers,
        json={"asset_key": internal_key, "owner": "team-updated"},
    )
    assert unchanged.status_code == 200, unchanged.text
    assert unchanged.json()["asset_key"] == internal_key
    assert unchanged.json()["owner"] == "team-updated"

    claim = workbench_api_env.client.patch(
        f"/api/v1/assets/{internal_asset_id}",
        headers=headers,
        json={"asset_key": f"{ASSET_IDENTITY_KEY_PREFIX}{'f' * 64}"},
    )
    assert claim.status_code == 422, claim.text
    assert claim.json()["detail"] == ("Asset key uses the reserved Workbench identity namespace.")


def test_import_rejects_versioned_asset_key_with_contradictory_evidence(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    desired = NormalizedOccurrence(
        cve_id="CVE-2299-2000",
        target_kind="host",
        target_ref="desired",
        source="identity-regression",
        raw_evidence={"source_record_id": "desired"},
    )
    versioned_key = _asset_persistence_key(desired)
    assert versioned_key is not None

    with Session(workbench_api_env.engine) as session:
        project = create_project(
            session,
            workbench_api_env.app_models,
            workbench_api_env.repositories,
            name="Contradictory versioned asset identity",
        )
        conflicting_asset = workbench_api_env.app_models.Asset(
            project_id=project.id,
            asset_key=versioned_key,
            name="Other host",
            target_ref="other",
        )
        session.add(conflicting_asset)
        vulnerability = workbench_api_env.app_models.Vulnerability(
            cve_id="CVE-2299-1999",
            source_id="CVE-2299-1999",
            title="Existing vulnerability",
        )
        session.add(vulnerability)
        session.flush()
        existing_finding = workbench_api_env.app_models.Finding(
            project_id=project.id,
            vulnerability_id=vulnerability.id,
            asset_id=conflicting_asset.id,
            cve_id=vulnerability.cve_id,
            dedup_key="existing-other-host",
        )
        session.add(existing_finding)
        existing_run = workbench_api_env.repositories.RunRepository(session).create_analysis_run(
            project_id=project.id,
            input_type="generic-occurrence-csv",
            filename="existing.csv",
        )
        session.flush()
        session.add(
            workbench_api_env.app_models.FindingOccurrence(
                finding_id=existing_finding.id,
                analysis_run_id=existing_run.id,
                source="identity-regression",
                evidence_json={"target_kind": "host", "target_ref": "other"},
            )
        )
        import_run = workbench_api_env.repositories.RunRepository(session).create_analysis_run(
            project_id=project.id,
            input_type="generic-occurrence-csv",
            filename="desired.csv",
        )
        session.flush()

        with pytest.raises(
            AssetIdentityInvariantError,
            match="contradicts its versioned identity key",
        ):
            _persist_workbench_occurrences(
                session=session,
                project_id=project.id,
                run_id=import_run.id,
                occurrences=[desired],
                analysis_result=_analysis_result([desired]),
            )

        assert conflicting_asset.target_ref == "other"


def test_operator_asset_id_cannot_claim_internal_identity_namespace() -> None:
    occurrence = NormalizedOccurrence(
        cve_id="CVE-2299-2100",
        asset_id=f"{ASSET_IDENTITY_KEY_PREFIX}{'0' * 64}",
        source="identity-regression",
    )
    identity_key = _asset_persistence_key(occurrence)
    assert identity_key is not None

    with pytest.raises(ValueError, match="reserved Workbench identity namespace"):
        _asset_storage_keys_by_identity({identity_key: [occurrence]})


def test_new_import_cannot_create_a_reserved_asset_id(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    occurrence = NormalizedOccurrence(
        cve_id="CVE-2299-2101",
        target_kind="host",
        target_ref="new-host",
        asset_id=f"{ASSET_IDENTITY_KEY_PREFIX}customer-db",
        source="identity-regression",
        raw_evidence={"source_record_id": "reserved-sidecar"},
    )

    with Session(workbench_api_env.engine) as session:
        project = create_project(
            session,
            workbench_api_env.app_models,
            workbench_api_env.repositories,
            name="Reserved sidecar claim",
        )
        run = workbench_api_env.repositories.RunRepository(session).create_analysis_run(
            project_id=project.id,
            input_type="generic-occurrence-csv",
            filename="reserved-sidecar.csv",
        )

        with pytest.raises(ValueError, match="reserved Workbench identity namespace"):
            _persist_workbench_occurrences(
                session=session,
                project_id=project.id,
                run_id=run.id,
                occurrences=[occurrence],
                analysis_result=_analysis_result([occurrence]),
            )

        assert not session.exec(
            select(workbench_api_env.app_models.Asset).where(
                workbench_api_env.app_models.Asset.project_id == project.id
            )
        ).all()


def test_bulk_path_defers_reserved_asset_ids_to_evidence_aware_persistence(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    occurrences = [
        NormalizedOccurrence(
            cve_id=f"CVE-2300-{index + 1000:04d}",
            target_kind="host",
            target_ref=f"host-{index}",
            asset_id=(
                f"{ASSET_IDENTITY_KEY_PREFIX}legacy-host" if index == 0 else f"asset-{index}"
            ),
            source="identity-regression",
            raw_evidence={"source_record_id": f"reserved-bulk-{index}"},
        )
        for index in range(1000)
    ]

    with Session(workbench_api_env.engine) as session:
        project = create_project(
            session,
            workbench_api_env.app_models,
            workbench_api_env.repositories,
            name="Reserved bulk fallback",
        )
        run = workbench_api_env.repositories.RunRepository(session).create_analysis_run(
            project_id=project.id,
            input_type="generic-occurrence-csv",
            filename="reserved-bulk.csv",
        )
        result = _persist_workbench_occurrences_bulk_insert(
            session=session,
            project_id=project.id,
            run_id=run.id,
            occurrences=occurrences,
            analysis_result=_analysis_result(occurrences),
        )

        assert result is None
        assert not session.exec(
            select(workbench_api_env.app_models.Asset).where(
                workbench_api_env.app_models.Asset.project_id == project.id
            )
        ).all()


def test_asset_api_rejects_reserved_identity_namespace(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)

    response = workbench_api_env.client.post(
        f"/api/v1/projects/{project['id']}/assets/",
        headers=headers,
        json={
            "asset_key": f"{ASSET_IDENTITY_KEY_PREFIX}{'2' * 64}",
            "name": "Reserved identity claim",
        },
    )

    assert response.status_code == 422, response.text
    assert response.json()["detail"] == (
        "Asset key uses the reserved Workbench identity namespace."
    )


def test_asset_api_normalizes_operator_keys_and_rejects_trimmed_blank_values(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    headers = local_api_headers(workbench_api_env.client)
    project = create_project_via_api(workbench_api_env.client, headers)
    decomposed_key = "  Cafe\u0301-asset  "
    composed_key = "Caf\u00e9-asset"

    create_response = workbench_api_env.client.post(
        f"/api/v1/projects/{project['id']}/assets/",
        headers=headers,
        json={"asset_key": decomposed_key, "name": "Unicode asset"},
    )
    assert create_response.status_code == 200, create_response.text
    assert create_response.json()["asset_key"] == composed_key

    upsert_response = workbench_api_env.client.post(
        f"/api/v1/projects/{project['id']}/assets/",
        headers=headers,
        json={"asset_key": composed_key, "name": "Updated Unicode asset"},
    )
    assert upsert_response.status_code == 200, upsert_response.text
    assert upsert_response.json()["id"] == create_response.json()["id"]

    update_response = workbench_api_env.client.patch(
        f"/api/v1/assets/{create_response.json()['id']}",
        headers=headers,
        json={"asset_key": "  Re\u0301named  "},
    )
    assert update_response.status_code == 200, update_response.text
    assert update_response.json()["asset_key"] == "R\u00e9named"

    blank_create = workbench_api_env.client.post(
        f"/api/v1/projects/{project['id']}/assets/",
        headers=headers,
        json={"asset_key": " \t ", "name": "Blank asset"},
    )
    blank_update = workbench_api_env.client.patch(
        f"/api/v1/assets/{create_response.json()['id']}",
        headers=headers,
        json={"asset_key": "   "},
    )
    assert blank_create.status_code == 422
    assert blank_create.json()["detail"] == "Asset key must not be blank."
    assert blank_update.status_code == 422
    assert blank_update.json()["detail"] == "Asset key must not be blank."

    list_response = workbench_api_env.client.get(
        f"/api/v1/projects/{project['id']}/assets/",
        headers=headers,
    )
    assert list_response.status_code == 200
    assert list_response.json()["count"] == 1
    assert list_response.json()["data"][0]["asset_key"] == "R\u00e9named"


def test_reserved_target_label_is_stored_under_its_own_identity_key() -> None:
    occurrence = NormalizedOccurrence(
        cve_id="CVE-2299-2200",
        target_ref=f"{ASSET_IDENTITY_KEY_PREFIX}{'1' * 64}",
        source="identity-regression",
    )
    identity_key = _asset_persistence_key(occurrence)
    assert identity_key is not None

    assert _asset_storage_keys_by_identity({identity_key: [occurrence]}) == {
        identity_key: identity_key
    }


def test_import_rejects_unproven_asset_in_internal_identity_namespace(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    desired = NormalizedOccurrence(
        cve_id="CVE-2299-2300",
        target_kind="host",
        target_ref="desired",
        source="identity-regression",
        raw_evidence={"source_record_id": "desired"},
    )
    versioned_key = _asset_persistence_key(desired)
    assert versioned_key is not None

    with Session(workbench_api_env.engine) as session:
        project = create_project(
            session,
            workbench_api_env.app_models,
            workbench_api_env.repositories,
            name="Unproven internal asset identity",
        )
        conflicting_asset = workbench_api_env.app_models.Asset(
            project_id=project.id,
            asset_key=versioned_key,
            name="Manually claimed identity",
            target_ref="other",
        )
        session.add(conflicting_asset)
        import_run = workbench_api_env.repositories.RunRepository(session).create_analysis_run(
            project_id=project.id,
            input_type="generic-occurrence-csv",
            filename="desired.csv",
        )
        session.flush()

        with pytest.raises(
            AssetIdentityInvariantError,
            match="contradicts its versioned identity key",
        ):
            _persist_workbench_occurrences(
                session=session,
                project_id=project.id,
                run_id=import_run.id,
                occurrences=[desired],
                analysis_result=_analysis_result([desired]),
            )

        assert conflicting_asset.name == "Manually claimed identity"
        assert conflicting_asset.target_ref == "other"


def test_normal_and_bulk_persistence_share_raw_severity_fallback(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    raw_severity = "scanner-critical"
    normal_occurrence = NormalizedOccurrence(
        cve_id="CVE-2202-1000",
        target_ref="normal-host",
        source="severity-regression",
        raw_evidence={"source_record_id": "normal", "severity": raw_severity},
    )
    bulk_occurrences = [
        NormalizedOccurrence(
            cve_id=f"CVE-2203-{index + 1000:04d}",
            target_ref=f"bulk-host-{index}",
            source="severity-regression",
            raw_evidence={
                "source_record_id": f"bulk-{index}",
                "severity": raw_severity,
            },
        )
        for index in range(1000)
    ]

    with Session(workbench_api_env.engine) as session:
        normal_project = create_project(
            session,
            workbench_api_env.app_models,
            workbench_api_env.repositories,
            name="Normal severity fallback",
        )
        normal_run = workbench_api_env.repositories.RunRepository(session).create_analysis_run(
            project_id=normal_project.id,
            input_type="generic-occurrence-csv",
            filename="normal-severity.csv",
        )
        normal_summary = _persist_workbench_occurrences(
            session=session,
            project_id=normal_project.id,
            run_id=normal_run.id,
            occurrences=[normal_occurrence],
            analysis_result=_analysis_result([normal_occurrence]),
        )

        bulk_project = create_project(
            session,
            workbench_api_env.app_models,
            workbench_api_env.repositories,
            name="Bulk severity fallback",
        )
        bulk_run = workbench_api_env.repositories.RunRepository(session).create_analysis_run(
            project_id=bulk_project.id,
            input_type="generic-occurrence-csv",
            filename="bulk-severity.csv",
        )
        bulk_summary = _persist_workbench_occurrences_bulk_insert(
            session=session,
            project_id=bulk_project.id,
            run_id=bulk_run.id,
            occurrences=bulk_occurrences,
            analysis_result=_analysis_result(bulk_occurrences),
        )
        assert bulk_summary is not None
        session.flush()

        normal_vulnerability = session.exec(
            select(workbench_api_env.app_models.Vulnerability).where(
                workbench_api_env.app_models.Vulnerability.cve_id == normal_occurrence.cve_id
            )
        ).one()
        bulk_vulnerability = session.exec(
            select(workbench_api_env.app_models.Vulnerability).where(
                workbench_api_env.app_models.Vulnerability.cve_id == bulk_occurrences[0].cve_id
            )
        ).one()

    assert normal_summary["finding_count"] == 1
    assert bulk_summary["finding_count"] == 1000
    assert normal_vulnerability.severity == bulk_vulnerability.severity == raw_severity

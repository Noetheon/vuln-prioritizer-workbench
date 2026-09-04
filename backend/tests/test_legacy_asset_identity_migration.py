from __future__ import annotations

import uuid

import pytest
from sqlmodel import Session, select
from utils.workbench_env import WorkbenchApiEnv, create_project_via_api, local_api_headers

from app.decision_core.identity import FINDING_SCOPE_KEY_PREFIX
from app.domain.engine.models import AnalysisContext, PrioritizedFinding
from app.importers.contracts import NormalizedOccurrence
from app.services.analysis import WorkbenchAnalysisResult
from app.services.import_execution_dedup import (
    _preferred_asset_storage_key,
)
from app.services.import_execution_persistence import _persist_workbench_occurrences
from app.services.import_execution_persistence_bulk import (
    _persist_workbench_occurrences_bulk_insert,
)

TARGET_KIND = "host"
TARGET_REF = "legacy-server-1"


def _decision(cve_id: str) -> PrioritizedFinding:
    return PrioritizedFinding(
        cve_id=cve_id,
        priority_label="High",
        priority_rank=2,
        priority_state="Open",
        operational_score=80,
        rationale="Legacy asset identity migration regression.",
        recommended_action="Review and remediate.",
    )


def _occurrence(
    cve_id: str,
    *,
    target_kind: str = TARGET_KIND,
    target_ref: str | None = TARGET_REF,
) -> NormalizedOccurrence:
    return NormalizedOccurrence(
        cve_id=cve_id,
        target_kind=target_kind,
        target_ref=target_ref,
        source="legacy-asset-regression",
        raw_evidence={
            "source_id": cve_id,
            "source_record_id": f"record:{cve_id}",
        },
    )


def _analysis_result(occurrences: list[NormalizedOccurrence]) -> WorkbenchAnalysisResult:
    return WorkbenchAnalysisResult(
        findings_by_cve={item.cve_id: _decision(item.cve_id) for item in occurrences},
        context=AnalysisContext(
            input_path="legacy-asset-regression.csv",
            output_format="json",
            generated_at="2026-09-04T00:00:00Z",
        ),
        provider_snapshot_id=None,
        provider_snapshot_hash=None,
        provider_snapshot_file=None,
        locked_provider_data=False,
    )


def _create_project(workbench_api_env: WorkbenchApiEnv, *, name: str) -> uuid.UUID:
    project = create_project_via_api(
        workbench_api_env.client,
        local_api_headers(workbench_api_env.client),
        name=name,
    )
    return uuid.UUID(project["id"])


def _seed_legacy_asset(
    workbench_api_env: WorkbenchApiEnv,
    *,
    project_id: uuid.UUID,
    evidence_scope: tuple[str, str] | None,
    evidence_asset_id: str | None = None,
) -> uuid.UUID:
    app_models = workbench_api_env.app_models
    with Session(workbench_api_env.engine) as session:
        asset = app_models.Asset(
            project_id=project_id,
            asset_key=TARGET_REF,
            name="Legacy server",
            target_ref=TARGET_REF,
        )
        session.add(asset)
        session.flush()

        if evidence_scope is not None:
            vulnerability = app_models.Vulnerability(
                cve_id="CVE-2099-0001",
                source_id="CVE-2099-0001",
                title="Legacy vulnerability",
            )
            session.add(vulnerability)
            session.flush()
            finding = app_models.Finding(
                project_id=project_id,
                vulnerability_id=vulnerability.id,
                asset_id=asset.id,
                cve_id=vulnerability.cve_id,
                dedup_key="legacy-finding-key",
            )
            session.add(finding)
            run = workbench_api_env.repositories.RunRepository(session).create_analysis_run(
                project_id=project_id,
                input_type="generic-occurrence-csv",
                filename="legacy.csv",
            )
            session.flush()
            evidence_json = {
                "target_kind": evidence_scope[0],
                "target_ref": evidence_scope[1],
            }
            if evidence_asset_id is not None:
                evidence_json["asset_id"] = evidence_asset_id
            session.add(
                app_models.FindingOccurrence(
                    finding_id=finding.id,
                    analysis_run_id=run.id,
                    source="legacy-import",
                    evidence_json=evidence_json,
                )
            )

        session.commit()
        return asset.id


def _seed_legacy_finding(
    workbench_api_env: WorkbenchApiEnv,
    *,
    project_id: uuid.UUID,
    cve_id: str,
    occurrence_evidence: list[dict[str, object]],
    dedup_prefix: str = "vpw-finding-scope-v1:",
) -> uuid.UUID:
    app_models = workbench_api_env.app_models
    with Session(workbench_api_env.engine) as session:
        vulnerability = app_models.Vulnerability(
            cve_id=cve_id,
            source_id=cve_id,
            title="Legacy vulnerability",
        )
        session.add(vulnerability)
        session.flush()
        finding = app_models.Finding(
            project_id=project_id,
            vulnerability_id=vulnerability.id,
            cve_id=cve_id,
            dedup_key=f"{dedup_prefix}old-source-sensitive-key",
        )
        session.add(finding)
        run = workbench_api_env.repositories.RunRepository(session).create_analysis_run(
            project_id=project_id,
            input_type="generic-occurrence-csv",
            filename="legacy-findings.csv",
        )
        session.flush()
        for evidence in occurrence_evidence:
            session.add(
                app_models.FindingOccurrence(
                    finding_id=finding.id,
                    analysis_run_id=run.id,
                    source="legacy-import",
                    evidence_json=evidence,
                )
            )
        session.commit()
        return finding.id


def _import_one(
    workbench_api_env: WorkbenchApiEnv,
    *,
    project_id: uuid.UUID,
    occurrence: NormalizedOccurrence,
) -> dict[str, object]:
    with Session(workbench_api_env.engine) as session:
        run = workbench_api_env.repositories.RunRepository(session).create_analysis_run(
            project_id=project_id,
            input_type="generic-occurrence-csv",
            filename="current.csv",
        )
        summary = _persist_workbench_occurrences(
            session=session,
            project_id=project_id,
            run_id=run.id,
            occurrences=[occurrence],
            analysis_result=_analysis_result([occurrence]),
        )
        session.commit()
        return summary


def test_evidence_proven_legacy_asset_is_promoted_in_place(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    project_id = _create_project(workbench_api_env, name="Proven legacy asset")
    legacy_asset_id = _seed_legacy_asset(
        workbench_api_env,
        project_id=project_id,
        evidence_scope=(TARGET_KIND, TARGET_REF),
    )
    occurrence = _occurrence("CVE-2099-0002")

    summary = _import_one(
        workbench_api_env,
        project_id=project_id,
        occurrence=occurrence,
    )

    with Session(workbench_api_env.engine) as session:
        assets = list(
            session.exec(
                select(workbench_api_env.app_models.Asset).where(
                    workbench_api_env.app_models.Asset.project_id == project_id
                )
            ).all()
        )
        findings = list(
            session.exec(
                select(workbench_api_env.app_models.Finding).where(
                    workbench_api_env.app_models.Finding.project_id == project_id
                )
            ).all()
        )

    assert summary["created_findings"] == 1
    assert len(assets) == 1
    assert assets[0].id == legacy_asset_id
    assert assets[0].asset_key == _preferred_asset_storage_key(occurrence)
    assert {finding.asset_id for finding in findings} == {legacy_asset_id}


@pytest.mark.parametrize(
    "evidence_scope",
    [
        pytest.param(None, id="unbound"),
        pytest.param((TARGET_KIND, "different-server"), id="contradictory-evidence"),
    ],
)
def test_unproven_legacy_asset_is_not_rebound(
    workbench_api_env: WorkbenchApiEnv,
    evidence_scope: tuple[str, str] | None,
) -> None:
    project_id = _create_project(workbench_api_env, name="Unproven legacy asset")
    legacy_asset_id = _seed_legacy_asset(
        workbench_api_env,
        project_id=project_id,
        evidence_scope=evidence_scope,
    )
    occurrence = _occurrence("CVE-2099-0002")

    _import_one(
        workbench_api_env,
        project_id=project_id,
        occurrence=occurrence,
    )

    with Session(workbench_api_env.engine) as session:
        assets = list(
            session.exec(
                select(workbench_api_env.app_models.Asset).where(
                    workbench_api_env.app_models.Asset.project_id == project_id
                )
            ).all()
        )
        current_finding = session.exec(
            select(workbench_api_env.app_models.Finding).where(
                workbench_api_env.app_models.Finding.project_id == project_id,
                workbench_api_env.app_models.Finding.cve_id == occurrence.cve_id,
            )
        ).one()

    assets_by_id = {asset.id: asset for asset in assets}
    assert len(assets) == 2
    assert assets_by_id[legacy_asset_id].asset_key == TARGET_REF
    assert current_finding.asset_id != legacy_asset_id
    assert current_finding.asset_id is not None
    assert assets_by_id[current_finding.asset_id].asset_key == _preferred_asset_storage_key(
        occurrence
    )


def test_explicit_legacy_asset_is_not_promoted_to_implicit_target_identity(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    project_id = _create_project(workbench_api_env, name="Explicit legacy asset")
    legacy_asset_id = _seed_legacy_asset(
        workbench_api_env,
        project_id=project_id,
        evidence_scope=(TARGET_KIND, TARGET_REF),
        evidence_asset_id="canonical-A",
    )
    occurrence = _occurrence("CVE-2099-0002")

    summary = _import_one(
        workbench_api_env,
        project_id=project_id,
        occurrence=occurrence,
    )

    with Session(workbench_api_env.engine) as session:
        assets = list(
            session.exec(
                select(workbench_api_env.app_models.Asset).where(
                    workbench_api_env.app_models.Asset.project_id == project_id
                )
            ).all()
        )
        current_finding = session.exec(
            select(workbench_api_env.app_models.Finding).where(
                workbench_api_env.app_models.Finding.project_id == project_id,
                workbench_api_env.app_models.Finding.cve_id == occurrence.cve_id,
            )
        ).one()

    assets_by_id = {asset.id: asset for asset in assets}
    assert summary["created_findings"] == 1
    assert len(assets) == 2
    assert assets_by_id[legacy_asset_id].asset_key == TARGET_REF
    assert current_finding.asset_id is not None
    assert current_finding.asset_id != legacy_asset_id
    assert assets_by_id[current_finding.asset_id].asset_key == _preferred_asset_storage_key(
        occurrence
    )


def test_bulk_fast_path_defers_when_a_legacy_asset_key_exists(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    project_id = _create_project(workbench_api_env, name="Bulk legacy fallback")
    legacy_asset_id = _seed_legacy_asset(
        workbench_api_env,
        project_id=project_id,
        evidence_scope=None,
    )
    occurrences = [
        _occurrence(f"CVE-2199-{index:04d}", target_ref=f"legacy-server-{index}")
        for index in range(1, 1001)
    ]

    with Session(workbench_api_env.engine) as session:
        result = _persist_workbench_occurrences_bulk_insert(
            session=session,
            project_id=project_id,
            run_id=uuid.uuid4(),
            occurrences=occurrences,
            analysis_result=_analysis_result(occurrences),
        )
        assets = list(
            session.exec(
                select(workbench_api_env.app_models.Asset).where(
                    workbench_api_env.app_models.Asset.project_id == project_id
                )
            ).all()
        )

    assert result is None
    assert [asset.id for asset in assets] == [legacy_asset_id]


def test_unscoped_singleton_legacy_finding_converges_on_v2_reimport(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    project_id = _create_project(workbench_api_env, name="Unscoped legacy finding")
    cve_id = "CVE-2299-0001"
    legacy_finding_id = _seed_legacy_finding(
        workbench_api_env,
        project_id=project_id,
        cve_id=cve_id,
        occurrence_evidence=[
            {"source_record_id": "legacy-record-1", "target_kind": "generic"},
            {"source_record_id": "legacy-record-2"},
        ],
    )
    occurrence = _occurrence(cve_id, target_kind="generic", target_ref=None)

    summary = _import_one(
        workbench_api_env,
        project_id=project_id,
        occurrence=occurrence,
    )

    with Session(workbench_api_env.engine) as session:
        findings = list(
            session.exec(
                select(workbench_api_env.app_models.Finding).where(
                    workbench_api_env.app_models.Finding.project_id == project_id
                )
            ).all()
        )
        occurrences = list(
            session.exec(
                select(workbench_api_env.app_models.FindingOccurrence).where(
                    workbench_api_env.app_models.FindingOccurrence.finding_id == legacy_finding_id
                )
            ).all()
        )

    assert summary["created_findings"] == 0
    assert summary["updated_findings"] == 1
    assert len(findings) == 1
    assert findings[0].id == legacy_finding_id
    assert findings[0].dedup_key.startswith(FINDING_SCOPE_KEY_PREFIX)
    assert len(occurrences) == 3


def test_scoped_legacy_finding_without_asset_converges_and_links_asset(
    workbench_api_env: WorkbenchApiEnv,
) -> None:
    project_id = _create_project(workbench_api_env, name="Scoped legacy finding")
    cve_id = "CVE-2299-0003"
    legacy_finding_id = _seed_legacy_finding(
        workbench_api_env,
        project_id=project_id,
        cve_id=cve_id,
        occurrence_evidence=[
            {"target_kind": TARGET_KIND, "target_ref": TARGET_REF},
        ],
    )
    occurrence = _occurrence(cve_id)

    summary = _import_one(
        workbench_api_env,
        project_id=project_id,
        occurrence=occurrence,
    )

    with Session(workbench_api_env.engine) as session:
        findings = list(
            session.exec(
                select(workbench_api_env.app_models.Finding).where(
                    workbench_api_env.app_models.Finding.project_id == project_id
                )
            ).all()
        )
        assets = list(
            session.exec(
                select(workbench_api_env.app_models.Asset).where(
                    workbench_api_env.app_models.Asset.project_id == project_id
                )
            ).all()
        )

    assert summary["created_findings"] == 0
    assert summary["updated_findings"] == 1
    assert len(findings) == len(assets) == 1
    assert findings[0].id == legacy_finding_id
    assert findings[0].dedup_key.startswith(FINDING_SCOPE_KEY_PREFIX)
    assert findings[0].asset_id == assets[0].id
    assert assets[0].target_ref == TARGET_REF


@pytest.mark.parametrize(
    "second_evidence",
    [
        pytest.param({}, id="scope-less"),
        pytest.param(
            {"target_kind": 7, "target_ref": TARGET_REF},
            id="malformed",
        ),
    ],
)
def test_partially_proven_legacy_finding_is_not_used_as_v2_alias(
    workbench_api_env: WorkbenchApiEnv,
    second_evidence: dict[str, object],
) -> None:
    project_id = _create_project(workbench_api_env, name="Ambiguous legacy finding")
    cve_id = "CVE-2299-0002"
    legacy_finding_id = _seed_legacy_finding(
        workbench_api_env,
        project_id=project_id,
        cve_id=cve_id,
        dedup_prefix="vpw019:",
        occurrence_evidence=[
            {"target_kind": TARGET_KIND, "target_ref": TARGET_REF},
            second_evidence,
        ],
    )
    occurrence = _occurrence(cve_id)

    summary = _import_one(
        workbench_api_env,
        project_id=project_id,
        occurrence=occurrence,
    )

    with Session(workbench_api_env.engine) as session:
        findings = list(
            session.exec(
                select(workbench_api_env.app_models.Finding).where(
                    workbench_api_env.app_models.Finding.project_id == project_id
                )
            ).all()
        )

    findings_by_id = {finding.id: finding for finding in findings}
    assert summary["created_findings"] == 1
    assert summary["updated_findings"] == 0
    assert len(findings) == 2
    assert findings_by_id[legacy_finding_id].dedup_key.startswith("vpw019:")
    new_finding = next(finding for finding in findings if finding.id != legacy_finding_id)
    assert new_finding.dedup_key.startswith(FINDING_SCOPE_KEY_PREFIX)

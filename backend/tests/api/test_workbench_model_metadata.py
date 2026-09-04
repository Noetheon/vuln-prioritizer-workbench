from __future__ import annotations

import importlib
import uuid
from pathlib import Path

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from sqlalchemy import create_engine, event, inspect, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import DBAPIError
from sqlmodel import Session, SQLModel, select

from app.core.migration_bootstrap import ALEMBIC_HEAD, current_alembic_head
from app.decision_core.contracts import FindingDecisionEvidenceV2, PriorityEvidenceV2
from app.domain.asset_identity import legacy_reserved_asset_storage_key
from app.domain.component_identity import component_scope_identity, component_storage_key
from app.domain.engine.models import AnalysisContext, PrioritizedFinding
from app.importers.contracts import NormalizedOccurrence
from app.models import (
    AnalysisEvidence,
    AnalysisRun,
    Asset,
    Finding,
    FindingDecisionEvidence,
    FindingOccurrence,
    GitHubIssueExport,
    Project,
    Vulnerability,
)
from app.repositories.assets import AssetRepository
from app.repositories.current_projections import FindingCurrentProjectionRepository
from app.services.analysis import WorkbenchAnalysisResult
from app.services.import_execution_persistence import _persist_workbench_occurrences
from app.services.import_execution_persistence_queries import _legacy_finding_identity_lookup

PUBLIC_MODEL_NAMES = (
    "AuditEvent",
    "AuditEventPublic",
    "AuditEventsPublic",
    "ProjectBase",
    "ProjectCreate",
    "ProjectUpdate",
    "Project",
    "ProjectPublic",
    "ProjectsPublic",
    "WorkbenchStatus",
)


def test_app_models_remains_public_aggregator_for_modular_models() -> None:
    app_models = importlib.import_module("app.models")

    exported_names = set(getattr(app_models, "__all__", ()))
    assert set(PUBLIC_MODEL_NAMES).issubset(exported_names)

    for model_name in PUBLIC_MODEL_NAMES:
        model = getattr(app_models, model_name)
        assert model.__module__.startswith("app.models.")
        assert model.__module__ != "app.models"


def test_app_models_import_registers_single_user_project_metadata() -> None:
    importlib.import_module("app.models")

    assert {"project", "audit_event"}.issubset(SQLModel.metadata.tables)
    assert {"user", "api_token", "auth_session"}.isdisjoint(SQLModel.metadata.tables)
    assert not SQLModel.metadata.tables["project"].foreign_keys


def test_workbench_alembic_head_matches_model_metadata(tmp_path: Path) -> None:
    importlib.import_module("app.models")

    config = _alembic_config(tmp_path)
    command.upgrade(config, "head")

    engine = create_engine(config.get_main_option("sqlalchemy.url"))
    try:
        with engine.connect() as connection:
            migration_context = MigrationContext.configure(connection)
            diffs = compare_metadata(migration_context, SQLModel.metadata)
            version = connection.execute(
                text("SELECT version_num FROM alembic_version")
            ).scalar_one()
    finally:
        engine.dispose()

    assert diffs == []
    assert version == ALEMBIC_HEAD


def test_workbench_migration_head_resolves_without_checked_out_alembic_ini(
    tmp_path: Path,
) -> None:
    assert current_alembic_head(tmp_path / "missing-alembic.ini") == ALEMBIC_HEAD


def test_workbench_initial_migration_is_local_single_user_schema(tmp_path: Path) -> None:
    config = _alembic_config(tmp_path)
    command.upgrade(config, "head")

    engine = create_engine(config.get_main_option("sqlalchemy.url"))
    try:
        inspector = inspect(engine)
        table_names = set(inspector.get_table_names())

        assert {
            "project",
            "audit_event",
            "analysis_run",
            "finding",
            "finding_current_projection",
            "report",
        }.issubset(table_names)
        assert {"user", "api_token", "auth_session"}.isdisjoint(table_names)
        assert "owner_id" not in {column["name"] for column in inspector.get_columns("project")}
        assert "api_token_id" not in {
            column["name"] for column in inspector.get_columns("audit_event")
        }
        assert "actor_user_id" not in {
            column["name"] for column in inspector.get_columns("audit_event")
        }
    finally:
        engine.dispose()


def test_waiver_freshness_migration_leaves_legacy_projects_stale(tmp_path: Path) -> None:
    config = _alembic_config(tmp_path)
    command.upgrade(config, "20260904_0005")
    engine = create_engine(config.get_main_option("sqlalchemy.url"))
    project_id = uuid.uuid4().hex
    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO project "
                "(name, description, id, created_at, updated_at) "
                "VALUES (:name, NULL, :id, :created_at, :updated_at)"
            ),
            {
                "name": "Legacy waiver freshness",
                "id": project_id,
                "created_at": "2026-09-03 00:00:00",
                "updated_at": "2026-09-03 00:00:00",
            },
        )
    engine.dispose()

    command.upgrade(config, "head")
    upgraded_engine = create_engine(config.get_main_option("sqlalchemy.url"))
    try:
        with upgraded_engine.connect() as connection:
            evaluated_on = connection.execute(
                text("SELECT waiver_evaluated_on FROM project WHERE id = :id"),
                {"id": project_id},
            ).scalar_one()
    finally:
        upgraded_engine.dispose()

    assert evaluated_on is None


def test_asset_identity_migration_normalizes_and_merges_legacy_aliases(
    tmp_path: Path,
) -> None:
    config = _alembic_config(tmp_path)
    command.upgrade(config, "20260710_0004")
    engine = create_engine(config.get_main_option("sqlalchemy.url"))
    asset_foreign_keys = {
        (table_name, tuple(foreign_key["constrained_columns"]))
        for table_name in inspect(engine).get_table_names()
        for foreign_key in inspect(engine).get_foreign_keys(table_name)
        if foreign_key["referred_table"] == "asset"
    }
    assert asset_foreign_keys == {
        ("finding", ("asset_id",)),
        ("waiver", ("asset_id",)),
    }
    project_id = uuid.UUID(int=1001)
    other_project_id = uuid.UUID(int=1002)
    survivor_id = uuid.UUID(int=1101)
    alias_id = uuid.UUID(int=1102)
    other_project_asset_id = uuid.UUID(int=1103)
    finding_ids = (uuid.UUID(int=1201), uuid.UUID(int=1202))
    run_id = uuid.UUID(int=1250)
    waiver_ids = (uuid.UUID(int=1301), uuid.UUID(int=1302))
    decomposed_key = "  Cafe\u0301-api  "
    composed_key = "Caf\u00e9-api"

    with Session(engine) as session:
        for current_project_id, name in (
            (project_id, "Asset identity merge"),
            (other_project_id, "Independent asset namespace"),
        ):
            session.connection().execute(
                text(
                    "INSERT INTO project "
                    "(name, description, id, created_at, updated_at) "
                    "VALUES (:name, NULL, :id, :created_at, :updated_at)"
                ),
                {
                    "name": name,
                    "id": current_project_id.hex,
                    "created_at": "2026-09-01 00:00:00",
                    "updated_at": "2026-09-01 00:00:00",
                },
            )
        session.connection().execute(
            text(
                "INSERT INTO asset "
                "(asset_key, name, target_ref, owner, business_service, environment, "
                "exposure, criticality, id, project_id, created_at, updated_at) "
                "VALUES (:asset_key, :name, :target_ref, :owner, :business_service, "
                ":environment, :exposure, :criticality, :id, :project_id, "
                ":created_at, :updated_at)"
            ),
            (
                {
                    "asset_key": decomposed_key,
                    "name": "Payments legacy survivor",
                    "target_ref": None,
                    "owner": None,
                    "business_service": "checkout",
                    "environment": "unknown",
                    "exposure": "unknown",
                    "criticality": "unknown",
                    "id": survivor_id.hex,
                    "project_id": project_id.hex,
                    "created_at": "2026-09-02 00:00:00",
                    "updated_at": "2026-09-02 00:00:00",
                },
                {
                    "asset_key": composed_key,
                    "name": "Later conflicting alias",
                    "target_ref": "payments.internal",
                    "owner": "team-payments",
                    "business_service": None,
                    "environment": "production",
                    "exposure": "internet",
                    "criticality": "high",
                    "id": alias_id.hex,
                    "project_id": project_id.hex,
                    "created_at": "2026-09-04 00:00:00",
                    "updated_at": "2026-09-04 00:00:00",
                },
                {
                    "asset_key": f"\t{decomposed_key}",
                    "name": "Other project asset",
                    "target_ref": "other.internal",
                    "owner": "team-other",
                    "business_service": "other",
                    "environment": "staging",
                    "exposure": "internal",
                    "criticality": "medium",
                    "id": other_project_asset_id.hex,
                    "project_id": other_project_id.hex,
                    "created_at": "2026-09-03 00:00:00",
                    "updated_at": "2026-09-03 00:00:00",
                },
            ),
        )
        vulnerability = Vulnerability(cve_id="CVE-2026-6005")
        session.add(vulnerability)
        session.flush()
        vulnerability_id = vulnerability.id
        session.add(
            AnalysisRun(
                id=run_id,
                project_id=project_id,
                input_type="legacy-asset-aliases",
            )
        )
        session.flush()
        for index, (finding_id, asset_id) in enumerate(
            zip(finding_ids, (survivor_id, alias_id), strict=True),
            start=1,
        ):
            session.add(
                Finding(
                    id=finding_id,
                    project_id=project_id,
                    vulnerability_id=vulnerability.id,
                    asset_id=asset_id,
                    cve_id=vulnerability.cve_id,
                    dedup_key=f"vpw019:legacy-asset-alias-{index}",
                )
            )
            raw_alias = (decomposed_key, composed_key)[index - 1]
            session.add(
                FindingOccurrence(
                    finding_id=finding_id,
                    analysis_run_id=run_id,
                    source="migration-regression",
                    evidence_json={
                        "target_kind": "host",
                        "target_ref": raw_alias,
                        "asset_id": raw_alias,
                    },
                )
            )
        session.flush()
        session.connection().execute(
            text(
                "INSERT INTO waiver "
                "(owner, reason, expires_at, cve_id, finding_id, asset_id, asset_key, "
                "service, id, project_id, created_at, updated_at) "
                "VALUES (:owner, :reason, :expires_at, NULL, NULL, :asset_id, "
                ":asset_key, NULL, :id, :project_id, :created_at, :updated_at)"
            ),
            (
                {
                    "owner": "risk-owner",
                    "reason": "Retain relational alias scope",
                    "expires_at": "2027-09-04",
                    "asset_id": alias_id.hex,
                    "asset_key": decomposed_key,
                    "id": waiver_ids[0].hex,
                    "project_id": project_id.hex,
                    "created_at": "2026-09-04 00:00:00",
                    "updated_at": "2026-09-04 00:00:00",
                },
                {
                    "owner": "risk-owner",
                    "reason": "Retain denormalized alias scope",
                    "expires_at": "2027-09-04",
                    "asset_id": None,
                    "asset_key": f"\n{decomposed_key}\t",
                    "id": waiver_ids[1].hex,
                    "project_id": project_id.hex,
                    "created_at": "2026-09-04 00:00:00",
                    "updated_at": "2026-09-04 00:00:00",
                },
            ),
        )
        session.commit()
    engine.dispose()

    command.upgrade(config, "head")
    upgraded_engine = create_engine(config.get_main_option("sqlalchemy.url"))
    try:
        with Session(upgraded_engine) as session:
            repository_asset = AssetRepository(session).get_project_asset_by_key(
                project_id,
                " \tCafe\u0301-api\n",
            )
            assert repository_asset is not None
            assert repository_asset.id == survivor_id
            legacy_lookup = _legacy_finding_identity_lookup(
                session=session,
                project_id=project_id,
                cves=["CVE-2026-6005"],
            )
        with upgraded_engine.connect() as connection:
            assets = (
                connection.execute(
                    text(
                        "SELECT id, project_id, asset_key, name, target_ref, owner, "
                        "business_service, environment, exposure, criticality, "
                        "created_at, updated_at FROM asset ORDER BY project_id, id"
                    )
                )
                .mappings()
                .all()
            )
            finding_assets = {
                uuid.UUID(str(row.id)): uuid.UUID(str(row.asset_id))
                for row in connection.execute(text("SELECT id, asset_id FROM finding ORDER BY id"))
            }
            waiver_assets = {
                uuid.UUID(str(row.id)): (
                    uuid.UUID(str(row.asset_id)) if row.asset_id is not None else None,
                    row.asset_key,
                )
                for row in connection.execute(
                    text("SELECT id, asset_id, asset_key FROM waiver ORDER BY id")
                )
            }
            foreign_key_violations = connection.exec_driver_sql("PRAGMA foreign_key_check").all()
    finally:
        upgraded_engine.dispose()

    assets_by_project = {uuid.UUID(str(row.project_id)): row for row in assets}
    survivor = assets_by_project[project_id]
    assert uuid.UUID(str(survivor.id)) == survivor_id
    assert survivor.asset_key == composed_key
    assert survivor.name == "Payments legacy survivor"
    assert survivor.target_ref == "payments.internal"
    assert survivor.owner == "team-payments"
    assert survivor.business_service == "checkout"
    assert survivor.environment == "production"
    assert survivor.exposure == "internet"
    assert survivor.criticality == "high"
    assert str(survivor.created_at).startswith("2026-09-02")
    assert str(survivor.updated_at).startswith("2026-09-04")
    assert uuid.UUID(str(assets_by_project[other_project_id].id)) == other_project_asset_id
    assert assets_by_project[other_project_id].asset_key == composed_key
    assert finding_assets == {finding_id: survivor_id for finding_id in finding_ids}
    legacy_identity = (vulnerability_id, None, "host", composed_key)
    assert legacy_lookup.matches[legacy_identity].id == finding_ids[0]
    assert legacy_identity not in legacy_lookup.ambiguous_identities
    assert waiver_assets == {
        waiver_ids[0]: (survivor_id, composed_key),
        waiver_ids[1]: (None, composed_key),
    }
    assert foreign_key_violations == []


def test_asset_identity_migration_roundtrip_preserves_reserved_legacy_reimport(
    tmp_path: Path,
) -> None:
    config = _alembic_config(tmp_path)
    command.upgrade(config, "20260710_0004")
    engine = create_engine(config.get_main_option("sqlalchemy.url"))
    project_id = uuid.uuid4()
    asset_id = uuid.uuid4()
    finding_id = uuid.uuid4()
    vulnerability_id = uuid.uuid4()
    legacy_run_id = uuid.uuid4()
    waiver_id = uuid.uuid4()
    legacy_asset_id = "vpw-asset-identity-v2:customer-db"
    target_ref = "customer-db"
    with Session(engine) as session:
        session.connection().execute(
            text(
                "INSERT INTO project "
                "(name, description, id, created_at, updated_at) "
                "VALUES (:name, NULL, :id, :created_at, :updated_at)"
            ),
            {
                "name": "Reserved legacy asset ID",
                "id": project_id.hex,
                "created_at": "2026-09-03 00:00:00",
                "updated_at": "2026-09-03 00:00:00",
            },
        )
        session.add(
            Asset(
                id=asset_id,
                project_id=project_id,
                asset_key=legacy_asset_id,
                name="Customer database",
                target_ref=target_ref,
            )
        )
        session.add(
            Vulnerability(
                id=vulnerability_id,
                cve_id="CVE-2026-6010",
                source_id="CVE-2026-6010",
                title="Reserved legacy asset ID",
            )
        )
        session.flush()
        session.add(
            Finding(
                id=finding_id,
                project_id=project_id,
                vulnerability_id=vulnerability_id,
                asset_id=asset_id,
                cve_id="CVE-2026-6010",
                dedup_key="vpw019:reserved-legacy-asset-id",
            )
        )
        session.add(
            AnalysisRun(
                id=legacy_run_id,
                project_id=project_id,
                input_type="legacy-reserved-asset",
            )
        )
        session.flush()
        session.add(
            FindingOccurrence(
                finding_id=finding_id,
                analysis_run_id=legacy_run_id,
                source="migration-regression",
                evidence_json={
                    "target_kind": "host",
                    "target_ref": target_ref,
                    "asset_id": legacy_asset_id,
                },
            )
        )
        session.connection().execute(
            text(
                "INSERT INTO waiver "
                "(owner, reason, expires_at, cve_id, finding_id, asset_id, asset_key, "
                "service, id, project_id, created_at, updated_at) "
                "VALUES (:owner, :reason, :expires_at, NULL, NULL, :asset_id, "
                ":asset_key, NULL, :id, :project_id, :created_at, :updated_at)"
            ),
            {
                "owner": "risk-owner",
                "reason": "Retain the reserved legacy asset scope",
                "expires_at": "2027-09-04",
                "asset_id": asset_id.hex,
                "asset_key": legacy_asset_id,
                "id": waiver_id.hex,
                "project_id": project_id.hex,
                "created_at": "2026-09-04 00:00:00",
                "updated_at": "2026-09-04 00:00:00",
            },
        )
        session.commit()
    engine.dispose()

    command.upgrade(config, "head")
    expected_storage_key = legacy_reserved_asset_storage_key(legacy_asset_id)
    first_upgrade_engine = create_engine(config.get_main_option("sqlalchemy.url"))
    try:
        with first_upgrade_engine.connect() as connection:
            first_asset_key = connection.execute(
                text("SELECT asset_key FROM asset WHERE id = :id"),
                {"id": asset_id.hex},
            ).scalar_one()
            first_waiver_key = connection.execute(
                text("SELECT asset_key FROM waiver WHERE id = :id"),
                {"id": waiver_id.hex},
            ).scalar_one()
    finally:
        first_upgrade_engine.dispose()

    assert first_asset_key == expected_storage_key
    assert first_waiver_key == expected_storage_key

    command.downgrade(config, "20260710_0004")
    command.upgrade(config, "head")
    upgraded_engine = create_engine(config.get_main_option("sqlalchemy.url"))
    try:
        occurrence = NormalizedOccurrence(
            cve_id="CVE-2026-6010",
            target_kind="host",
            target_ref=target_ref,
            asset_id=legacy_asset_id,
            source="migration-regression",
            raw_evidence={"source_record_id": "current-sidecar"},
        )
        decision = PrioritizedFinding(
            cve_id=occurrence.cve_id,
            priority_label="High",
            priority_rank=2,
            priority_state="Open",
            operational_score=80,
            rationale="Reserved legacy asset migration regression.",
            recommended_action="Review and remediate.",
        )
        analysis_result = WorkbenchAnalysisResult(
            findings_by_cve={occurrence.cve_id: decision},
            context=AnalysisContext(
                input_path="reserved-legacy-asset.csv",
                output_format="json",
                generated_at="2026-09-04T00:00:00Z",
            ),
            provider_snapshot_id=None,
            provider_snapshot_hash=None,
            provider_snapshot_file=None,
            locked_provider_data=False,
        )
        with Session(upgraded_engine) as session:
            migrated_asset = session.get(Asset, asset_id)
            assert migrated_asset is not None
            assert migrated_asset.asset_key == expected_storage_key
            migrated_waiver_key = session.execute(
                text("SELECT asset_key FROM waiver WHERE id = :id"),
                params={"id": waiver_id.hex},
            ).scalar_one()
            assert migrated_waiver_key == expected_storage_key
            current_run = AnalysisRun(
                project_id=project_id,
                input_type="generic-occurrence-csv",
            )
            session.add(current_run)
            session.flush()
            summary = _persist_workbench_occurrences(
                session=session,
                project_id=project_id,
                run_id=current_run.id,
                occurrences=[occurrence],
                analysis_result=analysis_result,
            )
            session.flush()
            assert migrated_asset.asset_key == expected_storage_key
            new_cve_occurrence = NormalizedOccurrence(
                cve_id="CVE-2026-6011",
                target_kind="host",
                target_ref="customer-db-replica",
                asset_id=legacy_asset_id,
                source="migration-regression",
                raw_evidence={"source_record_id": "new-cve-sidecar"},
            )
            new_cve_decision = PrioritizedFinding(
                cve_id=new_cve_occurrence.cve_id,
                priority_label="High",
                priority_rank=2,
                priority_state="Open",
                operational_score=79,
                rationale="New CVE on an escaped reserved legacy asset.",
                recommended_action="Review and remediate.",
            )
            new_cve_run = AnalysisRun(
                project_id=project_id,
                input_type="generic-occurrence-csv",
            )
            session.add(new_cve_run)
            session.flush()
            new_cve_summary = _persist_workbench_occurrences(
                session=session,
                project_id=project_id,
                run_id=new_cve_run.id,
                occurrences=[new_cve_occurrence],
                analysis_result=WorkbenchAnalysisResult(
                    findings_by_cve={new_cve_occurrence.cve_id: new_cve_decision},
                    context=AnalysisContext(
                        input_path="reserved-legacy-asset-new-cve.csv",
                        output_format="json",
                        generated_at="2026-09-04T00:01:00Z",
                    ),
                    provider_snapshot_id=None,
                    provider_snapshot_hash=None,
                    provider_snapshot_file=None,
                    locked_provider_data=False,
                ),
            )
            session.flush()
            migrated_finding = session.get(Finding, finding_id)
            new_cve_finding = session.exec(
                select(Finding).where(
                    Finding.project_id == project_id,
                    Finding.cve_id == new_cve_occurrence.cve_id,
                )
            ).one()
            asset_count = session.execute(
                text("SELECT COUNT(*) FROM asset WHERE project_id = :project_id"),
                params={"project_id": project_id.hex},
            ).scalar_one()

            assert summary["created_findings"] == 0
            assert summary["updated_findings"] == 1
            assert new_cve_summary["created_findings"] == 1
            assert new_cve_summary["updated_findings"] == 0
            assert migrated_finding is not None
            assert migrated_finding.asset_id == asset_id
            assert migrated_finding.dedup_key.startswith("vpw-finding-scope-v2:")
            assert new_cve_finding.asset_id == asset_id
            assert migrated_asset.asset_key == expected_storage_key
            assert asset_count == 1
    finally:
        upgraded_engine.dispose()


def test_asset_identity_migration_escapes_lone_canonical_looking_operator_key(
    tmp_path: Path,
) -> None:
    config = _alembic_config(tmp_path)
    command.upgrade(config, "20260710_0004")
    engine = create_engine(config.get_main_option("sqlalchemy.url"))
    project_id = uuid.uuid4()
    asset_id = uuid.uuid4()
    vulnerability_id = uuid.uuid4()
    finding_id = uuid.uuid4()
    run_id = uuid.uuid4()
    operator_asset_id = "vpw-legacy-asset-identity-v1:" + "a" * 64
    target_ref = "canonical-looking-operator-key"
    with Session(engine) as session:
        session.connection().execute(
            text(
                "INSERT INTO project "
                "(name, description, id, created_at, updated_at) "
                "VALUES (:name, NULL, :id, :created_at, :updated_at)"
            ),
            {
                "name": "Canonical-looking operator key",
                "id": project_id.hex,
                "created_at": "2026-09-03 00:00:00",
                "updated_at": "2026-09-03 00:00:00",
            },
        )
        session.add(
            Asset(
                id=asset_id,
                project_id=project_id,
                asset_key=operator_asset_id,
                name="Pre-0005 operator asset",
                target_ref=target_ref,
            )
        )
        session.add(
            Vulnerability(
                id=vulnerability_id,
                cve_id="CVE-2026-6013",
                source_id="CVE-2026-6013",
                title="Canonical-looking operator asset key",
            )
        )
        session.flush()
        session.add(
            Finding(
                id=finding_id,
                project_id=project_id,
                vulnerability_id=vulnerability_id,
                asset_id=asset_id,
                cve_id="CVE-2026-6013",
                dedup_key="canonical-looking-operator-key",
            )
        )
        session.add(
            AnalysisRun(
                id=run_id,
                project_id=project_id,
                input_type="canonical-looking-operator-key",
            )
        )
        session.flush()
        session.add(
            FindingOccurrence(
                finding_id=finding_id,
                analysis_run_id=run_id,
                source="migration-regression",
                evidence_json={
                    "target_kind": "host",
                    "target_ref": target_ref,
                    "asset_id": operator_asset_id,
                },
            )
        )
        session.commit()
    engine.dispose()

    command.upgrade(config, "head")
    expected_storage_key = legacy_reserved_asset_storage_key(operator_asset_id)
    upgraded_engine = create_engine(config.get_main_option("sqlalchemy.url"))
    try:
        occurrence = NormalizedOccurrence(
            cve_id="CVE-2026-6014",
            target_kind="host",
            target_ref="canonical-looking-operator-key-replica",
            asset_id=operator_asset_id,
            source="migration-regression",
            raw_evidence={"source_record_id": "canonical-looking-new-cve"},
        )
        decision = PrioritizedFinding(
            cve_id=occurrence.cve_id,
            priority_label="High",
            priority_rank=2,
            priority_state="Open",
            operational_score=78,
            rationale="Canonical-looking pre-v2 operator key migration regression.",
            recommended_action="Review and remediate.",
        )
        with Session(upgraded_engine) as session:
            migrated_asset = session.get(Asset, asset_id)
            assert migrated_asset is not None
            assert migrated_asset.asset_key == expected_storage_key
            current_run = AnalysisRun(
                project_id=project_id,
                input_type="generic-occurrence-csv",
            )
            session.add(current_run)
            session.flush()
            summary = _persist_workbench_occurrences(
                session=session,
                project_id=project_id,
                run_id=current_run.id,
                occurrences=[occurrence],
                analysis_result=WorkbenchAnalysisResult(
                    findings_by_cve={occurrence.cve_id: decision},
                    context=AnalysisContext(
                        input_path="canonical-looking-operator-key.csv",
                        output_format="json",
                        generated_at="2026-09-04T00:02:00Z",
                    ),
                    provider_snapshot_id=None,
                    provider_snapshot_hash=None,
                    provider_snapshot_file=None,
                    locked_provider_data=False,
                ),
            )
            session.flush()
            new_finding = session.exec(
                select(Finding).where(
                    Finding.project_id == project_id,
                    Finding.cve_id == occurrence.cve_id,
                )
            ).one()
            asset_count = session.execute(
                text("SELECT COUNT(*) FROM asset WHERE project_id = :project_id"),
                params={"project_id": project_id.hex},
            ).scalar_one()
            assert summary["created_findings"] == 1
            assert new_finding.asset_id == asset_id
            assert asset_count == 1
            session.commit()
    finally:
        upgraded_engine.dispose()

    command.downgrade(config, "20260710_0004")
    command.upgrade(config, "head")
    roundtrip_engine = create_engine(config.get_main_option("sqlalchemy.url"))
    try:
        with roundtrip_engine.connect() as connection:
            roundtrip_key = connection.execute(
                text("SELECT asset_key FROM asset WHERE id = :id"),
                {"id": asset_id.hex},
            ).scalar_one()
            foreign_key_violations = connection.exec_driver_sql("PRAGMA foreign_key_check").all()
    finally:
        roundtrip_engine.dispose()

    assert roundtrip_key == expected_storage_key
    assert foreign_key_violations == []


def test_asset_identity_migration_roundtrip_preserves_native_identity_and_waiver_key(
    tmp_path: Path,
) -> None:
    config = _alembic_config(tmp_path)
    command.upgrade(config, "head")
    engine = create_engine(config.get_main_option("sqlalchemy.url"))
    project_id = uuid.uuid4()
    asset_id = uuid.uuid4()
    waiver_id = uuid.uuid4()
    native_identity_key = "vpw-asset-identity-v2:" + "b" * 64
    with Session(engine) as session:
        session.add(Project(id=project_id, name="Native identity downgrade roundtrip"))
        session.add(
            Asset(
                id=asset_id,
                project_id=project_id,
                asset_key=native_identity_key,
                name="Native internal identity",
            )
        )
        session.flush()
        session.connection().execute(
            text(
                "INSERT INTO waiver "
                "(owner, reason, expires_at, cve_id, finding_id, asset_id, asset_key, "
                "service, id, project_id, created_at, updated_at) "
                "VALUES (:owner, :reason, :expires_at, NULL, NULL, :asset_id, "
                ":asset_key, NULL, :id, :project_id, :created_at, :updated_at)"
            ),
            {
                "owner": "risk-owner",
                "reason": "Retain native internal asset scope",
                "expires_at": "2027-09-04",
                "asset_id": asset_id.hex,
                "asset_key": native_identity_key,
                "id": waiver_id.hex,
                "project_id": project_id.hex,
                "created_at": "2026-09-04 00:00:00",
                "updated_at": "2026-09-04 00:00:00",
            },
        )
        session.commit()
    engine.dispose()

    command.downgrade(config, "20260710_0004")
    downgraded_engine = create_engine(config.get_main_option("sqlalchemy.url"))
    try:
        with downgraded_engine.connect() as connection:
            downgraded_asset_key = connection.execute(
                text("SELECT asset_key FROM asset WHERE id = :id"),
                {"id": asset_id.hex},
            ).scalar_one()
            downgraded_waiver_key = connection.execute(
                text("SELECT asset_key FROM waiver WHERE id = :id"),
                {"id": waiver_id.hex},
            ).scalar_one()
    finally:
        downgraded_engine.dispose()

    assert downgraded_asset_key != native_identity_key
    assert downgraded_asset_key.startswith(
        "vpw-legacy-asset-identity-v1:migration-0005-downgrade-v1:"
    )
    assert downgraded_waiver_key == downgraded_asset_key
    assert len(downgraded_asset_key) <= 200

    command.upgrade(config, "head")
    upgraded_engine = create_engine(config.get_main_option("sqlalchemy.url"))
    try:
        with upgraded_engine.connect() as connection:
            restored_asset_key = connection.execute(
                text("SELECT asset_key FROM asset WHERE id = :id"),
                {"id": asset_id.hex},
            ).scalar_one()
            restored_waiver_key = connection.execute(
                text("SELECT asset_key FROM waiver WHERE id = :id"),
                {"id": waiver_id.hex},
            ).scalar_one()
            foreign_key_violations = connection.exec_driver_sql("PRAGMA foreign_key_check").all()
    finally:
        upgraded_engine.dispose()

    assert restored_asset_key == native_identity_key
    assert restored_waiver_key == native_identity_key
    assert foreign_key_violations == []


def test_asset_identity_migration_escapes_genuine_downgrade_marker_prefix(
    tmp_path: Path,
) -> None:
    config = _alembic_config(tmp_path)
    command.upgrade(config, "20260710_0004")
    engine = create_engine(config.get_main_option("sqlalchemy.url"))
    project_id = uuid.uuid4()
    asset_id = uuid.uuid4()
    operator_asset_id = "vpw-legacy-asset-identity-v1:migration-0005-downgrade-v1:operator-key"
    with Session(engine) as session:
        session.connection().execute(
            text(
                "INSERT INTO project "
                "(name, description, id, created_at, updated_at) "
                "VALUES (:name, NULL, :id, :created_at, :updated_at)"
            ),
            {
                "name": "Genuine marker-prefix operator key",
                "id": project_id.hex,
                "created_at": "2026-09-03 00:00:00",
                "updated_at": "2026-09-03 00:00:00",
            },
        )
        session.add(
            Asset(
                id=asset_id,
                project_id=project_id,
                asset_key=operator_asset_id,
                name="Genuine marker-prefix operator asset",
            )
        )
        session.commit()
    engine.dispose()

    command.upgrade(config, "head")
    upgraded_engine = create_engine(config.get_main_option("sqlalchemy.url"))
    try:
        with upgraded_engine.connect() as connection:
            migrated_key = connection.execute(
                text("SELECT asset_key FROM asset WHERE id = :id"),
                {"id": asset_id.hex},
            ).scalar_one()
    finally:
        upgraded_engine.dispose()

    assert migrated_key == legacy_reserved_asset_storage_key(operator_asset_id)


def test_asset_identity_migration_stages_overlapping_escaped_keys_without_fk_loss(
    tmp_path: Path,
) -> None:
    config = _alembic_config(tmp_path)
    command.upgrade(config, "20260710_0004")
    engine = create_engine(config.get_main_option("sqlalchemy.url"))
    project_id = uuid.uuid4()
    vulnerability_id = uuid.uuid4()
    source_asset_id = uuid.UUID(int=1601)
    overlapping_asset_id = uuid.UUID(int=1602)
    source_finding_id = uuid.UUID(int=1603)
    overlapping_finding_id = uuid.UUID(int=1604)
    source_key = "vpw-asset-identity-v2:customer-db"
    overlapping_key = legacy_reserved_asset_storage_key(source_key)
    with Session(engine) as session:
        session.connection().execute(
            text(
                "INSERT INTO project "
                "(name, description, id, created_at, updated_at) "
                "VALUES (:name, NULL, :id, :created_at, :updated_at)"
            ),
            {
                "name": "Overlapping escaped asset keys",
                "id": project_id.hex,
                "created_at": "2026-09-03 00:00:00",
                "updated_at": "2026-09-03 00:00:00",
            },
        )
        session.add_all(
            [
                Asset(
                    id=source_asset_id,
                    project_id=project_id,
                    asset_key=source_key,
                    name="Source reserved key",
                ),
                Asset(
                    id=overlapping_asset_id,
                    project_id=project_id,
                    asset_key=overlapping_key,
                    name="Existing escaped-looking key",
                ),
                Vulnerability(
                    id=vulnerability_id,
                    cve_id="CVE-2026-6012",
                    source_id="CVE-2026-6012",
                    title="Overlapping escaped keys",
                ),
            ]
        )
        session.flush()
        session.add_all(
            [
                Finding(
                    id=source_finding_id,
                    project_id=project_id,
                    vulnerability_id=vulnerability_id,
                    asset_id=source_asset_id,
                    cve_id="CVE-2026-6012",
                    dedup_key="overlapping-escaped-source",
                ),
                Finding(
                    id=overlapping_finding_id,
                    project_id=project_id,
                    vulnerability_id=vulnerability_id,
                    asset_id=overlapping_asset_id,
                    cve_id="CVE-2026-6012",
                    dedup_key="overlapping-escaped-existing",
                ),
            ]
        )
        session.commit()
    engine.dispose()

    command.upgrade(config, "head")
    upgraded_engine = create_engine(config.get_main_option("sqlalchemy.url"))
    try:
        with upgraded_engine.connect() as connection:
            asset_keys = {
                uuid.UUID(str(row.id)): row.asset_key
                for row in connection.execute(text("SELECT id, asset_key FROM asset"))
            }
            finding_assets = {
                uuid.UUID(str(row.id)): uuid.UUID(str(row.asset_id))
                for row in connection.execute(text("SELECT id, asset_id FROM finding"))
            }
            foreign_key_violations = connection.exec_driver_sql("PRAGMA foreign_key_check").all()
    finally:
        upgraded_engine.dispose()

    assert asset_keys == {
        source_asset_id: overlapping_key,
        overlapping_asset_id: legacy_reserved_asset_storage_key(overlapping_key),
    }
    assert finding_assets == {
        source_finding_id: source_asset_id,
        overlapping_finding_id: overlapping_asset_id,
    }
    assert foreign_key_violations == []


def test_github_export_identity_migration_preserves_history_and_prefers_completed_link(
    tmp_path: Path,
) -> None:
    config = _alembic_config(tmp_path)
    command.upgrade(config, "20260904_0006")
    engine = create_engine(config.get_main_option("sqlalchemy.url"))
    project_id = uuid.uuid4()
    vulnerability_id = uuid.uuid4()
    finding_id = uuid.uuid4()
    incomplete_id = uuid.UUID(int=2)
    completed_id = uuid.UUID(int=1)
    with Session(engine) as session:
        session.add(Project(id=project_id, name="GitHub identity migration"))
        session.add(
            Vulnerability(
                id=vulnerability_id,
                cve_id="CVE-2299-2700",
                source_id="CVE-2299-2700",
                title="GitHub identity migration",
            )
        )
        session.flush()
        session.add(
            Finding(
                id=finding_id,
                project_id=project_id,
                vulnerability_id=vulnerability_id,
                cve_id="CVE-2299-2700",
                dedup_key="github-identity-migration",
            )
        )
        session.flush()
        session.add_all(
            [
                GitHubIssueExport(
                    id=incomplete_id,
                    project_id=project_id,
                    finding_id=finding_id,
                    repository="Acme/Workbench",
                    duplicate_key="stable-key",
                    title="Older incomplete reservation",
                    issue_url="",
                    issue_number=0,
                ),
                GitHubIssueExport(
                    id=completed_id,
                    project_id=project_id,
                    finding_id=finding_id,
                    repository="acme/workbench",
                    duplicate_key="stable-key",
                    title="Completed export",
                    issue_url="https://github.com/acme/workbench/issues/27",
                    issue_number=27,
                ),
            ]
        )
        session.commit()
    engine.dispose()

    command.upgrade(config, "head")
    upgraded_engine = create_engine(config.get_main_option("sqlalchemy.url"))
    try:
        inspector = inspect(upgraded_engine)
        unique_constraints = {
            constraint["name"]
            for constraint in inspector.get_unique_constraints("github_issue_export")
        }
        with upgraded_engine.connect() as connection:
            rows = (
                connection.execute(
                    text(
                        "SELECT id, finding_id, repository, duplicate_key, issue_url, issue_number "
                        "FROM github_issue_export "
                        "WHERE project_id = :project_id ORDER BY id"
                    ),
                    {"project_id": project_id.hex},
                )
                .mappings()
                .all()
            )
    finally:
        upgraded_engine.dispose()

    assert "uq_github_issue_export_project_repository_finding" in unique_constraints
    assert len(rows) == 2
    rows_by_id = {row["id"]: row for row in rows}
    assert rows_by_id[completed_id.hex]["finding_id"] == finding_id.hex
    assert rows_by_id[completed_id.hex]["repository"] == "acme/workbench"
    assert rows_by_id[completed_id.hex]["duplicate_key"] == "stable-key"
    assert rows_by_id[completed_id.hex]["issue_number"] == 27
    assert rows_by_id[incomplete_id.hex]["finding_id"] is None
    assert rows_by_id[incomplete_id.hex]["repository"] == "acme/workbench"
    assert ":legacy-case-alias:" in rows_by_id[incomplete_id.hex]["duplicate_key"]
    assert rows_by_id[incomplete_id.hex]["issue_url"] is None
    assert rows_by_id[incomplete_id.hex]["issue_number"] is None


def test_github_export_finding_fk_migration_cascades_and_downgrades_cleanly(
    tmp_path: Path,
) -> None:
    config = _alembic_config(tmp_path)
    command.upgrade(config, "head")

    engine = create_engine(config.get_main_option("sqlalchemy.url"))
    try:
        finding_foreign_key = next(
            item
            for item in inspect(engine).get_foreign_keys("github_issue_export")
            if item["constrained_columns"] == ["finding_id"]
        )
        assert finding_foreign_key["options"].get("ondelete") == "CASCADE"
    finally:
        engine.dispose()

    command.downgrade(config, "20260904_0007")
    downgraded_engine = create_engine(config.get_main_option("sqlalchemy.url"))
    try:
        finding_foreign_key = next(
            item
            for item in inspect(downgraded_engine).get_foreign_keys("github_issue_export")
            if item["constrained_columns"] == ["finding_id"]
        )
        assert finding_foreign_key["options"].get("ondelete") is None
    finally:
        downgraded_engine.dispose()

    command.upgrade(config, "head")


@pytest.mark.parametrize(
    ("start_revision", "operation", "target_revision", "expected_revision"),
    (
        (
            "20260904_0007",
            "upgrade",
            "head",
            ALEMBIC_HEAD,
        ),
        (
            "20260904_0008",
            "downgrade",
            "20260904_0007",
            "20260904_0007",
        ),
        (
            "20260904_0007",
            "downgrade",
            "20260904_0006",
            "20260904_0006",
        ),
    ),
    ids=("0008-upgrade", "0008-downgrade", "0007-downgrade"),
)
def test_github_export_batch_migrations_roll_back_ddl_and_allow_retry(
    tmp_path: Path,
    start_revision: str,
    operation: str,
    target_revision: str,
    expected_revision: str,
) -> None:
    config = _alembic_config(tmp_path)
    command.upgrade(config, start_revision)
    initial_revision = ALEMBIC_HEAD if start_revision == "head" else start_revision
    injected = False

    def fail_before_source_table_drop(
        _connection: object,
        _cursor: object,
        statement: str,
        _parameters: object,
        _context: object,
        _executemany: bool,
    ) -> None:
        nonlocal injected
        normalized = " ".join(statement.split()).replace('"', "").casefold().rstrip(";")
        if not injected and normalized == "drop table github_issue_export":
            injected = True
            raise RuntimeError("injected GitHub export batch migration failure")

    event.listen(Engine, "before_cursor_execute", fail_before_source_table_drop)
    try:
        with pytest.raises(
            RuntimeError,
            match="injected GitHub export batch migration failure",
        ):
            _run_alembic_operation(config, operation, target_revision)
    finally:
        event.remove(Engine, "before_cursor_execute", fail_before_source_table_drop)

    assert injected is True
    engine = create_engine(config.get_main_option("sqlalchemy.url"))
    try:
        table_names = set(inspect(engine).get_table_names())
        with engine.connect() as connection:
            revision_after_failure = connection.execute(
                text("SELECT version_num FROM alembic_version")
            ).scalar_one()
    finally:
        engine.dispose()

    assert revision_after_failure == initial_revision
    assert "github_issue_export" in table_names
    assert "_alembic_tmp_github_issue_export" not in table_names

    _run_alembic_operation(config, operation, target_revision)
    retried_engine = create_engine(config.get_main_option("sqlalchemy.url"))
    try:
        with retried_engine.connect() as connection:
            revision_after_retry = connection.execute(
                text("SELECT version_num FROM alembic_version")
            ).scalar_one()
    finally:
        retried_engine.dispose()

    assert revision_after_retry == expected_revision


def test_component_identity_migration_backfills_indexed_canonical_material(
    tmp_path: Path,
) -> None:
    config = _alembic_config(tmp_path)
    command.upgrade(config, "20260710_0004")
    engine = create_engine(config.get_main_option("sqlalchemy.url"))
    component_id = uuid.uuid4().hex
    with engine.begin() as connection:
        connection.exec_driver_sql(
            "INSERT INTO component "
            "(name, version, purl, ecosystem, package_type, id, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                " Cafe\u0301 ",
                "3.0.0",
                None,
                "DEB",
                None,
                component_id,
                "2026-09-04 00:00:00",
                "2026-09-04 00:00:00",
            ),
        )
    engine.dispose()

    command.upgrade(config, "head")
    upgraded_engine = create_engine(config.get_main_option("sqlalchemy.url"))
    try:
        with upgraded_engine.connect() as connection:
            row = (
                connection.execute(
                    text("SELECT identity_key, identity_material FROM component WHERE id = :id"),
                    {"id": component_id},
                )
                .mappings()
                .one()
            )
    finally:
        upgraded_engine.dispose()

    material = component_scope_identity(
        component_name="Caf\u00e9",
        component_version="3.0.0",
        package_type="deb",
    )
    assert material is not None
    assert row["identity_material"] == material
    assert row["identity_key"] == component_storage_key(material)


def test_component_identity_migration_merges_legacy_aliases_without_losing_ledger(
    tmp_path: Path,
) -> None:
    config = _alembic_config(tmp_path)
    command.upgrade(config, "20260612_0003")
    engine = create_engine(config.get_main_option("sqlalchemy.url"))
    project_id = uuid.uuid4()
    run_id = uuid.uuid4()
    coordinate_survivor = uuid.UUID(int=1)
    coordinate_tie_loser = uuid.UUID(int=3)
    coordinate_later = uuid.UUID(int=2)
    purl_survivor = uuid.UUID(int=10)
    purl_later = uuid.UUID(int=11)
    legacy_components = (
        (
            coordinate_survivor,
            "STRASSE",
            "1.0",
            None,
            "GENERIC",
            "2026-09-03 00:00:00",
        ),
        (
            coordinate_tie_loser,
            "Straße",
            "1.0",
            None,
            "generic",
            "2026-09-03 00:00:00",
        ),
        (
            coordinate_later,
            " strasse ",
            "1.0",
            None,
            " Generic ",
            "2026-09-04 00:00:00",
        ),
        (
            purl_survivor,
            "Django",
            "4.2",
            "pkg:pypi/Django@4.2",
            "pypi",
            "2026-09-02 00:00:00",
        ),
        (
            purl_later,
            "django",
            "4.2",
            "pkg:pypi/django@4.2",
            "PyPI",
            "2026-09-04 00:00:00",
        ),
    )
    expected_component_by_legacy_id = {
        coordinate_survivor: coordinate_survivor,
        coordinate_tie_loser: coordinate_survivor,
        coordinate_later: coordinate_survivor,
        purl_survivor: purl_survivor,
        purl_later: purl_survivor,
    }
    finding_component_pairs: list[tuple[uuid.UUID, uuid.UUID]] = []
    with Session(engine) as session:
        session.connection().execute(
            text(
                "INSERT INTO project "
                "(name, description, id, created_at, updated_at) "
                "VALUES (:name, NULL, :id, :created_at, :updated_at)"
            ),
            {
                "name": "Component identity merge",
                "id": project_id.hex,
                "created_at": "2026-09-02 00:00:00",
                "updated_at": "2026-09-02 00:00:00",
            },
        )
        for component_id, name, version, purl, ecosystem, created_at in legacy_components:
            session.connection().execute(
                text(
                    "INSERT INTO component "
                    "(name, version, purl, ecosystem, package_type, id, created_at, updated_at) "
                    "VALUES (:name, :version, :purl, :ecosystem, NULL, :id, "
                    ":created_at, :created_at)"
                ),
                {
                    "name": name,
                    "version": version,
                    "purl": purl,
                    "ecosystem": ecosystem,
                    "id": component_id.hex,
                    "created_at": created_at,
                },
            )
        vulnerability = Vulnerability(cve_id="CVE-2026-5005")
        session.add(vulnerability)
        session.flush()
        vulnerability_id = vulnerability.id
        run = AnalysisRun(id=run_id, project_id=project_id, input_type="component-merge")
        session.add(run)
        session.flush()
        analysis_evidence = AnalysisEvidence(
            project_id=project_id,
            analysis_run_id=run_id,
            payload_json={"migration": "component-alias-merge"},
        )
        session.add(analysis_evidence)
        session.flush()

        for index, component in enumerate(legacy_components, start=1):
            component_id, name, version, purl, _ecosystem, _created_at = component
            finding_id = uuid.UUID(int=100 + index)
            finding = Finding(
                id=finding_id,
                project_id=project_id,
                vulnerability_id=vulnerability.id,
                component_id=component_id,
                cve_id=vulnerability.cve_id,
                dedup_key=f"vpw019:legacy-component-{index}",
            )
            session.add(finding)
            session.flush()
            session.add(
                FindingOccurrence(
                    id=uuid.UUID(int=200 + index),
                    finding_id=finding_id,
                    analysis_run_id=run_id,
                    source="migration-regression",
                    evidence_json={
                        "component_name": name,
                        "component_version": version,
                        "purl": purl,
                    },
                )
            )
            contract = FindingDecisionEvidenceV2(
                finding_id=str(finding_id),
                analysis_run_id=str(run_id),
                project_id=str(project_id),
                cve_id=finding.cve_id,
                dedup_key=finding.dedup_key,
                status="open",
                priority="high",
                priority_rank=2,
                risk_score=80.0 + index,
                operational_rank=index,
                occurrence_scope={
                    "component_name": name,
                    "component_version": version,
                    "purl": purl,
                },
                priority_evidence=PriorityEvidenceV2(
                    priority_label="High",
                    priority_rank=2,
                ),
            )
            session.add(
                FindingDecisionEvidence(
                    id=uuid.UUID(int=300 + index),
                    analysis_evidence_id=analysis_evidence.id,
                    project_id=project_id,
                    analysis_run_id=run_id,
                    finding_id=finding_id,
                    cve_id=finding.cve_id,
                    dedup_key=finding.dedup_key,
                    priority=contract.priority,
                    status=contract.status,
                    payload_json=contract.to_jsonable(),
                )
            )
            finding_component_pairs.append((finding_id, component_id))
        exported_finding_id, exported_component_id = finding_component_pairs[1]
        session.add(
            GitHubIssueExport(
                id=uuid.UUID(int=401),
                project_id=project_id,
                finding_id=exported_finding_id,
                repository="acme/component-migration",
                duplicate_key=(
                    f"{project_id}:{exported_finding_id}:{vulnerability.cve_id}:"
                    f"no-asset:{exported_component_id}"
                ),
                title="Existing issue for canonical component alias",
                issue_url="https://github.com/acme/component-migration/issues/5",
                issue_number=5,
            )
        )
        session.commit()
    engine.dispose()

    command.upgrade(config, "20260710_0004")
    baseline = _component_merge_evidence_snapshot(config)
    assert len(baseline["components"]) == len(legacy_components)
    assert len(baseline["findings"]) == len(legacy_components)
    assert len(baseline["occurrences"]) == len(legacy_components)
    assert len(baseline["evidence"]) == len(legacy_components)
    assert len(baseline["projections"]) == len(legacy_components)
    assert len(baseline["github_exports"]) == 1

    command.upgrade(config, "head")
    _assert_component_merge_state(
        config,
        baseline=baseline,
        finding_component_pairs=finding_component_pairs,
        expected_component_by_legacy_id=expected_component_by_legacy_id,
        identity_columns_expected=True,
    )
    head_engine = create_engine(config.get_main_option("sqlalchemy.url"))
    try:
        with Session(head_engine) as session:
            lookup = _legacy_finding_identity_lookup(
                session=session,
                project_id=project_id,
                cves=["CVE-2026-5005"],
            )
    finally:
        head_engine.dispose()
    coordinate_identity = (vulnerability_id, coordinate_survivor, "generic", None)
    purl_identity = (vulnerability_id, purl_survivor, "generic", None)
    assert lookup.matches[coordinate_identity].id == finding_component_pairs[0][0]
    assert lookup.matches[purl_identity].id == finding_component_pairs[3][0]
    assert not lookup.ambiguous_identities

    command.downgrade(config, "20260710_0004")
    _assert_component_merge_state(
        config,
        baseline=baseline,
        finding_component_pairs=finding_component_pairs,
        expected_component_by_legacy_id=expected_component_by_legacy_id,
        identity_columns_expected=False,
    )

    command.upgrade(config, "head")
    _assert_component_merge_state(
        config,
        baseline=baseline,
        finding_component_pairs=finding_component_pairs,
        expected_component_by_legacy_id=expected_component_by_legacy_id,
        identity_columns_expected=True,
    )


def test_component_identity_migration_rolls_back_merge_and_ddl_together(
    tmp_path: Path,
) -> None:
    config = _alembic_config(tmp_path)
    command.upgrade(config, "20260710_0004")
    engine = create_engine(config.get_main_option("sqlalchemy.url"))
    project_id = uuid.uuid4()
    survivor_id = uuid.UUID(int=501)
    duplicate_id = uuid.UUID(int=502)
    asset_survivor_id = uuid.UUID(int=701)
    asset_duplicate_id = uuid.UUID(int=702)
    waiver_id = uuid.UUID(int=703)
    finding_ids = (uuid.UUID(int=601), uuid.UUID(int=602))
    with Session(engine) as session:
        session.connection().execute(
            text(
                "INSERT INTO project "
                "(name, description, id, created_at, updated_at) "
                "VALUES (:name, NULL, :id, :created_at, :updated_at)"
            ),
            {
                "name": "Atomic component merge",
                "id": project_id.hex,
                "created_at": "2026-09-04 00:00:00",
                "updated_at": "2026-09-04 00:00:00",
            },
        )
        for component_id, name, ecosystem in (
            (survivor_id, "ALPHA", "generic"),
            (duplicate_id, "alpha", "GENERIC"),
        ):
            session.connection().execute(
                text(
                    "INSERT INTO component "
                    "(name, version, purl, ecosystem, package_type, id, created_at, updated_at) "
                    "VALUES (:name, '1.0', NULL, :ecosystem, NULL, :id, "
                    "'2026-09-04 00:00:00', '2026-09-04 00:00:00')"
                ),
                {
                    "name": name,
                    "ecosystem": ecosystem,
                    "id": component_id.hex,
                },
            )
        session.connection().execute(
            text(
                "INSERT INTO asset "
                "(asset_key, name, environment, exposure, criticality, id, project_id, "
                "created_at, updated_at) VALUES (:asset_key, :name, 'unknown', 'unknown', "
                "'unknown', :id, :project_id, :created_at, :updated_at)"
            ),
            (
                {
                    "asset_key": "  Cafe\u0301-atomic  ",
                    "name": "Atomic asset survivor",
                    "id": asset_survivor_id.hex,
                    "project_id": project_id.hex,
                    "created_at": "2026-09-03 00:00:00",
                    "updated_at": "2026-09-03 00:00:00",
                },
                {
                    "asset_key": "Caf\u00e9-atomic",
                    "name": "Atomic asset alias",
                    "id": asset_duplicate_id.hex,
                    "project_id": project_id.hex,
                    "created_at": "2026-09-04 00:00:00",
                    "updated_at": "2026-09-04 00:00:00",
                },
            ),
        )
        vulnerability = Vulnerability(cve_id="CVE-2026-5505")
        session.add(vulnerability)
        session.flush()
        for index, (finding_id, component_id, asset_id) in enumerate(
            zip(
                finding_ids,
                (survivor_id, duplicate_id),
                (asset_survivor_id, asset_duplicate_id),
                strict=True,
            ),
            start=1,
        ):
            session.add(
                Finding(
                    id=finding_id,
                    project_id=project_id,
                    vulnerability_id=vulnerability.id,
                    component_id=component_id,
                    asset_id=asset_id,
                    cve_id=vulnerability.cve_id,
                    dedup_key=f"atomic-component-{index}",
                )
            )
        session.flush()
        session.connection().execute(
            text(
                "INSERT INTO waiver "
                "(owner, reason, expires_at, asset_id, asset_key, id, project_id, "
                "created_at, updated_at) VALUES ('risk-owner', 'Atomic asset alias', "
                "'2027-09-04', :asset_id, :asset_key, :id, :project_id, "
                "'2026-09-04 00:00:00', '2026-09-04 00:00:00')"
            ),
            {
                "asset_id": asset_duplicate_id.hex,
                "asset_key": "  Cafe\u0301-atomic  ",
                "id": waiver_id.hex,
                "project_id": project_id.hex,
            },
        )
        session.commit()

    with engine.begin() as connection:
        connection.exec_driver_sql(
            f"""
            CREATE TRIGGER fail_component_identity_backfill
            BEFORE UPDATE ON component
            WHEN OLD.id = '{survivor_id.hex}'
            BEGIN
                SELECT RAISE(ABORT, 'forced identity backfill failure');
            END
            """
        )
    engine.dispose()

    with pytest.raises(DBAPIError, match="forced identity backfill failure"):
        command.upgrade(config, "head")

    failed_engine = create_engine(config.get_main_option("sqlalchemy.url"))
    try:
        component_columns = {
            column["name"] for column in inspect(failed_engine).get_columns("component")
        }
        with failed_engine.connect() as connection:
            component_ids = {
                uuid.UUID(str(row.id))
                for row in connection.execute(text("SELECT id FROM component"))
            }
            finding_components = {
                uuid.UUID(str(row.id)): uuid.UUID(str(row.component_id))
                for row in connection.execute(text("SELECT id, component_id FROM finding"))
            }
            asset_keys = {
                uuid.UUID(str(row.id)): row.asset_key
                for row in connection.execute(text("SELECT id, asset_key FROM asset"))
            }
            finding_assets = {
                uuid.UUID(str(row.id)): uuid.UUID(str(row.asset_id))
                for row in connection.execute(text("SELECT id, asset_id FROM finding"))
            }
            waiver_asset = connection.execute(
                text("SELECT asset_id, asset_key FROM waiver WHERE id = :id"),
                {"id": waiver_id.hex},
            ).one()
            version = connection.execute(
                text("SELECT version_num FROM alembic_version")
            ).scalar_one()
            foreign_key_violations = connection.exec_driver_sql("PRAGMA foreign_key_check").all()
    finally:
        failed_engine.dispose()

    assert component_ids == {survivor_id, duplicate_id}
    assert finding_components == dict(zip(finding_ids, (survivor_id, duplicate_id), strict=True))
    assert asset_keys == {
        asset_survivor_id: "  Cafe\u0301-atomic  ",
        asset_duplicate_id: "Caf\u00e9-atomic",
    }
    assert finding_assets == dict(
        zip(finding_ids, (asset_survivor_id, asset_duplicate_id), strict=True)
    )
    assert uuid.UUID(str(waiver_asset.asset_id)) == asset_duplicate_id
    assert waiver_asset.asset_key == "  Cafe\u0301-atomic  "
    assert {"identity_key", "identity_material"}.isdisjoint(component_columns)
    assert version == "20260710_0004"
    assert foreign_key_violations == []


def _component_merge_evidence_snapshot(
    config: Config,
) -> dict[str, tuple[tuple[object, ...], ...]]:
    engine = create_engine(config.get_main_option("sqlalchemy.url"))
    queries = {
        "components": (
            "SELECT id, name, version, purl, ecosystem, package_type, created_at, updated_at "
            "FROM component ORDER BY id"
        ),
        "finding_core": (
            "SELECT id, project_id, vulnerability_id, asset_id, cve_id, dedup_key, status, "
            "first_seen_at, last_seen_at, created_at, updated_at FROM finding ORDER BY id"
        ),
        "findings": "SELECT id, component_id FROM finding ORDER BY id",
        "occurrences": (
            "SELECT id, finding_id, analysis_run_id, source, scanner, raw_reference, "
            "fix_version, evidence_json FROM finding_occurrence ORDER BY id"
        ),
        "analysis_evidence": (
            "SELECT id, project_id, analysis_run_id, provider_snapshot_id, schema_version, "
            "payload_json, diagnostics_json, created_at, updated_at "
            "FROM analysis_evidence ORDER BY id"
        ),
        "evidence": (
            "SELECT id, analysis_evidence_id, project_id, analysis_run_id, finding_id, "
            "schema_version, cve_id, dedup_key, priority, status, payload_json, "
            "created_at, updated_at FROM finding_decision_evidence ORDER BY id"
        ),
        "projections": (
            "SELECT finding_id, project_id, source_analysis_run_id, "
            "source_finding_evidence_id, source_created_at, cve_id, dedup_key, priority, "
            "status, priority_rank, risk_score, operational_rank, in_kev, epss, "
            "cvss_base_score, attack_mapped, suppressed_by_vex, under_investigation, "
            "waived, rationale, recommended_action, lifecycle_overlay_json, "
            "source_payload_sha256, projection_payload_sha256, revision, "
            "lifecycle_revision, created_at, updated_at "
            "FROM finding_current_projection ORDER BY finding_id"
        ),
        "github_exports": (
            "SELECT id, project_id, finding_id, repository, duplicate_key, title, "
            "issue_url, issue_number, created_at FROM github_issue_export ORDER BY id"
        ),
    }
    try:
        with engine.connect() as connection:
            return {
                name: tuple(tuple(row) for row in connection.execute(text(statement)))
                for name, statement in queries.items()
            }
    finally:
        engine.dispose()


def _assert_component_merge_state(
    config: Config,
    *,
    baseline: dict[str, tuple[tuple[object, ...], ...]],
    finding_component_pairs: list[tuple[uuid.UUID, uuid.UUID]],
    expected_component_by_legacy_id: dict[uuid.UUID, uuid.UUID],
    identity_columns_expected: bool,
) -> None:
    snapshot = _component_merge_evidence_snapshot(config)
    for preserved_table in (
        "finding_core",
        "occurrences",
        "analysis_evidence",
        "evidence",
        "projections",
        "github_exports",
    ):
        assert snapshot[preserved_table] == baseline[preserved_table]

    engine = create_engine(config.get_main_option("sqlalchemy.url"))
    try:
        inspector = inspect(engine)
        component_columns = {column["name"] for column in inspector.get_columns("component")}
        unique_constraints = {
            constraint["name"] for constraint in inspector.get_unique_constraints("component")
        }
        with engine.connect() as connection:
            components = connection.execute(
                text("SELECT id, name, purl FROM component ORDER BY id")
            ).all()
            finding_components = {
                uuid.UUID(str(row.id)): uuid.UUID(str(row.component_id))
                for row in connection.execute(
                    text("SELECT id, component_id FROM finding ORDER BY id")
                )
            }
            foreign_key_violations = connection.exec_driver_sql("PRAGMA foreign_key_check").all()
            version = connection.execute(
                text("SELECT version_num FROM alembic_version")
            ).scalar_one()
            if identity_columns_expected:
                identities = connection.execute(
                    text("SELECT identity_key, identity_material FROM component ORDER BY id")
                ).all()
            else:
                identities = []
        parity = None
        if identity_columns_expected:
            with Session(engine) as session:
                parity = FindingCurrentProjectionRepository(session).verify_all_source_parity()
    finally:
        engine.dispose()

    component_by_id = {uuid.UUID(str(row.id)): (row.name, row.purl) for row in components}
    assert component_by_id == {
        uuid.UUID(int=1): ("STRASSE", None),
        uuid.UUID(int=10): ("Django", "pkg:pypi/Django@4.2"),
    }
    assert finding_components == {
        finding_id: expected_component_by_legacy_id[legacy_component_id]
        for finding_id, legacy_component_id in finding_component_pairs
    }
    assert foreign_key_violations == []
    if identity_columns_expected:
        assert parity is not None
        assert parity.checked == len(finding_component_pairs)
        assert parity.matches is True
        assert {"identity_key", "identity_material"}.issubset(component_columns)
        assert "uq_component_identity_key" in unique_constraints
        assert "uq_component_identity" not in unique_constraints
        assert "uq_component_purl" not in unique_constraints
        assert len(identities) == 2
        assert len({row.identity_key for row in identities}) == 2
        assert all(row.identity_material for row in identities)
        assert version == ALEMBIC_HEAD
    else:
        assert {"identity_key", "identity_material"}.isdisjoint(component_columns)
        assert "uq_component_identity_key" not in unique_constraints
        assert {"uq_component_identity", "uq_component_purl"}.issubset(unique_constraints)
        assert version == "20260710_0004"


def test_decision_ledger_migration_backfills_latest_finding_evidence(tmp_path: Path) -> None:
    config = _alembic_config(tmp_path)
    command.upgrade(config, "20260612_0003")
    engine = create_engine(config.get_main_option("sqlalchemy.url"))
    project_id = uuid.uuid4()
    finding_id = uuid.uuid4()
    run_id = uuid.uuid4()
    with Session(engine) as session:
        session.connection().execute(
            text(
                "INSERT INTO project "
                "(name, description, id, created_at, updated_at) "
                "VALUES (:name, NULL, :id, :created_at, :updated_at)"
            ),
            {
                "name": "Ledger migration",
                "id": project_id.hex,
                "created_at": "2026-06-12 00:00:00",
                "updated_at": "2026-06-12 00:00:00",
            },
        )
        vulnerability = Vulnerability(cve_id="CVE-2026-4242")
        session.add(vulnerability)
        session.flush()
        finding = Finding(
            id=finding_id,
            project_id=project_id,
            vulnerability_id=vulnerability.id,
            cve_id="CVE-2026-4242",
            dedup_key="ledger-backfill",
        )
        run = AnalysisRun(
            id=run_id,
            project_id=project_id,
            input_type="cve-list",
        )
        session.add(finding)
        session.add(run)
        session.flush()
        analysis_evidence = AnalysisEvidence(
            project_id=project_id,
            analysis_run_id=run_id,
        )
        session.add(analysis_evidence)
        session.flush()
        contract = FindingDecisionEvidenceV2(
            finding_id=str(finding_id),
            analysis_run_id=str(run_id),
            project_id=str(project_id),
            cve_id=finding.cve_id,
            dedup_key=finding.dedup_key,
            status="open",
            priority="critical",
            priority_rank=1,
            risk_score=98.0,
            operational_rank=1,
            in_kev=True,
            occurrence_scope={"purl": "pkg:pypi/Django@4.2"},
            priority_evidence=PriorityEvidenceV2(
                priority_label="Critical",
                priority_rank=1,
            ),
        )
        session.add(
            FindingDecisionEvidence(
                analysis_evidence_id=analysis_evidence.id,
                project_id=project_id,
                analysis_run_id=run_id,
                finding_id=finding_id,
                cve_id=finding.cve_id,
                dedup_key=finding.dedup_key,
                priority=contract.priority,
                status=contract.status,
                payload_json=contract.to_jsonable(),
            )
        )
        session.commit()
    _replace_finding_decision_evidence_with_stale_foreign_key(engine)
    engine.dispose()

    command.upgrade(config, "head")
    upgraded_engine = create_engine(config.get_main_option("sqlalchemy.url"))
    try:
        with Session(upgraded_engine) as session:
            parity = FindingCurrentProjectionRepository(session).verify_all_source_parity()
        with upgraded_engine.connect() as connection:
            row = (
                connection.execute(
                    text(
                        "SELECT finding_id, priority, risk_score, in_kev, "
                        "source_finding_evidence_id, schema_version, component_name, "
                        "component_version, component_purl, component_package_type, "
                        "component_ecosystem FROM finding_current_projection"
                    )
                )
                .mappings()
                .one()
            )
    finally:
        upgraded_engine.dispose()

    assert str(uuid.UUID(row["finding_id"])) == str(finding_id)
    assert row["priority"] == "critical"
    assert row["risk_score"] == 98.0
    assert bool(row["in_kev"]) is True
    assert row["source_finding_evidence_id"] is not None
    assert row["schema_version"] == "finding-current-projection.v2"
    assert row["component_name"] == "django"
    assert row["component_version"] == "4.2"
    assert row["component_purl"] == "pkg:pypi/Django@4.2"
    assert row["component_package_type"] == "pypi"
    assert row["component_ecosystem"] == "pypi"
    assert parity.checked == 1
    assert parity.matches is True


def test_component_projection_migration_is_atomic_and_retryable(tmp_path: Path) -> None:
    config = _alembic_config(tmp_path)
    command.upgrade(config, "head")
    engine = create_engine(config.get_main_option("sqlalchemy.url"))
    project_id = uuid.uuid4()
    finding_id = uuid.uuid4()
    run_id = uuid.uuid4()
    source_id = uuid.uuid4()
    with Session(engine) as session:
        project = Project(id=project_id, name="Projection atomicity")
        vulnerability = Vulnerability(cve_id="CVE-2026-9009")
        run = AnalysisRun(id=run_id, project_id=project_id, input_type="cve-list")
        session.add(project)
        session.add(vulnerability)
        session.flush()
        finding = Finding(
            id=finding_id,
            project_id=project_id,
            vulnerability_id=vulnerability.id,
            cve_id=vulnerability.cve_id,
            dedup_key="projection-atomicity",
        )
        session.add(run)
        session.add(finding)
        session.flush()
        analysis_evidence = AnalysisEvidence(
            project_id=project_id,
            analysis_run_id=run_id,
        )
        session.add(analysis_evidence)
        session.flush()
        contract = FindingDecisionEvidenceV2(
            finding_id=str(finding_id),
            analysis_run_id=str(run_id),
            project_id=str(project_id),
            cve_id=finding.cve_id,
            dedup_key=finding.dedup_key,
            status="open",
            priority="medium",
            priority_rank=3,
            occurrence_scope={"component_name": "atomic-component"},
            priority_evidence=PriorityEvidenceV2(
                priority_label="Medium",
                priority_rank=3,
            ),
        )
        source = FindingDecisionEvidence(
            id=source_id,
            analysis_evidence_id=analysis_evidence.id,
            project_id=project_id,
            analysis_run_id=run_id,
            finding_id=finding_id,
            cve_id=finding.cve_id,
            dedup_key=finding.dedup_key,
            priority=contract.priority,
            status=contract.status,
            payload_json=contract.to_jsonable(),
        )
        session.add(source)
        session.flush()
        FindingCurrentProjectionRepository(session).upsert_from_evidence_record(
            source_record=source,
            evidence=contract,
        )
        session.commit()
    engine.dispose()

    command.downgrade(config, "20260904_0008")
    downgraded_engine = create_engine(config.get_main_option("sqlalchemy.url"))
    with downgraded_engine.begin() as connection:
        connection.exec_driver_sql("PRAGMA foreign_keys=ON")
        connection.execute(
            text("DELETE FROM finding_decision_evidence WHERE id = :id"),
            {"id": source_id.hex},
        )
        assert (
            connection.execute(
                text(
                    "SELECT source_finding_evidence_id FROM finding_current_projection "
                    "WHERE finding_id = :finding_id"
                ),
                {"finding_id": finding_id.hex},
            ).scalar_one()
            is None
        )
    downgraded_engine.dispose()

    with pytest.raises(RuntimeError, match="must retain immutable source evidence"):
        command.upgrade(config, "head")

    failed_engine = create_engine(config.get_main_option("sqlalchemy.url"))
    try:
        columns = {
            column["name"]
            for column in inspect(failed_engine).get_columns("finding_current_projection")
        }
        with failed_engine.begin() as connection:
            revision_after_failure = connection.execute(
                text("SELECT version_num FROM alembic_version")
            ).scalar_one()
            connection.execute(text("DELETE FROM finding_current_projection"))
    finally:
        failed_engine.dispose()

    assert revision_after_failure == "20260904_0008"
    assert {
        "component_name",
        "component_version",
        "component_purl",
        "component_package_type",
        "component_ecosystem",
    }.isdisjoint(columns)

    command.upgrade(config, "head")
    retried_engine = create_engine(config.get_main_option("sqlalchemy.url"))
    try:
        assert {
            "component_name",
            "component_version",
            "component_purl",
            "component_package_type",
            "component_ecosystem",
        }.issubset(
            {
                column["name"]
                for column in inspect(retried_engine).get_columns("finding_current_projection")
            }
        )
    finally:
        retried_engine.dispose()


def _replace_finding_decision_evidence_with_stale_foreign_key(engine: Engine) -> None:
    """Model a historical SQLite table whose renamed FK target no longer exists."""
    with engine.connect() as connection:
        connection.exec_driver_sql("PRAGMA foreign_keys=OFF")
        connection.exec_driver_sql(
            """
            CREATE TABLE finding_decision_evidence_stale (
                schema_version VARCHAR(80) NOT NULL,
                cve_id VARCHAR(64) NOT NULL,
                dedup_key VARCHAR(512) NOT NULL,
                priority VARCHAR(40) NOT NULL,
                status VARCHAR(40) NOT NULL,
                payload_json JSON NOT NULL,
                id CHAR(32) NOT NULL PRIMARY KEY,
                analysis_evidence_id CHAR(32) NOT NULL,
                project_id CHAR(32) NOT NULL,
                analysis_run_id CHAR(32) NOT NULL,
                finding_id CHAR(32) NOT NULL,
                created_at DATETIME NOT NULL,
                updated_at DATETIME NOT NULL,
                FOREIGN KEY(analysis_run_id)
                    REFERENCES _analysis_run_legacy_repair (id) ON DELETE CASCADE,
                FOREIGN KEY(finding_id)
                    REFERENCES _finding_legacy_repair (id) ON DELETE CASCADE
            )
            """
        )
        connection.exec_driver_sql(
            """
            INSERT INTO finding_decision_evidence_stale
            SELECT schema_version, cve_id, dedup_key, priority, status, payload_json,
                   id, analysis_evidence_id, project_id, analysis_run_id, finding_id,
                   created_at, updated_at
              FROM finding_decision_evidence
            """
        )
        connection.exec_driver_sql("DROP TABLE finding_decision_evidence")
        connection.exec_driver_sql(
            "ALTER TABLE finding_decision_evidence_stale RENAME TO finding_decision_evidence"
        )
        connection.commit()


def _alembic_config(tmp_path: Path) -> Config:
    script_location = Path(__file__).resolve().parents[2] / "app" / "alembic"
    database_url = f"sqlite:///{tmp_path / 'workbench.db'}"

    config = Config()
    config.set_main_option("script_location", str(script_location))
    config.set_main_option("sqlalchemy.url", database_url)
    return config


def _run_alembic_operation(config: Config, operation: str, revision: str) -> None:
    if operation == "upgrade":
        command.upgrade(config, revision)
        return
    if operation == "downgrade":
        command.downgrade(config, revision)
        return
    raise AssertionError(f"Unsupported Alembic operation: {operation}")

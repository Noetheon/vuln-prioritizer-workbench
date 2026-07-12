from __future__ import annotations

import importlib
import uuid
from pathlib import Path

from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import Engine
from sqlmodel import Session, SQLModel

from app.core.migration_bootstrap import ALEMBIC_HEAD, current_alembic_head
from app.decision_core.contracts import FindingDecisionEvidenceV2, PriorityEvidenceV2
from app.models import (
    AnalysisEvidence,
    AnalysisRun,
    Finding,
    FindingDecisionEvidence,
    Project,
    Vulnerability,
)
from app.repositories.current_projections import FindingCurrentProjectionRepository

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


def test_decision_ledger_migration_backfills_latest_finding_evidence(tmp_path: Path) -> None:
    config = _alembic_config(tmp_path)
    command.upgrade(config, "20260612_0003")
    engine = create_engine(config.get_main_option("sqlalchemy.url"))
    project_id = uuid.uuid4()
    finding_id = uuid.uuid4()
    run_id = uuid.uuid4()
    with Session(engine) as session:
        project = Project(id=project_id, name="Ledger migration")
        vulnerability = Vulnerability(cve_id="CVE-2026-4242")
        session.add(project)
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
                        "source_finding_evidence_id FROM finding_current_projection"
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
    assert parity.checked == 1
    assert parity.matches is True


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

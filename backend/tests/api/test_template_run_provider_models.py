from __future__ import annotations

import importlib
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect
from sqlalchemy.engine import Engine
from sqlmodel import Session, SQLModel, select

RUN_PROVIDER_TABLES = {"analysis_run", "finding_occurrence", "provider_snapshot"}
RUN_PROVIDER_EXPORTS = (
    "AnalysisRun",
    "AnalysisRunStatus",
    "FindingOccurrence",
    "ProviderSnapshot",
)
RUN_STATUS_VALUES = (
    "pending",
    "running",
    "completed",
    "completed_with_errors",
    "failed",
    "cancelled",
)
FIXED_STARTED_AT = datetime(2026, 4, 28, 12, 0, tzinfo=UTC)
FIXED_FINISHED_AT = datetime(2026, 4, 28, 12, 4, tzinfo=UTC)


def test_run_provider_models_are_exported_and_registered() -> None:
    app_models = _app_models()

    exported_names = set(getattr(app_models, "__all__", ()))
    assert set(RUN_PROVIDER_EXPORTS).issubset(exported_names)
    assert RUN_PROVIDER_TABLES.issubset(SQLModel.metadata.tables)

    for model_name in RUN_PROVIDER_EXPORTS:
        model = getattr(app_models, model_name)
        assert model.__module__.startswith("app.models.")
        assert model.__module__ != "app.models"


def test_run_provider_migration_creates_tables_and_foreign_keys(
    migrated_engine: Engine,
) -> None:
    inspector = inspect(migrated_engine)
    assert RUN_PROVIDER_TABLES.issubset(set(inspector.get_table_names()))

    foreign_keys = {
        table: {
            (
                tuple(foreign_key["constrained_columns"]),
                foreign_key["referred_table"],
                tuple(foreign_key["referred_columns"]),
            )
            for foreign_key in inspector.get_foreign_keys(table)
        }
        for table in RUN_PROVIDER_TABLES
    }

    assert (("project_id",), "project", ("id",)) in foreign_keys["analysis_run"]
    assert (
        ("provider_snapshot_id",),
        "provider_snapshot",
        ("id",),
    ) in foreign_keys["analysis_run"]
    assert (
        ("analysis_run_id",),
        "analysis_run",
        ("id",),
    ) in foreign_keys["finding_occurrence"]
    assert (("finding_id",), "finding", ("id",)) in foreign_keys["finding_occurrence"]


def test_project_can_persist_analysis_run_without_findings_then_with_occurrence(
    migrated_engine: Engine,
) -> None:
    app_models = _app_models()
    ids = _ids()

    with Session(migrated_engine) as session:
        _persist_project_shell(session, app_models, ids)
        session.add(
            app_models.AnalysisRun(
                id=ids["run"],
                project_id=ids["project"],
                input_type="trivy-json",
                filename="trivy-results.json",
                status=app_models.AnalysisRunStatus.RUNNING,
                started_at=FIXED_STARTED_AT,
                summary_json={"parsed": 0, "findings": 0},
            )
        )
        session.commit()

    with Session(migrated_engine) as session:
        run = session.get(app_models.AnalysisRun, ids["run"])
        assert run is not None
        assert run.project_id == ids["project"]
        assert _value(run.status) == "running"

        occurrences = session.exec(
            select(app_models.FindingOccurrence).where(
                app_models.FindingOccurrence.analysis_run_id == ids["run"]
            )
        ).all()
        assert occurrences == []

    with Session(migrated_engine) as session:
        session.add(
            app_models.Vulnerability(
                id=ids["vulnerability"],
                cve_id="CVE-2021-44228",
                source_id="CVE-2021-44228",
                cvss_score=10.0,
                severity="CRITICAL",
            )
        )
        session.add(
            app_models.Finding(
                id=ids["finding"],
                project_id=ids["project"],
                vulnerability_id=ids["vulnerability"],
                cve_id="CVE-2021-44228",
                status=_enum_or_string(app_models, "FindingStatus", "open"),
                priority=_enum_or_string(app_models, "FindingPriority", "critical"),
                priority_rank=1,
                in_kev=True,
            )
        )
        session.add(
            app_models.FindingOccurrence(
                id=ids["occurrence"],
                analysis_run_id=ids["run"],
                finding_id=ids["finding"],
                source="dependency-scan",
                scanner="trivy",
                raw_reference="pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
                fix_version="2.17.1",
                evidence_json={
                    "target_ref": "registry.example.test/payments-api:2026.04.28",
                    "input_line": 42,
                },
            )
        )

        run = session.get(app_models.AnalysisRun, ids["run"])
        assert run is not None
        run.status = app_models.AnalysisRunStatus.COMPLETED
        run.finished_at = FIXED_FINISHED_AT
        run.summary_json = {"parsed": 1, "findings": 1}
        session.commit()

    with Session(migrated_engine) as session:
        occurrence = session.get(app_models.FindingOccurrence, ids["occurrence"])
        assert occurrence is not None
        assert occurrence.analysis_run_id == ids["run"]
        assert occurrence.finding_id == ids["finding"]
        assert occurrence.source == "dependency-scan"
        assert occurrence.scanner == "trivy"
        assert occurrence.raw_reference == "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
        assert occurrence.fix_version == "2.17.1"
        assert occurrence.evidence_json["input_line"] == 42

        run = session.get(app_models.AnalysisRun, ids["run"])
        assert run is not None
        assert _value(run.status) == "completed"
        assert run.summary_json == {"parsed": 1, "findings": 1}


def test_provider_snapshot_can_be_linked_to_analysis_run(migrated_engine: Engine) -> None:
    app_models = _app_models()
    ids = _ids()

    with Session(migrated_engine) as session:
        _persist_project_shell(session, app_models, ids)
        session.add(
            app_models.ProviderSnapshot(
                id=ids["provider_snapshot"],
                nvd_last_sync="2026-04-28T10:15:00Z",
                epss_date="2026-04-28",
                kev_catalog_version="2026-04-28",
                content_hash="sha256:6a98c6d1d5f0d57c7b7d3e1adce89c01",
                source_hashes_json={
                    "nvd": "sha256:nvd-feed",
                    "epss": "sha256:epss-feed",
                    "kev": "sha256:kev-feed",
                },
                source_metadata_json={
                    "selected_sources": ["nvd", "epss", "kev"],
                    "cache_only": True,
                    "requested_cves": 1,
                },
            )
        )
        session.add(
            app_models.AnalysisRun(
                id=ids["run"],
                project_id=ids["project"],
                provider_snapshot_id=ids["provider_snapshot"],
                input_type="cve-list",
                filename="known-cves.txt",
                status=app_models.AnalysisRunStatus.COMPLETED,
                started_at=FIXED_STARTED_AT,
                finished_at=FIXED_FINISHED_AT,
                summary_json={"parsed": 1, "findings": 1},
            )
        )
        session.commit()

    with Session(migrated_engine) as session:
        run = session.get(app_models.AnalysisRun, ids["run"])
        assert run is not None
        assert run.provider_snapshot_id == ids["provider_snapshot"]

        snapshot = session.get(app_models.ProviderSnapshot, ids["provider_snapshot"])
        assert snapshot is not None
        assert snapshot.content_hash == "sha256:6a98c6d1d5f0d57c7b7d3e1adce89c01"
        assert snapshot.source_hashes_json["kev"] == "sha256:kev-feed"
        assert snapshot.source_metadata_json["selected_sources"] == ["nvd", "epss", "kev"]


def test_analysis_run_status_values_serialize_as_stable_strings() -> None:
    app_models = _app_models()
    status_enum = app_models.AnalysisRunStatus

    assert {status.value for status in status_enum}.issuperset(RUN_STATUS_VALUES)

    for value in RUN_STATUS_VALUES:
        run = app_models.AnalysisRun(
            project_id=uuid.uuid4(),
            input_type="cve-list",
            filename="known-cves.txt",
            status=status_enum(value),
            error_message="Provider enrichment failed." if value == "failed" else None,
            error_json={"provider": "nvd"} if value == "failed" else {},
        )
        payload = run.model_dump(mode="json")

        assert payload["status"] == value
        if value == "failed":
            assert payload["error_message"] == "Provider enrichment failed."
            assert payload["error_json"] == {"provider": "nvd"}


def test_run_provider_constraints_and_indexes_exist(migrated_engine: Engine) -> None:
    inspector = inspect(migrated_engine)
    assert RUN_PROVIDER_TABLES.issubset(set(inspector.get_table_names()))

    assert _has_unique_constraint_or_index(
        inspector,
        "provider_snapshot",
        ("content_hash",),
    )

    assert _has_index(inspector, "analysis_run", ("project_id",))
    assert _has_index(inspector, "analysis_run", ("provider_snapshot_id",))
    assert _has_index(inspector, "analysis_run", ("project_id", "started_at"))
    assert _has_index(inspector, "analysis_run", ("project_id", "status"))
    assert _has_index(inspector, "finding_occurrence", ("analysis_run_id",))
    assert _has_index(inspector, "finding_occurrence", ("finding_id",))


def _app_models() -> Any:
    models = importlib.import_module("app.models")
    import_table_models = getattr(models, "import_table_models", None)
    assert import_table_models is not None, "app.models must expose import_table_models"
    import_table_models()
    return models


def _alembic_config(tmp_path: Path) -> Config:
    script_location = Path(__file__).resolve().parents[2] / "app" / "alembic"
    assert script_location.exists(), "Template app Alembic migrations must live under app/alembic"

    config = Config()
    config.set_main_option("script_location", str(script_location))
    config.set_main_option("sqlalchemy.url", f"sqlite:///{tmp_path / 'template.db'}")
    return config


@pytest.fixture()
def migrated_engine(tmp_path: Path) -> Iterator[Engine]:
    config = _alembic_config(tmp_path)
    _app_models()
    command.upgrade(config, "head")

    engine = create_engine(config.get_main_option("sqlalchemy.url"))
    try:
        yield engine
    finally:
        engine.dispose()


def _ids() -> dict[str, uuid.UUID]:
    return {
        "user": uuid.uuid4(),
        "project": uuid.uuid4(),
        "run": uuid.uuid4(),
        "provider_snapshot": uuid.uuid4(),
        "vulnerability": uuid.uuid4(),
        "finding": uuid.uuid4(),
        "occurrence": uuid.uuid4(),
    }


def _persist_project_shell(session: Session, app_models: Any, ids: dict[str, uuid.UUID]) -> None:
    session.add(
        app_models.User(
            id=ids["user"],
            email=f"{ids['user']}@example.test",
            hashed_password="not-used",
            is_active=True,
            is_superuser=True,
        )
    )
    session.add(
        app_models.Project(
            id=ids["project"],
            owner_id=ids["user"],
            name="Run Provider Contract",
            description="VPW-009 AnalysisRun and ProviderSnapshot test shell.",
        )
    )


def _enum_or_string(app_models: Any, enum_name: str, value: str) -> Any:
    enum_class = getattr(app_models, enum_name, None)
    if enum_class is None:
        return value
    return enum_class(value)


def _value(value: Any) -> Any:
    return getattr(value, "value", value)


def _has_unique_constraint_or_index(inspector: Any, table: str, columns: tuple[str, ...]) -> bool:
    return any(
        tuple(constraint["column_names"]) == columns
        for constraint in inspector.get_unique_constraints(table)
    ) or any(
        index.get("unique") and tuple(index["column_names"]) == columns
        for index in inspector.get_indexes(table)
    )


def _has_index(inspector: Any, table: str, columns: tuple[str, ...]) -> bool:
    return any(tuple(index["column_names"]) == columns for index in inspector.get_indexes(table))

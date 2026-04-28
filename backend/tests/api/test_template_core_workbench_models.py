from __future__ import annotations

import importlib
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect
from sqlalchemy.engine import Engine
from sqlmodel import Session, SQLModel, select

CORE_WORKBENCH_TABLES = {"asset", "component", "vulnerability", "finding"}
CORE_WORKBENCH_EXPORTS = ("Asset", "Component", "Vulnerability", "Finding")


@pytest.fixture()
def app_models() -> Any:
    models = importlib.import_module("app.models")
    import_table_models = getattr(models, "import_table_models", None)
    assert import_table_models is not None, "app.models must expose import_table_models"
    import_table_models()
    return models


@pytest.fixture()
def alembic_config(tmp_path: Path) -> Config:
    script_location = Path(__file__).resolve().parents[2] / "app" / "alembic"
    assert script_location.exists(), "Template app Alembic migrations must live under app/alembic"

    config = Config()
    config.set_main_option("script_location", str(script_location))
    config.set_main_option("sqlalchemy.url", f"sqlite:///{tmp_path / 'template.db'}")
    return config


@pytest.fixture()
def migrated_engine(alembic_config: Config, app_models: Any) -> Iterator[Engine]:
    command.upgrade(alembic_config, "head")

    engine = create_engine(alembic_config.get_main_option("sqlalchemy.url"))
    try:
        yield engine
    finally:
        engine.dispose()


def test_core_workbench_models_are_exported_and_registered(app_models: Any) -> None:
    exported_names = set(getattr(app_models, "__all__", ()))
    assert set(CORE_WORKBENCH_EXPORTS).issubset(exported_names)
    assert CORE_WORKBENCH_TABLES.issubset(SQLModel.metadata.tables)

    for model_name in CORE_WORKBENCH_EXPORTS:
        model = getattr(app_models, model_name)
        assert model.__module__.startswith("app.models.")
        assert model.__module__ != "app.models"


def test_core_workbench_migration_creates_tables_and_foreign_keys(
    migrated_engine: Engine,
) -> None:
    inspector = inspect(migrated_engine)
    assert CORE_WORKBENCH_TABLES.issubset(set(inspector.get_table_names()))

    foreign_keys = {
        table: {
            (
                tuple(foreign_key["constrained_columns"]),
                foreign_key["referred_table"],
                tuple(foreign_key["referred_columns"]),
            )
            for foreign_key in inspector.get_foreign_keys(table)
        }
        for table in CORE_WORKBENCH_TABLES
    }

    assert (("project_id",), "project", ("id",)) in foreign_keys["asset"]
    assert (("project_id",), "project", ("id",)) in foreign_keys["finding"]
    assert (("asset_id",), "asset", ("id",)) in foreign_keys["finding"]
    assert (("component_id",), "component", ("id",)) in foreign_keys["finding"]
    assert (("vulnerability_id",), "vulnerability", ("id",)) in foreign_keys["finding"]


def test_project_can_persist_core_workbench_graph(app_models: Any, migrated_engine: Engine) -> None:
    user_id = uuid.uuid4()
    project_id = uuid.uuid4()
    asset_id = uuid.uuid4()
    component_id = uuid.uuid4()
    vulnerability_id = uuid.uuid4()
    finding_id = uuid.uuid4()

    with Session(migrated_engine) as session:
        session.add(
            app_models.User(
                id=user_id,
                email="owner@example.test",
                hashed_password="not-used",
                is_active=True,
                is_superuser=True,
            )
        )
        session.add(
            app_models.Project(
                id=project_id,
                owner_id=user_id,
                name="Core Workbench",
                description="Template SQLModel persistence contract.",
            )
        )
        session.add(
            app_models.Asset(
                id=asset_id,
                project_id=project_id,
                asset_key="api-gateway",
                name="API Gateway",
                environment=_enum_or_string(app_models, "AssetEnvironment", "production"),
                exposure=_enum_or_string(app_models, "AssetExposure", "internet-facing"),
                criticality=_enum_or_string(app_models, "AssetCriticality", "critical"),
            )
        )
        session.add(
            app_models.Component(
                id=component_id,
                name="log4j-core",
                version="2.14.1",
                purl="pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
                ecosystem="maven",
            )
        )
        session.add(
            app_models.Vulnerability(
                id=vulnerability_id,
                cve_id="CVE-2021-44228",
                source_id="CVE-2021-44228",
                cvss_score=10.0,
                severity="CRITICAL",
            )
        )
        session.add(
            app_models.Finding(
                id=finding_id,
                project_id=project_id,
                asset_id=asset_id,
                component_id=component_id,
                vulnerability_id=vulnerability_id,
                cve_id="CVE-2021-44228",
                status=_enum_or_string(app_models, "FindingStatus", "open"),
                priority=_enum_or_string(app_models, "FindingPriority", "critical"),
                priority_rank=1,
                in_kev=True,
            )
        )
        session.commit()

    with Session(migrated_engine) as session:
        finding = session.exec(
            select(app_models.Finding).where(app_models.Finding.id == finding_id)
        ).one()
        assert finding.project_id == project_id
        assert finding.asset_id == asset_id
        assert finding.component_id == component_id
        assert finding.vulnerability_id == vulnerability_id
        assert finding.cve_id == "CVE-2021-44228"
        assert _value(finding.status) == "open"
        assert _value(finding.priority) == "critical"


def test_core_workbench_enum_values_serialize_as_stable_strings(app_models: Any) -> None:
    asset = app_models.Asset(
        project_id=uuid.uuid4(),
        asset_key="payments-api",
        name="Payments API",
        environment=_enum_or_string(app_models, "AssetEnvironment", "production"),
        exposure=_enum_or_string(app_models, "AssetExposure", "internet-facing"),
        criticality=_enum_or_string(app_models, "AssetCriticality", "critical"),
    )
    finding = app_models.Finding(
        project_id=uuid.uuid4(),
        vulnerability_id=uuid.uuid4(),
        cve_id="CVE-2024-0001",
        status=_enum_or_string(app_models, "FindingStatus", "open"),
        priority=_enum_or_string(app_models, "FindingPriority", "high"),
        priority_rank=2,
    )

    asset_payload = asset.model_dump(mode="json")
    finding_payload = finding.model_dump(mode="json")

    assert asset_payload["environment"] == "production"
    assert asset_payload["exposure"] == "internet-facing"
    assert asset_payload["criticality"] == "critical"
    assert finding_payload["status"] == "open"
    assert finding_payload["priority"] == "high"


def test_core_workbench_dedup_constraints_and_indexes_exist(migrated_engine: Engine) -> None:
    inspector = inspect(migrated_engine)
    assert CORE_WORKBENCH_TABLES.issubset(set(inspector.get_table_names()))

    assert _has_unique_constraint_or_index(inspector, "asset", ("project_id", "asset_key"))
    assert _has_unique_constraint_or_index(inspector, "component", ("purl",)) or (
        _has_unique_constraint_or_index(inspector, "component", ("name", "version", "ecosystem"))
    )
    assert _has_unique_constraint_or_index(inspector, "vulnerability", ("cve_id",))
    assert _has_unique_constraint_or_index(
        inspector,
        "finding",
        ("project_id", "vulnerability_id", "component_id", "asset_id"),
    )

    assert _has_index(inspector, "asset", ("project_id",))
    assert _has_index(inspector, "finding", ("project_id", "priority_rank"))
    assert _has_index(inspector, "finding", ("project_id", "status"))
    assert _has_index(inspector, "finding", ("cve_id",))


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

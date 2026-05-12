from __future__ import annotations

import importlib
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
from pydantic import ValidationError
from sqlalchemy import create_engine, inspect
from sqlalchemy.engine import Engine
from sqlmodel import Session, SQLModel, select

ATTACK_LITE_TABLES = {
    "attack_stix_mitigation",
    "attack_stix_snapshot",
    "attack_stix_tactic",
    "attack_stix_technique",
    "attack_stix_technique_mitigation",
    "attack_tactic",
    "attack_technique",
    "cve_attack_mapping",
    "finding_attack_context",
}
ATTACK_LITE_EXPORTS = (
    "AttackStixMitigation",
    "AttackStixSnapshot",
    "AttackStixTactic",
    "AttackStixTechnique",
    "AttackStixTechniqueMitigation",
    "AttackTactic",
    "AttackTechnique",
    "CveAttackMapping",
    "FindingAttackContext",
)


@pytest.fixture()
def app_models() -> Any:
    models = importlib.import_module("app.models")
    models.import_table_models()
    return models


@pytest.fixture()
def alembic_config(tmp_path: Path) -> Config:
    script_location = Path(__file__).resolve().parents[2] / "app" / "alembic"

    config = Config()
    config.set_main_option("script_location", str(script_location))
    config.set_main_option("sqlalchemy.url", f"sqlite:///{tmp_path / 'workbench.db'}")
    return config


@pytest.fixture()
def migrated_engine(alembic_config: Config, app_models: Any) -> Iterator[Engine]:
    command.upgrade(alembic_config, "head")

    engine = create_engine(alembic_config.get_main_option("sqlalchemy.url"))
    try:
        yield engine
    finally:
        engine.dispose()


def test_attack_lite_models_are_exported_and_registered(app_models: Any) -> None:
    exported_names = set(getattr(app_models, "__all__", ()))

    assert set(ATTACK_LITE_EXPORTS).issubset(exported_names)
    assert ATTACK_LITE_TABLES.issubset(SQLModel.metadata.tables)

    for model_name in ATTACK_LITE_EXPORTS:
        model = getattr(app_models, model_name)
        assert model.__module__ == "app.models.attack"


def test_attack_lite_migration_creates_tables_and_foreign_keys(
    migrated_engine: Engine,
) -> None:
    inspector = inspect(migrated_engine)
    assert ATTACK_LITE_TABLES.issubset(set(inspector.get_table_names()))

    foreign_keys = {
        table: {
            (
                tuple(foreign_key["constrained_columns"]),
                foreign_key["referred_table"],
                tuple(foreign_key["referred_columns"]),
            )
            for foreign_key in inspector.get_foreign_keys(table)
        }
        for table in ATTACK_LITE_TABLES
    }

    assert (("technique_id",), "attack_technique", ("technique_id",)) in foreign_keys[
        "cve_attack_mapping"
    ]
    assert (("vulnerability_id",), "vulnerability", ("id",)) in foreign_keys["cve_attack_mapping"]
    assert (("finding_id",), "finding", ("id",)) in foreign_keys["finding_attack_context"]
    assert (("analysis_run_id",), "analysis_run", ("id",)) in foreign_keys["finding_attack_context"]
    assert (("provider_snapshot_id",), "provider_snapshot", ("id",)) in foreign_keys[
        "attack_stix_snapshot"
    ]
    for table in (
        "attack_stix_tactic",
        "attack_stix_technique",
        "attack_stix_mitigation",
        "attack_stix_technique_mitigation",
    ):
        assert (("snapshot_id",), "attack_stix_snapshot", ("id",)) in foreign_keys[table]


def test_attack_lite_models_reject_unreviewable_mapping_fields(app_models: Any) -> None:
    valid_mapping = app_models.CveAttackMappingBase(
        cve_id="CVE-2021-44228",
        technique_id="T1190",
        mapping_type="exploitation",
        source="CTID Mappings Explorer",
        confidence=0.9,
        rationale="Maps the known CVE to a public-facing application exposure pattern.",
        review_status="reviewed",
        defensive_note="Use this only to prioritize defensive review and detection coverage.",
    )
    assert valid_mapping.technique_id == "T1190"

    with pytest.raises(ValidationError):
        app_models.CveAttackMappingBase(
            cve_id="CVE-2021-44228",
            technique_id="T1190",
            mapping_type="exploitation",
            confidence=0.9,
            rationale="Missing source must fail.",
            defensive_note="Defensive context only.",
        )

    with pytest.raises(ValidationError):
        app_models.CveAttackMappingBase(
            cve_id="CVE-2021-44228",
            technique_id="TA0001",
            mapping_type="exploitation",
            source="CTID Mappings Explorer",
            confidence=0.9,
            rationale="Tactic IDs are not valid technique IDs.",
            defensive_note="Defensive context only.",
        )

    with pytest.raises(ValidationError):
        app_models.CveAttackMappingBase(
            cve_id="CVE-2021-44228",
            technique_id="T1190",
            mapping_type="exploitation",
            source="CTID Mappings Explorer",
            confidence=1.5,
            rationale="Confidence must be normalized.",
            defensive_note="Defensive context only.",
        )


def test_attack_lite_model_validators_reject_invalid_stix_and_context_fields(
    app_models: Any,
) -> None:
    with pytest.raises(ValidationError):
        app_models.AttackTacticBase(tactic_id="T1190", name="Initial Access")

    with pytest.raises(ValidationError):
        app_models.AttackTechniqueBase(
            technique_id="T1190",
            name="Exploit Public-Facing Application",
            tactic_ids_json=["T1190"],
        )

    with pytest.raises(ValidationError):
        app_models.AttackStixSnapshotBase(
            attack_version=" ",
            domain="enterprise-attack",
            bundle_sha256="f" * 64,
        )

    with pytest.raises(ValidationError):
        app_models.AttackStixTacticBase(
            stix_id=" ",
            tactic_id="TA0001",
            name="Initial Access",
        )

    with pytest.raises(ValidationError):
        app_models.AttackStixTechniqueBase(
            stix_id="attack-pattern--1",
            technique_id="T1190",
            name="Exploit Public-Facing Application",
            tactic_ids_json=["T1190"],
        )

    with pytest.raises(ValidationError):
        app_models.AttackStixMitigationBase(
            stix_id="course-of-action--1",
            mitigation_id="     ",
            name="Update Software",
        )

    with pytest.raises(ValidationError):
        app_models.AttackStixTechniqueMitigationBase(
            relationship_id=" ",
            technique_id="T1190",
            mitigation_id="M1051",
        )

    with pytest.raises(ValidationError):
        app_models.CveAttackMappingBase(
            cve_id="CVE-2021-44228",
            technique_id="T1190",
            tactic_ids_json=["T1190"],
            mapping_type="exploitation",
            source="CTID Mappings Explorer",
            confidence=0.9,
            rationale="Tactic list contains a technique identifier.",
            review_status="reviewed",
            defensive_note="Defensive context only.",
        )

    with pytest.raises(ValidationError):
        app_models.CveAttackMappingBase(
            cve_id="CVE-2021-44228",
            technique_id="T1190",
            mapping_type="unknown",
            source="CTID Mappings Explorer",
            confidence=0.9,
            rationale="Mapping type must be a known defensive category.",
            review_status="reviewed",
            defensive_note="Defensive context only.",
        )

    with pytest.raises(ValidationError):
        app_models.CveAttackMappingBase(
            cve_id="CVE-2021-44228",
            technique_id="T1190",
            mapping_type="exploitation",
            source="CTID Mappings Explorer",
            confidence=0.9,
            rationale="Review status must be explicit.",
            review_status="done",
            defensive_note="Defensive context only.",
        )

    with pytest.raises(ValidationError):
        app_models.FindingAttackContextBase(
            cve_id="CVE-2021-44228",
            mapped=False,
            source="CTID Mappings Explorer",
            review_status="done",
            defensive_note="Defensive context only.",
        )

    with pytest.raises(ValidationError):
        app_models.FindingAttackContextBase(
            cve_id="CVE-2021-44228",
            mapped=False,
            source="CTID Mappings Explorer",
            review_status="reviewed",
            defensive_note="Defensive context only.",
            technique_ids_json=["TA0001"],
        )

    with pytest.raises(ValidationError):
        app_models.FindingAttackContextBase(
            cve_id="CVE-2021-44228",
            mapped=True,
            source="CTID Mappings Explorer",
            review_status="reviewed",
            defensive_note="Defensive context only.",
        )


def test_project_can_persist_attack_lite_graph(
    app_models: Any,
    migrated_engine: Engine,
) -> None:
    ids = _ids()
    with Session(migrated_engine) as session:
        _persist_project_run_graph(session, app_models, ids)
        session.add(
            app_models.AttackTactic(
                id=ids["tactic"],
                tactic_id="TA0001",
                name="Initial Access",
                short_name="initial-access",
                attack_version="16.1",
            )
        )
        session.add(
            app_models.AttackTechnique(
                id=ids["technique"],
                technique_id="T1190",
                name="Exploit Public-Facing Application",
                tactic_ids_json=["TA0001"],
                attack_version="16.1",
                defensive_note=(
                    "Review exposure and detection coverage; do not treat as exploit proof."
                ),
            )
        )
        session.add(
            app_models.CveAttackMapping(
                id=ids["mapping"],
                vulnerability_id=ids["vulnerability"],
                cve_id="CVE-2021-44228",
                technique_id="T1190",
                technique_name="Exploit Public-Facing Application",
                tactic_ids_json=["TA0001"],
                mapping_type="exploitation",
                source="CTID Mappings Explorer",
                confidence=0.9,
                rationale="Reviewed mapping from CVE impact to defensive ATT&CK context.",
                review_status="reviewed",
                defensive_note="Use this mapping for defensive triage and control review only.",
                references_json=["https://ctid.mitre.org/projects/mappings-explorer"],
            )
        )
        session.add(
            app_models.FindingAttackContext(
                id=ids["attack_context"],
                finding_id=ids["finding"],
                analysis_run_id=ids["run"],
                cve_id="CVE-2021-44228",
                mapped=True,
                source="CTID Mappings Explorer",
                review_status="reviewed",
                defensive_note="Finding context is defensive triage evidence only.",
                rationale="Finding has a reviewed CTID mapping.",
                technique_ids_json=["T1190"],
                tactic_ids_json=["TA0001"],
                mappings_json=[
                    {
                        "cve_id": "CVE-2021-44228",
                        "technique_id": "T1190",
                        "source": "CTID Mappings Explorer",
                        "confidence": 0.9,
                        "rationale": "Reviewed mapping.",
                        "review_status": "reviewed",
                        "defensive_note": "Defensive context only.",
                    }
                ],
            )
        )
        session.commit()

    with Session(migrated_engine) as session:
        mapping = session.exec(
            select(app_models.CveAttackMapping).where(
                app_models.CveAttackMapping.cve_id == "CVE-2021-44228"
            )
        ).one()
        context = session.exec(
            select(app_models.FindingAttackContext).where(
                app_models.FindingAttackContext.finding_id == ids["finding"]
            )
        ).one()

        assert mapping.technique_id == "T1190"
        assert mapping.confidence == 0.9
        assert mapping.review_status == "reviewed"
        assert "defensive" in mapping.defensive_note.lower()
        assert context.mapped is True
        assert context.technique_ids_json == ["T1190"]
        assert context.mappings_json[0]["source"] == "CTID Mappings Explorer"


def _ids() -> dict[str, uuid.UUID]:
    return {
        "project": uuid.UUID("00000000-0000-4000-8000-000000000552"),
        "vulnerability": uuid.UUID("00000000-0000-4000-8000-000000000553"),
        "finding": uuid.UUID("00000000-0000-4000-8000-000000000554"),
        "run": uuid.UUID("00000000-0000-4000-8000-000000000555"),
        "tactic": uuid.UUID("00000000-0000-4000-8000-000000000556"),
        "technique": uuid.UUID("00000000-0000-4000-8000-000000000557"),
        "mapping": uuid.UUID("00000000-0000-4000-8000-000000000558"),
        "attack_context": uuid.UUID("00000000-0000-4000-8000-000000000559"),
    }


def _persist_project_run_graph(
    session: Session, app_models: Any, ids: dict[str, uuid.UUID]
) -> None:
    session.add(
        app_models.Project(
            id=ids["project"],
            name="ATT&CK Lite",
            description="Workbench ATT&CK persistence contract.",
        )
    )
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
            status=app_models.FindingStatus.OPEN,
            priority=app_models.FindingPriority.CRITICAL,
            priority_rank=1,
            in_kev=True,
            attack_mapped=True,
        )
    )
    session.add(
        app_models.AnalysisRun(
            id=ids["run"],
            project_id=ids["project"],
            input_type="cve-list",
            filename="known-cves.txt",
            status=app_models.AnalysisRunStatus.COMPLETED,
            summary_json={"finding_count": 1, "attack_mapped_cves": 1},
        )
    )

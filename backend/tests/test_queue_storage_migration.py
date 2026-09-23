"""Rollback must preserve current queue semantics as well as historical evidence."""

from __future__ import annotations

import json
import uuid
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, event, inspect, text
from sqlalchemy.engine import Engine
from sqlmodel import Session, select
from utils.workbench_env import seed_finding_pair

from app import models, repositories
from app.decision_core.ledger import canonical_payload_sha256
from app.repositories.current_projections import FindingCurrentProjectionRepository
from app.repositories.evidence_payloads import EvidencePayloadStore


def test_queue_downgrade_restores_legacy_payloads_without_rewriting_history(tmp_path: Path) -> None:
    config = Config()
    config.set_main_option("script_location", str(Path(__file__).parents[1] / "app/alembic"))
    config.set_main_option("sqlalchemy.url", f"sqlite:///{tmp_path / 'queue.db'}")
    command.upgrade(config, "head")
    engine = create_engine(config.get_main_option("sqlalchemy.url"))
    with Session(engine) as session:
        project = models.Project(name="Queue rollback")
        session.add(project)
        session.commit()
        project_id = project.id
    seeded = seed_finding_pair(
        engine, models, repositories, project_id=project_id, with_decision_evidence=True
    )
    with Session(engine) as session:
        repository = FindingCurrentProjectionRepository(session)
        first, second = seeded["finding_ids"]
        payload = repository.current_payload(first)
        assert payload is not None
        payload["status"] = "in_review"
        payload["remediation"]["decision_statement"] = "Top finding #1: Recorded guidance"
        repository.update_current_payload(first, payload)
        repository.update_queue_ranks({first: 7, second: 1})
        session.commit()
        expected = {str(key): repository.current_payload(key) for key in (first, second)}
        history = EvidencePayloadStore(session.connection()).load_records(
            session.exec(select(models.FindingDecisionEvidence)).all()
        )
        history = {str(key): value for key, value in history.items()}
    engine.dispose()

    command.downgrade(config, "20260923_0011")
    engine = create_engine(config.get_main_option("sqlalchemy.url"))
    with engine.connect() as connection:
        before = connection.execute(text("SELECT * FROM finding_current_projection")).all()
    engine.dispose()

    def fail_after_conversion(_connection, _cursor, statement, _parameters, _context, _executemany):
        if (
            statement.startswith("UPDATE finding_current_projection SET ")
            and "lifecycle_overlay_json=" in statement
        ):
            raise RuntimeError("injected queue rollback failure")

    event.listen(Engine, "after_cursor_execute", fail_after_conversion)
    try:
        with pytest.raises(RuntimeError, match="injected queue rollback failure"):
            command.downgrade(config, "20260906_0010")
    finally:
        event.remove(Engine, "after_cursor_execute", fail_after_conversion)
    engine = create_engine(config.get_main_option("sqlalchemy.url"))
    try:
        with engine.connect() as connection:
            assert (
                connection.execute(text("SELECT * FROM finding_current_projection")).all() == before
            )
            assert (
                connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
                == "20260923_0011"
            )
            assert "operational_sort_key_json" in {
                column["name"]
                for column in inspect(connection).get_columns("finding_current_projection")
            }
    finally:
        engine.dispose()

    command.downgrade(config, "20260906_0010")
    engine = create_engine(config.get_main_option("sqlalchemy.url"))
    try:
        with engine.connect() as connection:
            rows = (
                connection.execute(
                    text(
                        "SELECT p.finding_id, p.operational_rank, p.lifecycle_overlay_json, "
                        "p.projection_payload_sha256, p.lifecycle_revision, e.id, e.payload_json "
                        "FROM finding_current_projection p "
                        "JOIN finding_decision_evidence e ON e.id = p.source_finding_evidence_id"
                    )
                )
                .mappings()
                .all()
            )
            for row in rows:
                source = json.loads(row["payload_json"])
                effective = source | json.loads(row["lifecycle_overlay_json"])
                assert effective == expected[str(uuid.UUID(row["finding_id"]))]
                assert effective["operational_rank"] == row["operational_rank"]
                assert canonical_payload_sha256(effective) == row["projection_payload_sha256"]
                assert row["lifecycle_revision"] > 0
                assert source == history[str(uuid.UUID(row["id"]))]
    finally:
        engine.dispose()

    command.upgrade(config, "head")
    engine = create_engine(config.get_main_option("sqlalchemy.url"))
    try:
        with Session(engine) as session:
            repository = FindingCurrentProjectionRepository(session)
            assert {
                str(key): repository.current_payload(key) for key in (first, second)
            } == expected
            assert repository.verify_all_source_parity().matches
    finally:
        engine.dispose()
